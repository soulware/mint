//! Configuration (`docs/design-mint.md` § *Mint configuration*). v1 is
//! single-tenant, single-root-key.
//!
//! Audience, store, and role metadata are file-backed (TOML); the
//! macaroon keyring is not config (loaded by [`crate::state::Store`]
//! from `<data_dir>/root_keys/`). Each role's IAM-policy template lives in
//! its own file under
//! `roles_dir`, named by the role's `policy_file` (a single normal path
//! component — see [`read_policy`]). The Tigris admin credential is the
//! one input that comes from the environment — `AWS_*`, resolved by
//! [`AdminCredential::from_env`] at load — never the TOML, so secrets
//! and role definitions stay on separate management planes.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("duplicate role name: {0}")]
    DuplicateRole(String),
    #[error("role {role}: ttl_seconds must be > 0")]
    ZeroTtl { role: String },
    #[error("ticket_ttl_seconds must be > 0")]
    BadTicketTtl,
    #[error(
        "role {role}: policy_file {value:?} must be a single filename \
         (no path separators, no '.' or '..', not absolute)"
    )]
    BadPolicyFileName { role: String, value: String },
    #[error(
        "role {role}: derived policy filename {value:?} is not a single \
         filename — set an explicit policy_file or rename the role"
    )]
    BadDerivedPolicyName { role: String, value: String },
    #[error("role {role}: read policy_file {path}: {source}")]
    ReadPolicyFile {
        role: String,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "bind and socket are mutually exclusive — set one (TCP) or the \
         other (UDS), not both"
    )]
    ConflictingListener,
    #[error("bind {value:?} is not a valid host:port: {source}")]
    BadBindAddr {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error(
        "[attestation.demo] enabled = true requires [auth.demo] enabled = true \
         (the issuer is gated on the demo login session)"
    )]
    DemoAttestationWithoutDemoAuth,
    #[error(
        "role {role}: binds a non-reserved caveat (so it is attested) but no \
         [attestation].location is configured to discharge it"
    )]
    AttestationWithoutLocation { role: String },
    #[error("role {role}: policy template is not valid JSON: {source}")]
    PolicyNotJson {
        role: String,
        source: serde_json::Error,
    },
    #[error("role {role}: policy template has a malformed substitution {token}")]
    MalformedPolicyToken { role: String, token: String },
    #[error(
        "role {role}: template references mint.{key}, which is not a \
         mint-computed value"
    )]
    UnknownMintKey { role: String, key: String },
}

/// Normalise a declared field set (`attested`/`caveat`) to a canonical sorted,
/// de-duplicated form so the sealed contract is independent of authoring
/// order and the seal-time exact-match is a plain `Vec` equality against
/// the equally-canonical [`crate::template::template_surface`] output.
fn canonical_field_set(mut fields: Vec<String>) -> Vec<String> {
    fields.sort();
    fields.dedup();
    fields
}

/// Strip a namespace prefix (`attested.`/`caveat.`) off each
/// [`crate::template::template_surface`] entry, yielding the bare keys to
/// compare against a role's declared contract. The surface is already
/// sorted+deduped, so the result is too.
fn strip_ns(paths: &[String], prefix: &str) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.strip_prefix(prefix).unwrap_or(p).to_string())
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    /// The audience name this mint answers to. A macaroon whose
    /// `Audience` caveat differs is rejected (cross-service replay
    /// defence).
    pub audience: String,
    /// Directory for mint's persisted state — the macaroon keyring
    /// (`root_keys/`), the current invite nonce, and the transient
    /// pending-enrollment table, all under one custody
    /// (`docs/design-mint.md` § *Enrollment*, § *Mint configuration*). A
    /// relative value (including the default
    /// `mint_data`) resolves against the current working directory,
    /// not the config file's parent; an absolute path is used verbatim.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// Directory holding role policy-template files, one per role
    /// (referenced by each role's `policy_file`). Same resolution rule
    /// as `data_dir`; defaults to `mint_roles`.
    #[serde(default)]
    pub roles_dir: Option<String>,
    /// TCP listener address (`host:port`). The network deployment
    /// shapes — self-hosted on a separate trusted machine, central
    /// custodial/proxy — all use this; TLS is terminated ahead of or by
    /// mint. Mutually exclusive with `socket`. When neither is set the
    /// listener defaults to TCP `127.0.0.1:8085`.
    #[serde(default)]
    pub bind: Option<String>,
    /// Unix-domain-socket listener path — the bundled single-host dev
    /// shape (client + mint co-resident). Selecting it is what makes a
    /// mint instance local-only: no port, no accidental network
    /// exposure, no same-host TLS, filesystem-permission scoped.
    /// Mutually exclusive with `bind`. Same resolution rule as
    /// `data_dir` (relative against cwd, absolute verbatim); an empty
    /// value selects UDS at the default `<data_dir>/mint.sock`.
    #[serde(default)]
    pub socket: Option<String>,
    /// Lifetime in seconds of the credential ticket minted at
    /// `/v1/enroll` — the multi-use `op=enroll-exchange` token a client
    /// presents at `/v1/enroll-exchange`. Defaults to
    /// [`DEFAULT_TICKET_TTL_SECONDS`] when omitted; must be
    /// `> 0`.
    #[serde(default)]
    pub ticket_ttl_seconds: Option<u64>,
    pub store: Store,
    /// The `[auth]` plane: the discharge `location` for the enroll /
    /// exchange / admin gates, plus the optional `[auth.demo]` colocation
    /// of the auth role. Absent ⟹ no auth plane.
    #[serde(default)]
    pub auth: Option<RawAuth>,
    /// The `[attestation]` plane: the discharge `location` for attested
    /// third-party caveats, plus the optional `[attestation.demo]`
    /// colocation of the attestation authority. Absent ⟹ no attestation.
    #[serde(default)]
    pub attestation: Option<RawAttestation>,
    #[serde(rename = "role", default)]
    pub roles: Vec<RawRole>,
}

/// `[auth]` table: the auth plane. `location` is the discharge URL
/// stamped into the enroll-gate (invite), exchange-gate (ticket), and
/// admin-gate (admin-service) third-party caveats — where a
/// client/operator fetches the discharge. A mint without it (and without
/// `[auth.demo].enabled`) cannot stamp those caveats, so it has no
/// enrollment plane — `/v1/enroll` fails closed. The path is the
/// discharge route; the transport it is dialed over is resolved
/// separately (`[auth.demo]` socket in the colocated demo, the remembered
/// `auth-transport` otherwise).
#[derive(Debug, Clone, Deserialize)]
pub struct RawAuth {
    #[serde(default)]
    pub location: Option<String>,
    /// Colocated demo auth role (`docs/design-auth-service.md`). Demo /
    /// single-host only; absent in production.
    #[serde(default)]
    pub demo: Option<RawDemoAuth>,
}

/// `[attestation]` table: the attestation plane. `location` is the
/// discharge URL stamped into the attested third-party caveat of every
/// role that declares `[role.attestation]` — where the holder fetches the
/// attestation discharge. A single fixed attestation authority for the
/// deployment; absent means no role may declare
/// attestation. The transport is resolved separately, like the auth
/// location.
#[derive(Debug, Clone, Deserialize)]
pub struct RawAttestation {
    #[serde(default)]
    pub location: Option<String>,
    /// Colocated demo attestation authority. Demo / single-host only;
    /// absent in production.
    #[serde(default)]
    pub demo: Option<RawDemoAttestation>,
}

/// `[auth.demo]` block: whether mint colocates the auth-service role and
/// the UDS it binds. Demo / single-host only; production runs a separate
/// auth-service binary.
#[derive(Debug, Clone, Deserialize)]
pub struct RawDemoAuth {
    /// When `true`, mint colocates the auth-service role and binds its
    /// own UDS for `/v1/login` + `/v1/discharge`. Generates `K_M-A` and
    /// `K_session` on first start. Mint refuses to start with
    /// `enabled = true` unless mint itself is bound to loopback or UDS —
    /// see `docs/design-auth-service.md` § *Mint as auth (demo only)*.
    #[serde(default)]
    pub enabled: bool,
    /// UDS path the colocated auth role binds, and the transport the
    /// operator/client dial to reach it. Path-only (UDS-only). Defaults
    /// to `<data_dir>/auth.sock` when omitted; ignored when
    /// `enabled = false`.
    #[serde(default)]
    pub socket: Option<String>,
}

/// `[attestation.demo]` block: whether mint colocates the attestation
/// authority and the UDS it binds. Demo / single-host only; production
/// runs a real attestation authority (for Elide, the attestation
/// coordinator) that shares `K_M-B` with mint.
#[derive(Debug, Clone, Deserialize)]
pub struct RawDemoAttestation {
    /// When `true`, mint colocates the attestation authority and binds
    /// its own UDS for `/v1/discharge`. Generates `K_M-B` on first
    /// start. Requires `[auth.demo].enabled = true`: the issuer is gated
    /// on the same login session the demo auth role mints.
    #[serde(default)]
    pub enabled: bool,
    /// UDS path the colocated attestation authority binds, and the
    /// transport the client dials to reach it. Path-only (UDS-only).
    /// Defaults to `<data_dir>/attest.sock` when omitted; ignored when
    /// `enabled = false`.
    #[serde(default)]
    pub socket: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Store {
    /// Bucket holding mint's own `_mint/*` state (the store bucket).
    /// Operational only — **not** a template surface; roles name the
    /// bucket(s) they grant on as `{{caveat.X}}` (holder-supplied) or as
    /// inlined literals in the policy template.
    pub bucket: String,
    /// S3 endpoint URL. Used by `serve --tigris` to build the
    /// data-plane client that reads and writes `_mint/*` under
    /// [self-vended `mint-rw` credentials][mint-rw], distinct from
    /// the IAM endpoint that `tigris.rs` calls. Omit to use Tigris's
    /// default S3 endpoint
    /// ([`crate::mint_rw::DEFAULT_TIGRIS_S3_ENDPOINT`]); set
    /// explicitly only for a non-Tigris S3-compatible target
    /// (custom AWS region, MinIO, etc.).
    ///
    /// [mint-rw]: crate::state::Store
    #[serde(default)]
    pub endpoint: Option<String>,
    /// S3 region; defaults to `us-east-1` (which Tigris accepts as a
    /// no-op). Override only for non-Tigris S3-compatible backends that
    /// reject the default.
    #[serde(default)]
    pub region: Option<String>,
}

/// Tigris admin credential, read from the standard AWS environment
/// variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
/// optional `AWS_SESSION_TOKEN`). Deliberately **not** in the TOML
/// config: the credential is a secret delivered by the environment
/// (systemd `LoadCredential=`, a secrets manager, …), never committed
/// alongside role definitions.
#[derive(Clone)]
pub struct AdminCredential {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `AWS_SESSION_TOKEN` if present (STS-style temporary creds).
    pub session_token: Option<String>,
}

impl std::fmt::Debug for AdminCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret — only that a credential is present.
        f.debug_struct("AdminCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl AdminCredential {
    /// Resolve from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
    /// (+ optional `AWS_SESSION_TOKEN`). `None` if either required var
    /// is unset or empty — the prototype's faked minter does not need
    /// it, so absence is a warning at startup, not a hard error.
    pub fn from_env() -> Option<Self> {
        let access_key_id = non_empty_env("AWS_ACCESS_KEY_ID")?;
        let secret_access_key = non_empty_env("AWS_SECRET_ACCESS_KEY")?;
        Some(Self {
            access_key_id,
            secret_access_key,
            session_token: non_empty_env("AWS_SESSION_TOKEN"),
        })
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

#[derive(Debug, Deserialize)]
pub struct RawRole {
    pub name: String,
    pub ttl_seconds: u64,
    /// Filename of the IAM-policy JSON template (see
    /// [`crate::template`]), resolved against `roles_dir`. Optional;
    /// defaults to `<name>.json`. Whether explicit or derived it must
    /// be a single normal path component — validated by [`read_policy`]
    /// (so a role `name` with a path separator is rejected too).
    #[serde(default)]
    pub policy_file: Option<String>,
}

/// Resolved listener transport — a per-deployment-shape choice, not a
/// global default (`docs/design-mint.md` § *Transport*). The macaroon +
/// Ed25519 PoP auth is identical over either; the socket neither
/// weakens nor substitutes for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listener {
    /// The network shapes. TLS terminated ahead of or by mint.
    Tcp(SocketAddr),
    /// The single-host dev shape. Recreated on bind (stale dentry
    /// removed first), chmod `0o666` so a non-root client can
    /// connect.
    Uds(PathBuf),
}

impl Listener {
    /// The transport string a same-host client dials this listener at:
    /// `unix:<path>` for UDS, `http://<host>:<port>` for TCP. A wildcard
    /// bind (`0.0.0.0`/`::`) is rewritten to loopback — it is a bind
    /// address, not a dialable one.
    pub fn dial_url(&self) -> String {
        match self {
            Listener::Uds(path) => format!("unix:{}", path.display()),
            Listener::Tcp(addr) if addr.ip().is_unspecified() => {
                let loopback = if addr.is_ipv4() {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                };
                format!("http://{}", SocketAddr::new(loopback, addr.port()))
            }
            Listener::Tcp(addr) => format!("http://{addr}"),
        }
    }
}

/// Default TCP listener when neither `bind` nor `socket` is configured.
pub const DEFAULT_BIND: &str = "127.0.0.1:8085";
/// Socket filename under `data_dir` when `socket` is selected without
/// an explicit path.
pub const DEFAULT_SOCKET_NAME: &str = "mint.sock";
/// Persisted-state directory when the config omits `data_dir`.
pub const DEFAULT_DATA_DIR: &str = "mint_data";

/// Credential-ticket lifetime when the config omits
/// `ticket_ttl_seconds`. The ticket is multi-use within this
/// window: one operator approval, then the client exchanges it once per
/// role it needs (`docs/design-mint.md` § *Enrollment*). 24 h gives a
/// client comfortable room to enrol, wait for an out-of-band approval,
/// and mint its per-role credentials across a working day. If it lapses
/// the client just re-enrols (idempotent for the same `(sub, pub)` →
/// fresh ticket); a *new* role after expiry needs a fresh approval, by
/// design.
pub const DEFAULT_TICKET_TTL_SECONDS: u64 = 24 * 60 * 60;

/// The default UDS path `mint serve` binds and `mint client` dials when
/// no config selects another: `<DEFAULT_DATA_DIR>/<DEFAULT_SOCKET_NAME>`.
pub fn default_mint_socket() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR).join(DEFAULT_SOCKET_NAME)
}

/// Colocated demo auth role, post-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoAuth {
    pub enabled: bool,
    /// UDS the demo auth role binds, and the transport the
    /// operator/client dial to reach it. Resolved from
    /// `[auth.demo].socket` (explicit) or `<data_dir>/auth.sock`
    /// (default). `None` when `enabled = false`.
    pub socket: Option<PathBuf>,
}

/// Colocated demo attestation authority, post-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoAttestation {
    pub enabled: bool,
    /// UDS the demo attestation authority binds, and the transport the
    /// client dials to reach it. Resolved from
    /// `[attestation.demo].socket` (explicit) or `<data_dir>/attest.sock`
    /// (default). `None` when `enabled = false`.
    pub socket: Option<PathBuf>,
}

/// Validated configuration, ready to serve.
#[derive(Debug)]
pub struct Config {
    pub audience: String,
    /// Persisted-state directory: the root key (generated on first
    /// start), invite nonce, and pending table all share this
    /// custody. Defaults to `mint_data` when the config omits
    /// `data_dir`. The root key itself is owned by
    /// [`crate::state::Store`], not parsed from config.
    pub data_dir: PathBuf,
    /// Directory the role `policy_file`s were read from. Defaults to
    /// `mint_roles`. Retained for diagnostics; policies are already
    /// resolved into [`Role::policy`].
    pub roles_dir: PathBuf,
    /// Lifetime in seconds of the credential ticket minted at
    /// `/v1/enroll`. Resolved from `ticket_ttl_seconds`,
    /// defaulting to [`DEFAULT_TICKET_TTL_SECONDS`]; validated
    /// `> 0` at load.
    pub ticket_ttl_seconds: u64,
    /// The resolved listener transport. The CLI may still override this
    /// with an explicit `--bind` (the TCP single-host override).
    pub listener: Listener,
    pub store: Store,
    /// Resolved from the AWS environment at load time. `None` when the
    /// env is unset. `mint serve` requires `Some`; tests that
    /// construct `Config` directly (and use `Store::open_local` /
    /// `Store::open_in_memory` instead of the Tigris backend) can
    /// leave it `None`.
    pub admin: Option<AdminCredential>,
    /// Colocated demo auth role — `None` if the config omits
    /// `[auth.demo]`.
    pub demo_auth: Option<DemoAuth>,
    /// Colocated demo attestation authority — `None` if the config omits
    /// `[attestation.demo]`.
    pub demo_attestation: Option<DemoAttestation>,
    /// The discharge URL stamped into the enroll/exchange/admin gates —
    /// `None` if the config omits `auth_location`. A mint without it (and
    /// without a demo auth role) cannot stamp those gates, so enrollment
    /// and the admin plane fail closed.
    pub auth_location: Option<String>,
    /// The discharge URL for the attested third-party caveat — `None`
    /// if the config omits `attestation_location`. An attested role (one
    /// binding a non-reserved caveat) without it is rejected at load.
    pub attestation_location: Option<String>,
    pub roles: BTreeMap<String, Role>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    pub ttl_seconds: u64,
    /// The resolved source of [`policy`](Role::policy):
    /// `<roles_dir>/<policy_file>`, or `<roles_dir>/<name>.json` when no
    /// explicit `policy_file` was set. Retained for diagnostics
    /// (`mint role inspect`); the template itself is already resolved.
    pub policy_path: PathBuf,
    /// The role's IAM-policy JSON template, read from
    /// [`policy_path`](Role::policy_path) at load.
    pub policy: String,
    /// The **attested** caveat names — the non-reserved `{{caveat.X}}` the
    /// template binds, vouched by the attestation authority and baked at
    /// `exchange-finalize`. Derived from the template (every non-reserved
    /// token), sorted and de-duplicated. Empty ⟹ an issuer-only role.
    pub attested: Vec<String>,
    /// The full manifest of `{{caveat.X}}` names the template substitutes,
    /// whatever their provenance — the attested names above plus the
    /// issuer-stamped reserved names (e.g. `sub`). Derived from the
    /// template, sorted and de-duplicated, sealed into
    /// [`crate::seal::SealedRole`], and enforced at request time before
    /// render (every name must resolve to a MAC'd value).
    pub caveat: Vec<String>,
}

impl Role {
    /// `true` when the role binds a non-reserved `{{caveat.X}}`: its
    /// credential carries an attested third-party caveat, so exchange is
    /// two-step (intermediate → discharge → finalize). Equivalently, the
    /// attested set — every non-reserved template token — is non-empty.
    pub fn is_attested(&self) -> bool {
        !self.attested.is_empty()
    }
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Config, ConfigError> {
        Self::from_raw(toml::from_str(s)?)
    }

    /// Resolve only the listener from a config file, skipping role and
    /// policy loading. `mint client` uses this to locate the local
    /// daemon socket without needing the server's `roles_dir` present.
    pub fn load_listener(path: &Path) -> Result<Listener, ConfigError> {
        let raw: RawConfig = toml::from_str(&std::fs::read_to_string(path)?)?;
        let data_dir = raw
            .data_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
        resolve_listener(raw.bind.as_deref(), raw.socket.as_deref(), &data_dir)
    }

    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        Self::from_toml_str(&std::fs::read_to_string(path)?)
    }

    fn from_raw(raw: RawConfig) -> Result<Config, ConfigError> {
        let roles_dir = raw
            .roles_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("mint_roles"));
        let ticket_ttl_seconds = match raw.ticket_ttl_seconds {
            Some(0) => return Err(ConfigError::BadTicketTtl),
            Some(ttl) => ttl,
            None => DEFAULT_TICKET_TTL_SECONDS,
        };
        // Flatten the two planes into their resolved scalar location +
        // demo-colocation parts; everything downstream consumes those.
        let (auth_location, demo_auth_raw) = match raw.auth {
            Some(a) => (a.location, a.demo),
            None => (None, None),
        };
        let (attestation_location, demo_attestation_raw) = match raw.attestation {
            Some(a) => (a.location, a.demo),
            None => (None, None),
        };
        let mut roles = BTreeMap::new();
        for r in raw.roles {
            if r.ttl_seconds == 0 {
                return Err(ConfigError::ZeroTtl {
                    role: r.name.clone(),
                });
            }
            let (policy_path, policy) = match r.policy_file {
                Some(ref f) => read_policy(&roles_dir, &r.name, f, true)?,
                None => read_policy(&roles_dir, &r.name, &format!("{}.json", r.name), false)?,
            };
            // Provenance is derived from the template, never declared. The
            // caveat manifest is exactly the `{{caveat.X}}` tokens the policy
            // binds; a reserved name (`sub`, …) is issuer-stamped, every
            // other name is attested (the authority vouches it at finalize).
            let caveat = canonical_field_set(strip_ns(
                &crate::template::template_surface(&policy).caveat,
                "caveat.",
            ));
            let attested: Vec<String> = caveat
                .iter()
                .filter(|n| !crate::caveat::name::RESERVED.contains(&n.as_str()))
                .cloned()
                .collect();
            // An attested role (one binding a non-reserved caveat) needs an
            // authority to discharge its TPC; an issuer-only role does not. A
            // missing authority is a silent dead-credential trap, so fail
            // closed at load.
            if !attested.is_empty() && attestation_location.is_none() {
                return Err(ConfigError::AttestationWithoutLocation {
                    role: r.name.clone(),
                });
            }
            let role = Role {
                name: r.name.clone(),
                ttl_seconds: r.ttl_seconds,
                policy_path,
                policy,
                attested,
                caveat,
            };
            if roles.insert(r.name.clone(), role).is_some() {
                return Err(ConfigError::DuplicateRole(r.name));
            }
        }
        let data_dir = raw
            .data_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
        let listener = resolve_listener(raw.bind.as_deref(), raw.socket.as_deref(), &data_dir)?;
        let demo_auth = demo_auth_raw.map(|d| {
            let socket = d.enabled.then(|| {
                d.socket
                    .map(PathBuf::from)
                    .unwrap_or_else(|| data_dir.join("auth.sock"))
            });
            DemoAuth {
                enabled: d.enabled,
                socket,
            }
        });
        let demo_attestation = demo_attestation_raw.map(|d| {
            let socket = d.enabled.then(|| {
                d.socket
                    .map(PathBuf::from)
                    .unwrap_or_else(|| data_dir.join("attest.sock"))
            });
            DemoAttestation {
                enabled: d.enabled,
                socket,
            }
        });
        // The demo attestation authority gates issuance on the login
        // session the demo auth role mints (verified under K_session),
        // so it cannot exist without the colocated auth role.
        if demo_attestation.as_ref().is_some_and(|d| d.enabled)
            && !demo_auth.as_ref().is_some_and(|d| d.enabled)
        {
            return Err(ConfigError::DemoAttestationWithoutDemoAuth);
        }
        Ok(Config {
            audience: raw.audience,
            data_dir,
            roles_dir,
            ticket_ttl_seconds,
            listener,
            store: raw.store,
            admin: AdminCredential::from_env(),
            demo_auth,
            demo_attestation,
            auth_location,
            attestation_location,
            roles,
        })
    }

    /// Gate **seal authoring** (`POST /v1/admin/seal`) by validating every
    /// template's substitution surface against an authoritative set per
    /// namespace, so a sealed template is one the renderer can render and
    /// the request path can enforce:
    ///
    /// 1. The template parses as JSON. A `{{…}}` token may sit only inside
    ///    a JSON string value; one that escaped (array, key, bare position)
    ///    makes the template invalid JSON and is caught here, not at first
    ///    render. The renderer relies on this — it substitutes into the
    ///    parsed string leaves and re-serialises, so a valid-JSON template
    ///    is the precondition for injection-proof rendering
    ///    (`crate::template`).
    /// 2. Every `{{…}}` token is a well-formed `namespace.key` scalar path.
    ///    An engine-ism (`{{#each}}`), a namespace-less or empty token, or
    ///    an unterminated `{{` would fail the render closed; the lint
    ///    surfaces it at publish instead.
    /// 3. Every `{{mint.X}}` names a [`crate::template::MINT_KEYS`] value.
    ///    (The attested/holder↔caveat fencing — each a subset of `caveat`,
    ///    disjoint from each other and from the reserved control names — is
    ///    enforced at config load, since neither is a template namespace.)
    /// 4. The template's `{{caveat.X}}` tokens match the role's declared
    ///    `caveat` contract exactly (the full manifest, including the
    ///    attestation-baked and holder-supplied subsets). A typo
    ///    (`{{caveat.sb}}` vs declared `sub`) or a dropped binding (a
    ///    template forgetting `{{caveat.sub}}`) fails at publish instead of
    ///    silently mis-scoping a live credential. The declared set is what
    ///    gets sealed and enforced at request time.
    ///
    /// None is run at config load: the request path renders the sealed
    /// surface, decoupled from the live config, so a drifted local
    /// template must never block a host from serving its already-sealed
    /// roles. Render-time strict mode is the final backstop.
    pub fn validate_policy_surface(&self) -> Result<(), ConfigError> {
        for role in self.roles.values() {
            let doc =
                serde_json::from_str::<serde_json::Value>(&role.policy).map_err(|source| {
                    ConfigError::PolicyNotJson {
                        role: role.name.clone(),
                        source,
                    }
                })?;
            if let Some(token) = crate::template::malformed_tokens(&doc).into_iter().next() {
                return Err(ConfigError::MalformedPolicyToken {
                    role: role.name.clone(),
                    token,
                });
            }
            let surface = crate::template::template_surface(&role.policy);
            for path in &surface.mint {
                let key = path.strip_prefix("mint.").unwrap_or(path);
                if !crate::template::MINT_KEYS.contains(&key) {
                    return Err(ConfigError::UnknownMintKey {
                        role: role.name.clone(),
                        key: key.to_string(),
                    });
                }
            }
            // The caveat manifest is derived from this same template at load
            // (`from_raw`), so there is no declared set to cross-check — the
            // policy's `{{caveat.X}}` tokens are the manifest by construction.
            // `{{attested.X}}` is no longer a namespace — a stray one is caught
            // above as a malformed token.
        }
        Ok(())
    }
}

/// Resolve the listener transport from the mutually-exclusive `bind` /
/// `socket` keys (`docs/design-mint.md` § *Transport*):
///
/// - both set → [`ConfigError::ConflictingListener`];
/// - `socket` non-empty → UDS at that path (relative against cwd,
///   absolute verbatim — the `data_dir` rule);
/// - `socket` present but empty → UDS at `<data_dir>/mint.sock`;
/// - `bind` set → TCP at that parsed address;
/// - neither → TCP at [`DEFAULT_BIND`] (the production default;
///   selecting the socket is the deliberate act that makes an instance
///   local-only).
fn resolve_listener(
    bind: Option<&str>,
    socket: Option<&str>,
    data_dir: &Path,
) -> Result<Listener, ConfigError> {
    match (bind, socket) {
        (Some(_), Some(_)) => Err(ConfigError::ConflictingListener),
        (None, Some(s)) => Ok(Listener::Uds(if s.is_empty() {
            data_dir.join(DEFAULT_SOCKET_NAME)
        } else {
            PathBuf::from(s)
        })),
        (Some(b), None) => parse_bind(b).map(Listener::Tcp),
        (None, None) => parse_bind(DEFAULT_BIND).map(Listener::Tcp),
    }
}

fn parse_bind(value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|source| ConfigError::BadBindAddr {
        value: value.to_owned(),
        source,
    })
}

/// Read a role's policy template from `<roles_dir>/<policy_file>`.
///
/// `policy_file` is parsed, not substring-checked: `Path::new` of it
/// must yield exactly one [`Component::Normal`]. That rejects path
/// separators, absolute paths, `.`, `..`, parent traversal, and the
/// empty string in one predicate, so a role name cannot reach outside
/// `roles_dir`. The guarantee is name-level — a symlink *inside*
/// `roles_dir` is still followed, but `roles_dir` shares the config's
/// custody, so its contents are the operator's own.
///
/// `explicit` selects the diagnostic: a bad *explicit* `policy_file` is
/// [`ConfigError::BadPolicyFileName`]; a bad *derived* `<name>.json`
/// (i.e. an unsafe role name) is [`ConfigError::BadDerivedPolicyName`].
fn read_policy(
    roles_dir: &Path,
    role: &str,
    policy_file: &str,
    explicit: bool,
) -> Result<(PathBuf, String), ConfigError> {
    let mut comps = Path::new(policy_file).components();
    let only = comps.next();
    if comps.next().is_some() || !matches!(only, Some(Component::Normal(_))) {
        let (role, value) = (role.to_owned(), policy_file.to_owned());
        return Err(if explicit {
            ConfigError::BadPolicyFileName { role, value }
        } else {
            ConfigError::BadDerivedPolicyName { role, value }
        });
    }
    let path = roles_dir.join(policy_file);
    let contents =
        std::fs::read_to_string(&path).map_err(|source| ConfigError::ReadPolicyFile {
            role: role.to_owned(),
            path: path.display().to_string(),
            source,
        })?;
    Ok((path, contents))
}

/// Path-A test harness (shared with `role.rs`'s unit tests): write each
/// role policy into a tempdir, splice an absolute `roles_dir` into the
/// TOML, then exercise the real [`Config::from_toml_str`] file-read
/// path. The tempdir only needs to outlive the parse — `policy` is read
/// eagerly — so it is dropped on return.
#[cfg(test)]
pub(crate) fn parse_for_test(toml: &str, roles: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, body) in roles {
        std::fs::write(dir.path().join(name), body).expect("write role file");
    }
    let injected = toml.replacen(
        "[store]",
        &format!(
            "roles_dir = {:?}\n[store]",
            dir.path().display().to_string()
        ),
        1,
    );
    Config::from_toml_str(&injected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
audience = "mint"

[store]
bucket = "demo-bucket"

[[role]]
name = "volume-ro"
ttl_seconds = 2592000
policy_file = "volume-ro.json"
"#;

    #[test]
    fn parses_sample() {
        let c = parse_for_test(SAMPLE, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.audience, "mint");
        assert_eq!(c.store.bucket, "demo-bucket");
        assert_eq!(c.roles["volume-ro"].policy, "{}");
    }

    const ATTESTATION_SAMPLE: &str = r#"
audience = "mint"
[store]
bucket = "demo-bucket"
[attestation]
location = "https://coord-b.example/v1/discharge"
[[role]]
name = "volume-rw"
ttl_seconds = 100
policy_file = "volume-rw.json"
[[role]]
name = "volume-ro"
ttl_seconds = 100
policy_file = "volume-ro.json"
[[role]]
name = "coord-base"
ttl_seconds = 100
policy_file = "coord-base.json"
"#;

    /// Policies for `ATTESTATION_SAMPLE`: the `volume-*` roles bind a
    /// non-reserved `{{caveat.volume}}` (so they are attested); `coord-base`
    /// binds only `sub` (so it is issuer-only).
    fn attestation_sample_policies() -> [(&'static str, &'static str); 3] {
        [
            ("volume-rw.json", r#"{"r":"{{caveat.volume}}"}"#),
            ("volume-ro.json", r#"{"r":"{{caveat.volume}}"}"#),
            ("coord-base.json", r#"{"r":"{{caveat.sub}}"}"#),
        ]
    }

    #[test]
    fn attestation_marker_and_location_resolve_per_role() {
        let c = parse_for_test(ATTESTATION_SAMPLE, &attestation_sample_policies()).expect("parse");
        assert_eq!(
            c.attestation_location.as_deref(),
            Some("https://coord-b.example/v1/discharge")
        );
        // A role binding a non-reserved caveat is attested; one binding only
        // reserved names (`sub`) is issuer-only.
        assert!(c.roles["volume-rw"].is_attested());
        assert_eq!(c.roles["volume-rw"].attested, vec!["volume".to_string()]);
        assert!(c.roles["volume-ro"].is_attested());
        assert!(!c.roles["coord-base"].is_attested());
        assert!(c.roles["coord-base"].attested.is_empty());
    }

    #[test]
    fn attested_role_without_location_is_rejected_at_load() {
        // A role binding a non-reserved caveat needs an authority to discharge
        // its TPC; without one it would mint a dead credential. Fail closed.
        let toml = ATTESTATION_SAMPLE.replace(
            "[attestation]\nlocation = \"https://coord-b.example/v1/discharge\"\n",
            "",
        );
        assert!(matches!(
            parse_for_test(&toml, &attestation_sample_policies()),
            Err(ConfigError::AttestationWithoutLocation { role }) if role == "volume-rw"
        ));
    }

    /// A minimal single-role config with no [attestation] location, for the
    /// issuer-only and seal-authoring surface checks (the policy body is
    /// supplied per-test).
    const SINGLE_ROLE_SAMPLE: &str = r#"
audience = "mint"
[store]
bucket = "state-bucket"
[[role]]
name = "r"
ttl_seconds = 100
policy_file = "r.json"
"#;

    /// A single-role config that supplies an [attestation] location, so a
    /// policy binding a non-reserved (attested) caveat loads cleanly. The
    /// policy body is supplied per-test.
    const ATTESTED_ROLE_SAMPLE: &str = r#"
audience = "mint"
[store]
bucket = "state-bucket"
[attestation]
location = "https://a.example/v1/discharge"
[[role]]
name = "r"
ttl_seconds = 100
policy_file = "r.json"
"#;

    #[test]
    fn malformed_token_passes_load_but_fails_seal_validation() {
        // An engine-ism the renderer would fail closed on is caught at
        // seal authoring, not deferred to first render. Config load
        // tolerates it (serving is decoupled from the live config).
        let cfg = parse_for_test(
            SINGLE_ROLE_SAMPLE,
            &[("r.json", r#"{"r":"{{#each items}}"}"#)],
        )
        .expect("load tolerates a malformed token");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::MalformedPolicyToken { token, .. }) if token == "{{#each items}}"
        ));
    }

    #[test]
    fn non_json_template_passes_load_but_fails_seal_validation() {
        // A token that escaped its string slot makes the template invalid
        // JSON; the seal gate rejects it before it can ever be rendered.
        let cfg = parse_for_test(
            SINGLE_ROLE_SAMPLE,
            &[("r.json", r#"{"r":[{{attested.volume}}]}"#)],
        )
        .expect("load tolerates a non-JSON template");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::PolicyNotJson { role, .. }) if role == "r"
        ));
    }

    #[test]
    fn provenance_is_derived_from_the_template() {
        // `project` is non-reserved (attested); `sub` is reserved (issuer).
        // The caveat manifest is the template's tokens; the attested set is
        // the non-reserved ones. Nothing is declared.
        let cfg = parse_for_test(
            ATTESTED_ROLE_SAMPLE,
            &[("r.json", r#"{"r":"{{caveat.project}}/{{caveat.sub}}"}"#)],
        )
        .expect("parse");
        cfg.validate_policy_surface().expect("seals");
        assert_eq!(cfg.roles["r"].attested, vec!["project".to_string()]);
        assert_eq!(
            cfg.roles["r"].caveat,
            vec!["project".to_string(), "sub".to_string()]
        );
    }

    #[test]
    fn issuer_only_template_needs_no_attestation() {
        // A template binding only reserved names is issuer-only: no attested
        // caveat, and it loads with no authority configured.
        let cfg = parse_for_test(
            SINGLE_ROLE_SAMPLE,
            &[("r.json", r#"{"r":"literal-bucket/{{caveat.sub}}/*"}"#)],
        )
        .expect("parse");
        cfg.validate_policy_surface().expect("seals");
        assert!(!cfg.roles["r"].is_attested());
        assert!(cfg.roles["r"].attested.is_empty());
        assert_eq!(cfg.roles["r"].caveat, vec!["sub".to_string()]);
    }

    #[test]
    fn non_reserved_caveat_without_location_is_rejected_at_load() {
        // SINGLE_ROLE_SAMPLE configures no [attestation] location, so a
        // template binding a non-reserved caveat is attested-but-
        // undischargeable — rejected at load.
        assert!(matches!(
            parse_for_test(
                SINGLE_ROLE_SAMPLE,
                &[("r.json", r#"{"r":"{{caveat.project}}"}"#)],
            ),
            Err(ConfigError::AttestationWithoutLocation { role }) if role == "r"
        ));
    }

    #[test]
    fn stale_attested_token_fails_seal_as_malformed() {
        // `{{attested.X}}` is no longer a namespace; a leftover one is a
        // malformed (unknown-namespace) token, rejected at publish. It is not
        // a caveat token, so the role stays issuer-only and loads.
        let cfg = parse_for_test(
            SINGLE_ROLE_SAMPLE,
            &[("r.json", r#"{"r":"{{attested.volume}}"}"#)],
        )
        .expect("load tolerates a malformed template");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::MalformedPolicyToken { token, .. }) if token == "{{attested.volume}}"
        ));
    }

    #[test]
    fn unknown_mint_key_fails_seal() {
        // `mint.*` is closed to the server-computed set; an unknown key
        // fails at publish rather than at render.
        let cfg = parse_for_test(
            SINGLE_ROLE_SAMPLE,
            &[("r.json", r#"{"r":"{{mint.bogus}}"}"#)],
        )
        .expect("load tolerates an unknown mint key");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::UnknownMintKey { key, .. }) if key == "bogus"
        ));
    }

    #[test]
    fn ticket_ttl_defaults_when_omitted() {
        let c = parse_for_test(SAMPLE, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.ticket_ttl_seconds, DEFAULT_TICKET_TTL_SECONDS);
    }

    #[test]
    fn ticket_ttl_is_overridable() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nticket_ttl_seconds = 1800",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.ticket_ttl_seconds, 1800);
    }

    #[test]
    fn rejects_zero_ticket_ttl() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nticket_ttl_seconds = 0",
        );
        assert!(matches!(
            parse_for_test(&toml, &[("volume-ro.json", "{}")]),
            Err(ConfigError::BadTicketTtl)
        ));
    }

    #[test]
    fn rejects_zero_role_ttl() {
        let bad = SAMPLE.replace("ttl_seconds = 2592000", "ttl_seconds = 0");
        assert!(matches!(
            parse_for_test(&bad, &[("volume-ro.json", "{}")]),
            Err(ConfigError::ZeroTtl { role }) if role == "volume-ro"
        ));
    }

    #[test]
    fn rejects_policy_file_traversal() {
        // Name validation fires before any read, so roles_dir is never
        // touched — no file is written.
        for evil in ["../escape.json", "/etc/passwd", "a/b.json", "..", "."] {
            let toml = SAMPLE
                .replace("[store]", "roles_dir = \"mint_roles\"\n[store]")
                .replace("volume-ro.json", evil);
            assert!(
                matches!(
                    Config::from_toml_str(&toml),
                    Err(ConfigError::BadPolicyFileName { .. })
                ),
                "expected BadPolicyFileName for {evil:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_policy_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let toml = SAMPLE.replace(
            "[store]",
            &format!(
                "roles_dir = {:?}\n[store]",
                dir.path().display().to_string()
            ),
        );
        assert!(matches!(
            Config::from_toml_str(&toml),
            Err(ConfigError::ReadPolicyFile { .. })
        ));
    }

    /// Inject a config block (e.g. `[auth.demo]`) before the first
    /// `[[role]]` in SAMPLE. Injecting at `[store]` would land
    /// `parse_for_test`'s `roles_dir = ...` line inside the injected
    /// table; injecting at `[[role]]` keeps every key in the right table.
    fn with_block(s: &str, block: &str) -> String {
        s.replacen("[[role]]", &format!("{block}\n\n[[role]]"), 1)
    }

    #[test]
    fn auth_block_with_location_and_demo_is_parsed() {
        // The whole `[auth]` plane is one table tree: `location` plus the
        // `[auth.demo]` colocation subtable, injected before `[[role]]`.
        let toml = with_block(
            SAMPLE,
            "[auth]\nlocation = \"https://auth.example/v1/discharge\"\n\n[auth.demo]\nenabled = true",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        let demo = c.demo_auth.expect("demo_auth present");
        assert!(demo.enabled);
        assert!(demo.socket.is_some(), "socket resolves when enabled");
        assert_eq!(
            c.auth_location.expect("auth_location present"),
            "https://auth.example/v1/discharge"
        );
    }

    #[test]
    fn demo_auth_enabled_defaults_to_false() {
        // `[auth.demo]` alone implicitly creates the `[auth]` table with
        // no location — demo colocation present, enabled defaulting false.
        let toml = with_block(SAMPLE, "[auth.demo]\nsocket = \"x.sock\"");
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        let demo = c.demo_auth.expect("demo_auth present");
        assert!(!demo.enabled);
        assert!(demo.socket.is_none(), "socket ignored when disabled");
    }

    #[test]
    fn policy_file_defaults_to_name_json() {
        // Drop the explicit policy_file: it must derive `<name>.json`.
        let toml = SAMPLE.replace("policy_file = \"volume-ro.json\"\n", "");
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.roles["volume-ro"].policy, "{}");
    }

    #[test]
    fn listener_defaults_to_tcp_8085() {
        let c = parse_for_test(SAMPLE, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.listener, Listener::Tcp("127.0.0.1:8085".parse().unwrap()));
    }

    #[test]
    fn explicit_bind_is_parsed() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nbind = \"0.0.0.0:9000\"",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.listener, Listener::Tcp("0.0.0.0:9000".parse().unwrap()));
    }

    #[test]
    fn bad_bind_is_rejected() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nbind = \"not-an-addr\"",
        );
        assert!(matches!(
            parse_for_test(&toml, &[("volume-ro.json", "{}")]),
            Err(ConfigError::BadBindAddr { .. })
        ));
    }

    #[test]
    fn socket_path_selects_uds_verbatim() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nsocket = \"/run/mint.sock\"",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.listener, Listener::Uds(PathBuf::from("/run/mint.sock")));
    }

    #[test]
    fn dial_url_maps_each_listener_shape() {
        assert_eq!(
            Listener::Uds(PathBuf::from("/run/mint.sock")).dial_url(),
            "unix:/run/mint.sock"
        );
        // An explicit address dials verbatim.
        assert_eq!(
            Listener::Tcp("10.0.0.5:9000".parse().unwrap()).dial_url(),
            "http://10.0.0.5:9000"
        );
        // A wildcard bind is rewritten to loopback — it is not dialable.
        assert_eq!(
            Listener::Tcp("0.0.0.0:9000".parse().unwrap()).dial_url(),
            "http://127.0.0.1:9000"
        );
        assert_eq!(
            Listener::Tcp("[::]:9000".parse().unwrap()).dial_url(),
            "http://[::1]:9000"
        );
    }

    #[test]
    fn default_mint_socket_is_under_default_data_dir() {
        assert_eq!(default_mint_socket(), PathBuf::from("mint_data/mint.sock"));
    }

    #[test]
    fn empty_socket_selects_uds_at_default_under_data_dir() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\ndata_dir = \"/var/lib/mint\"\nsocket = \"\"",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(
            c.listener,
            Listener::Uds(PathBuf::from("/var/lib/mint/mint.sock"))
        );
    }

    #[test]
    fn bind_and_socket_together_are_rejected() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nbind = \"127.0.0.1:8085\"\nsocket = \"/run/mint.sock\"",
        );
        assert!(matches!(
            parse_for_test(&toml, &[("volume-ro.json", "{}")]),
            Err(ConfigError::ConflictingListener)
        ));
    }

    #[test]
    fn unsafe_role_name_rejected_when_derived() {
        // No explicit policy_file, so the unsafe name flows into the
        // derived filename and must be caught — distinctly from an
        // explicit bad policy_file.
        let toml = SAMPLE
            .replace("policy_file = \"volume-ro.json\"\n", "")
            .replace("[store]", "roles_dir = \"mint_roles\"\n[store]")
            .replace("name = \"volume-ro\"", "name = \"../escape\"");
        assert!(matches!(
            Config::from_toml_str(&toml),
            Err(ConfigError::BadDerivedPolicyName { .. })
        ));
    }
}
