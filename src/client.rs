//! Reference client — what a mint caller does end-to-end
//! (`docs/design-mint.md` § *Reference client & demo*). Lives in `mint/`
//! with no external deps; it is also the conformance surface the
//! integration tests exercise.
//!
//! Identity is a `.key`/`.pub` pair: lowercase hex of the 32-byte
//! Ed25519 material with a trailing newline; the private `client.key`
//! is mode 0600. Both live under a client directory defaulting to
//! `./mint_client` (analogous to the server's `./mint_data`),
//! overridable with `--client-dir`. The credential ticket and
//! credential received from the server are persisted there too (file
//! names are `--out`/`--in` overridable), so the client is
//! self-contained.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};

use crate::caveat::{Caveat, name, op, scope};
use crate::macaroon::Macaroon;
use crate::pop;
use crate::state::fingerprint;

const KEY_FILE: &str = "client.key";
const PUB_FILE: &str = "client.pub";
/// Default `enroll --out` / `exchange --in`: the credential ticket —
/// the short-lived, redeem-once token you trade in at the exchange.
pub const CREDENTIAL_TICKET_FILE: &str = "credential.ticket";
/// Per-role credentials live one file per role under this directory:
/// `credentials/<role>`. Kept distinct from the flat `credential.ticket`
/// so the `credential.` name is never overloaded (`docs/design-mint.md`
/// § *Credential macaroon & lifecycle*).
pub const CREDENTIALS_DIR: &str = "credentials";

/// The default on-disk path (under the client dir) for the credential
/// of `role` — `credentials/<role>`. The `exchange --out` /
/// `assume-role --in` default.
pub fn credential_path(role: &str) -> String {
    format!("{CREDENTIALS_DIR}/{role}")
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("transport: {0}")]
    Transport(String),
    #[error(transparent)]
    Session(#[from] crate::session::SessionError),
    #[error("malformed {0}")]
    BadFile(&'static str),
    #[error("{path} not found — {hint}")]
    Missing { path: String, hint: &'static str },
    #[error("bad request ({0})")]
    BadRequest(&'static str),
    #[error("--caveat must be NAME=VALUE (got {0:?})")]
    BadCaveat(String),
    #[error(
        "exchange refused (401) — the credential ticket most likely expired \
         (it is short-lived). Re-run `mint client enroll …` for a fresh \
         one; your approval persists, so just `mint client exchange` again"
    )]
    TicketRejected,
    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },
    #[error("server response missing the {0} field")]
    MissingField(&'static str),
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], ClientError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(ClientError::BadFile(KEY_FILE));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| ClientError::BadFile(KEY_FILE))?;
    }
    Ok(out)
}

fn write_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Read a client-state file, turning a missing one into an actionable
/// error (which path, and the prerequisite command) rather than an
/// opaque `Io(NotFound)`. Other io errors stay distinct.
fn read_text(path: &Path, hint: &'static str) -> Result<String, ClientError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(ClientError::Missing {
            path: path.display().to_string(),
            hint,
        }),
        Err(e) => Err(ClientError::Io(e)),
    }
}

/// Mint a fresh Ed25519 identity into `dir`, persisting `client.key`
/// (0600) + `client.pub`, and return the key. The caller is the first
/// operation that needs an identity — see [`load_key`].
fn generate_identity(dir: &Path) -> Result<SigningKey, ClientError> {
    fs::create_dir_all(dir)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    write_0600(
        &dir.join(KEY_FILE),
        format!("{}\n", encode_hex(&seed)).as_bytes(),
    )?;
    fs::write(
        dir.join(PUB_FILE),
        format!("{}\n", encode_hex(&sk.verifying_key().to_bytes())),
    )?;
    Ok(sk)
}

/// Load this client's identity key, minting one on first use. A key
/// *is* an identity, so the first operation that needs one generates and
/// persists it; every later call reuses the same `client.key`.
fn load_key(dir: &Path) -> Result<SigningKey, ClientError> {
    match fs::read_to_string(dir.join(KEY_FILE)) {
        Ok(raw) => Ok(SigningKey::from_bytes(&decode_hex_32(&raw)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => generate_identity(dir),
        Err(e) => Err(ClientError::Io(e)),
    }
}

/// `(cnf, fingerprint)` for the identity in `dir` — what the operator
/// compares out of band before `mint enroll approve`.
pub fn identity(dir: &Path) -> Result<(String, String), ClientError> {
    let cnf = pop::cnf_value(&load_key(dir)?);
    let fp = fingerprint(&cnf);
    Ok((cnf, fp))
}

fn now_unix() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// Decode an inline invite macaroon argument. The macaroon is passed
/// verbatim (the operator hands you the encoded string); there is no
/// file or stdin source.
fn parse_invite(src: &str) -> Result<Macaroon, ClientError> {
    Macaroon::decode(src.trim()).map_err(|_| ClientError::BadFile("invite macaroon"))
}

/// POST a `(primary, discharges)` bundle: the `Authorization` header
/// carries the primary followed by each discharge, comma-separated; the
/// PoP signs the body under the **primary's** tail (the principal whose
/// chain is being exercised). This is the wire shape mint's
/// `extract_bundle` + `verify_and_clear` expect.
async fn post_bundle(
    base_url: &str,
    endpoint: &str,
    primary: &Macaroon,
    discharges: &[Macaroon],
    sk: &SigningKey,
    body: String,
) -> Result<(u16, String), ClientError> {
    let sig = pop::client_signature(sk, primary.tail(), body.as_bytes());
    let mut auth = format!("MintV1 {}", primary.encode());
    for d in discharges {
        auth.push(',');
        auth.push_str(&d.encode());
    }
    let headers = [
        ("authorization", auth),
        ("x-mint-pop", sig),
        ("content-type", "application/json".into()),
    ];
    send(base_url, endpoint, &headers, body).await
}

/// Transport leg shared by every POST — a thin wrapper over
/// [`crate::transport::post`], which selects TCP or HTTP-over-UDS by the
/// transport scheme (`unix:` vs `http(s)://`). Transport failures collapse to
/// [`ClientError::Transport`]; there is nothing the caller branches on
/// beyond the HTTP status.
async fn send(
    base_url: &str,
    endpoint: &str,
    headers: &[(&str, String)],
    body: String,
) -> Result<(u16, String), ClientError> {
    crate::transport::post(base_url, endpoint, headers, body)
        .await
        .map_err(ClientError::Transport)
}

fn json_field(body: &str, key: &'static str) -> Result<String, ClientError> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(key).and_then(|s| s.as_str()).map(str::to_string))
        .ok_or(ClientError::MissingField(key))
}

fn save_macaroon(dir: &Path, file: &str, b64: &str) -> Result<(), ClientError> {
    // Parse-don't-validate: only persist something that decodes.
    Macaroon::decode(b64).map_err(|_| ClientError::BadFile("server macaroon"))?;
    let path = dir.join(file);
    // `file` may be nested (e.g. `credentials/<role>`); create the
    // parent so per-role credentials land under their directory.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, b64)?;
    Ok(())
}

/// Shorten a long opaque value for display, keeping both ends so it
/// stays recognisable. Standard caveat values here are ASCII (ULID,
/// `ed25519:<b64>`, unix int), so byte slicing is char-safe.
fn abbrev(s: &str) -> String {
    if s.len() <= 28 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..14], &s[s.len() - 8..])
    }
}

/// One-line plain-English gloss for a standard caveat, so the demo
/// narration explains *why* each line is there. mint is
/// caveat-vocabulary-agnostic; an unrecognised name glosses to nothing
/// and is still shown verbatim.
fn caveat_gloss(cav_name: &str, cav_value: &str) -> &'static str {
    match cav_name {
        name::OP => match cav_value {
            op::ENROLL => "participation gate — enroll only",
            op::ENROLL_EXCHANGE => "redeem-once — may only be exchanged for a credential",
            op::ASSUME_ROLE => "the working credential — mints role keypairs",
            _ => "mint operation this token is partitioned to",
        },
        name::AUD => "the mint instance this token is for",
        name::SUB => "the enrollment identity (operator-approved)",
        name::CNF => "bound to this client's key — proof-of-possession",
        name::EXP => "expiry, unix seconds",
        name::ROLE => "restricts the assumable role",
        name::INVITE => "current invite nonce",
        _ => "",
    }
}

/// Narrate a macaroon's caveat chain to stderr — what this token *is*,
/// in the demo. Renders `exp` as a readable UTC instant alongside the
/// raw seconds.
fn describe(label: &str, m: &Macaroon) {
    eprintln!("  {label} — {} caveat(s):", m.caveats().len());
    for c in m.caveats() {
        match c {
            Caveat::FirstParty { name, value } => {
                let mut shown = abbrev(value);
                let exp_instant = (name == name::EXP)
                    .then(|| value.parse::<i64>().ok())
                    .flatten()
                    .and_then(|s| chrono::DateTime::from_timestamp(s, 0));
                if let Some(dt) = exp_instant {
                    shown = format!("{shown} ({})", dt.format("%Y-%m-%dT%H:%M:%SZ"));
                }
                let gloss = caveat_gloss(name, value);
                if gloss.is_empty() {
                    eprintln!("    {:<10} {shown}", name);
                } else {
                    eprintln!("    {:<10} {shown}  — {gloss}", name);
                }
            }
            Caveat::ThirdParty { location, .. } => {
                eprintln!(
                    "    {:<10} {location}  — discharge required from this authority",
                    "tpc"
                );
            }
        }
    }
}

/// `mint client enroll`: attenuate the invite macaroon with this
/// identity's `sub`/`cnf`, prove possession, receive + persist the
/// credential ticket.
pub async fn enroll(
    dir: &Path,
    base_url: &str,
    invite_src: &str,
    sub: &str,
    out: &str,
) -> Result<(), ClientError> {
    let sk = load_key(dir)?;
    let cnf = pop::cnf_value(&sk);
    let presented = parse_invite(invite_src)?
        .attenuate(Caveat::scalar(name::SUB, sub))
        .attenuate(Caveat::scalar(name::CNF, cnf.clone()));
    eprintln!("enroll: attenuating the operator's invite macaroon with your identity");
    eprintln!("  sub = {sub}  (the principal you are claiming)");
    eprintln!(
        "  cnf = {}  (your client key — binds the token to you)",
        abbrev(&cnf)
    );
    // The invite carries the enroll gate (a third-party caveat): fetch
    // an enrolling-operator discharge at scope `mint:enroll` and present
    // it alongside. Requires a logged-in session (`mint login`).
    let discharges = gate_discharges(&presented, scope::MINT_ENROLL).await?;
    eprintln!("  → POST {base_url}/v1/enroll  (signed with your client key)");
    let body = format!(r#"{{"ts":{}}}"#, now_unix());
    let (status, text) =
        post_bundle(base_url, "/v1/enroll", &presented, &discharges, &sk, body).await?;
    if status != 200 {
        return Err(ClientError::Server { status, body: text });
    }
    let ticket = json_field(&text, "credential.ticket")?;
    if let Ok(m) = Macaroon::decode(&ticket) {
        eprintln!("  ← 200 — mint minted a credential ticket from its root:");
        describe("credential ticket", &m);
    }
    save_macaroon(dir, out, &ticket)?;
    eprintln!(
        "  saved to {}  (now: operator runs `mint enroll approve {sub}`)",
        dir.join(out).display()
    );
    Ok(())
}

/// `mint client exchange`: present the credential ticket. `Ok(true)` =
/// credential written; `Ok(false)` = still awaiting operator approval
/// (HTTP 403, the one non-failure non-200) — the caller decides the
/// exit code / retry.
pub async fn exchange(
    dir: &Path,
    base_url: &str,
    in_file: &str,
    role: &str,
    out: &str,
    values: &[String],
) -> Result<bool, ClientError> {
    let sk = load_key(dir)?;
    let in_path = dir.join(in_file);
    let ticket = Macaroon::decode(read_text(&in_path, "run `mint client enroll …` first")?.trim())
        .map_err(|_| ClientError::BadFile("credential ticket"))?;
    eprintln!(
        "exchange: presenting your credential ticket ({}) for role `{role}`",
        in_path.display()
    );
    describe("credential ticket (what you hold)", &ticket);
    // The ticket carries the exchange gate: fetch an exchanging-operator
    // discharge at scope `mint:exchange` and present it alongside. One
    // discharge covers every role exchanged within its window.
    let discharges = gate_discharges(&ticket, scope::MINT_EXCHANGE).await?;
    eprintln!(
        "  → POST {base_url}/v1/enroll-exchange  role={role}  (signed with your client key — proof-of-possession)"
    );
    let body = serde_json::json!({
        "ts": now_unix(),
        "role": role,
    })
    .to_string();
    let (status, text) = post_bundle(
        base_url,
        "/v1/enroll-exchange",
        &ticket,
        &discharges,
        &sk,
        body,
    )
    .await?;
    match status {
        200 => {
            let received = json_field(&text, "credential")?;
            let m = Macaroon::decode(&received).map_err(|_| ClientError::BadFile("credential"))?;
            // An attested role returns a short-lived `op=exchange-finalize`
            // intermediate, not the credential: propose the role's caveat
            // values to the attestation authority, discharge its TPC, and
            // finalize (step 2) to bake them in. An issuer-only role returns
            // the credential directly and takes no values.
            let credential = if scalar_value(&m, name::OP).as_deref() == Some(op::EXCHANGE_FINALIZE)
            {
                eprintln!(
                    "  ← 200 — mint issued a short-lived intermediate for attested role `{role}`:"
                );
                describe("intermediate (step 1 of 2)", &m);
                let values = parse_caveats(values)?;
                finalize_attested(base_url, &m, &values, &sk).await?
            } else {
                eprintln!(
                    "  ← 200 — mint re-minted a credential from its root (a fresh chain, not an attenuation of the ticket):"
                );
                describe("credential (what you received)", &m);
                received
            };
            save_macaroon(dir, out, &credential)?;
            eprintln!("  saved to {}", dir.join(out).display());
            Ok(true)
        }
        403 => {
            eprintln!("  ← 403 — the operator has not approved this enrollment yet");
            Ok(false)
        }
        // The server's 401 is deliberately opaque, but at exchange the
        // overwhelmingly likely cause is an expired ticket (it is
        // short-lived by design). Point at the idempotent remedy rather
        // than echoing a bare unauthorized.
        401 => Err(ClientError::TicketRejected),
        _ => Err(ClientError::Server { status, body: text }),
    }
}

/// Resolve a scalar caveat's single value off a macaroon, or `None` if
/// absent or contradictory (the same fail-closed resolution mint uses).
fn scalar_value(m: &Macaroon, name: &str) -> Option<String> {
    match crate::caveat::EffectiveCaveats::new(m.caveats()).resolve(name) {
        crate::caveat::Resolved::Value(v) => Some(v),
        _ => None,
    }
}

/// Step 2 of an attested exchange: propose the role's caveat values to the
/// attestation authority, discharge the intermediate's third-party caveat,
/// and present the bundle to `POST /v1/exchange-finalize`, which bakes the
/// vouched values into the final credential. Returns the encoded credential.
async fn finalize_attested(
    base_url: &str,
    intermediate: &Macaroon,
    values: &[CaveatArg],
    sk: &SigningKey,
) -> Result<String, ClientError> {
    let discharges = attest_discharges(intermediate, values).await?;
    eprintln!(
        "  → POST {base_url}/v1/exchange-finalize  (signed with your client key — proof-of-possession)"
    );
    let body = format!(r#"{{"ts":{}}}"#, now_unix());
    let (status, text) = post_bundle(
        base_url,
        "/v1/exchange-finalize",
        intermediate,
        &discharges,
        sk,
        body,
    )
    .await?;
    if status != 200 {
        return Err(ClientError::Server { status, body: text });
    }
    let credential = json_field(&text, "credential")?;
    if let Ok(m) = Macaroon::decode(&credential) {
        eprintln!("  ← 200 — mint baked the attested value(s) into your credential:");
        describe("credential (what you received)", &m);
    }
    Ok(credential)
}

/// A parsed `NAME=VALUE` CLI argument — a caveat value the client proposes
/// at `exchange` (`--caveat`), vouched by the attestation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CaveatArg {
    name: String,
    value: String,
}

impl CaveatArg {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Consume into the `(name, value)` pair the JSON/`BTreeMap` wire
    /// representations want.
    fn into_pair(self) -> (String, String) {
        (self.name, self.value)
    }
}

/// Parse `NAME=VALUE` args, splitting on the first `=`. mint is
/// caveat-vocabulary-agnostic, so the client is too: no name is
/// special-cased.
fn parse_caveats(args: &[String]) -> Result<Vec<CaveatArg>, ClientError> {
    args.iter()
        .map(|a| match a.split_once('=') {
            Some((n, v)) if !n.is_empty() => Ok(CaveatArg::new(n, v)),
            _ => Err(ClientError::BadCaveat(a.clone())),
        })
        .collect()
}

/// The assume-role request body: just the client-owned `ts`/`role`/
/// `ttl_seconds`. These are the only fields mint reads (scoping is
/// attested by a discharge, not the body), so there is nothing else to
/// send. Pure + ts-injected for testability.
fn build_request_body(role: &str, ttl_seconds: u64, ts: u64) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("ts".into(), ts.into());
    obj.insert("role".into(), role.into());
    obj.insert("ttl_seconds".into(), ttl_seconds.into());
    serde_json::Value::Object(obj).to_string()
}

/// `mint client assume-role`: attenuate the held credential with the
/// bounding `exp` from `ttl` and exercise it. The credential is a bare
/// primary — any attestation was discharged and baked in at exchange — so
/// no discharge is fetched here. Returns the raw keypair JSON to print.
pub async fn assume_role(
    dir: &Path,
    base_url: &str,
    role: &str,
    ttl_seconds: u64,
    in_file: &str,
) -> Result<String, ClientError> {
    let sk = load_key(dir)?;
    let in_path = dir.join(in_file);
    let mut mac = Macaroon::decode(
        read_text(
            &in_path,
            "run `mint client exchange` after the operator approves",
        )?
        .trim(),
    )
    .map_err(|_| ClientError::BadFile("credential"))?;
    eprintln!(
        "assume-role: attenuating your credential ({}) for role `{role}`",
        in_path.display()
    );
    describe("credential (what you hold)", &mac);
    // The credential does not expire; the role gate requires `exp`. Bound
    // it to the requested lifetime.
    let exp = now_unix().saturating_add(ttl_seconds);
    mac = mac.attenuate(Caveat::scalar(name::EXP, exp.to_string()));
    eprintln!("  appended exp={exp}");

    // The credential carries no third-party caveat — any attestation was
    // discharged and baked in at exchange — so `assume-role` presents a
    // bare primary with no discharge.
    eprintln!("  → POST {base_url}/v1/assume-role");
    let body = build_request_body(role, ttl_seconds, now_unix());
    let (status, text) = post_bundle(base_url, "/v1/assume-role", &mac, &[], &sk, body).await?;
    if status != 200 {
        return Err(ClientError::Server { status, body: text });
    }
    eprintln!("  ← 200 — mint verified the chain + PoP and minted a scoped Tigris keypair:");
    Ok(text)
}

/// Fetch an attestation discharge for each third-party caveat on the
/// credential, attesting the caller's `--attest` pairs. The session
/// comes from the shared per-user login; the transport is the
/// attestation authority's, saved by `mint login --config` against a
/// config that colocates it. A credential with no TPC yields an empty
/// list without touching either.
async fn attest_discharges(
    credential: &Macaroon,
    values: &[CaveatArg],
) -> Result<Vec<Macaroon>, ClientError> {
    let has_tpc = credential
        .caveats()
        .iter()
        .any(|c| matches!(c, Caveat::ThirdParty { .. }));
    if !has_tpc {
        return Ok(Vec::new());
    }
    // The client proposes the role's caveat values; the authority vouches
    // them into the discharge. The client does not hold the role's contract,
    // so it cannot tell up front which values the role requires — a
    // mismatch surfaces as a clean 400 from `exchange-finalize`.
    let session = crate::session::load_session()?;
    let transport = crate::session::load_attest_transport()?;
    let caveats: std::collections::BTreeMap<String, String> =
        values.iter().cloned().map(CaveatArg::into_pair).collect();
    let mut discharges = Vec::new();
    for c in credential.caveats() {
        let Caveat::ThirdParty { location, cid, .. } = c else {
            continue;
        };
        eprintln!(
            "  credential carries an attested caveat → fetching discharge \
             from {location} (via {transport})"
        );
        let body = serde_json::to_string(&crate::attest::AttestRequest {
            cid: BASE64.encode(cid),
            caveats: caveats.clone(),
        })
        .map_err(|_| ClientError::BadRequest("attest body"))?;
        let headers = [
            ("content-type", "application/json".into()),
            ("authorization", format!("Bearer {session}")),
        ];
        let path = discharge_path(location)?;
        let (status, text) = send(&transport, &path, &headers, body).await?;
        if status != 200 {
            return Err(ClientError::Server { status, body: text });
        }
        let discharge = json_field(&text, "discharge")?;
        discharges
            .push(Macaroon::decode(&discharge).map_err(|_| ClientError::BadFile("discharge"))?);
        eprintln!("    ← discharge received");
    }
    Ok(discharges)
}

/// Fetch an operator discharge for each third-party caveat on `anchor`
/// (the invite at enroll, the ticket at exchange) at the named `scope`,
/// to present alongside the anchor. The session + transport come from the
/// shared per-user login ([`crate::session`], written by `mint login`),
/// so the gates require a logged-in operator. An anchor with no TPC yields
/// an empty list.
async fn gate_discharges(anchor: &Macaroon, scope: &str) -> Result<Vec<Macaroon>, ClientError> {
    let has_tpc = anchor
        .caveats()
        .iter()
        .any(|c| matches!(c, Caveat::ThirdParty { .. }));
    if !has_tpc {
        return Ok(Vec::new());
    }
    let session = crate::session::load_session()?;
    let transport = crate::session::load_transport()?;
    let mut discharges = Vec::new();
    for c in anchor.caveats() {
        let Caveat::ThirdParty { location, cid, .. } = c else {
            continue;
        };
        eprintln!(
            "  anchor carries the {scope} gate → fetching discharge \
             from {location} (via {transport})"
        );
        let discharge = fetch_discharge(&transport, location, cid, &session, scope).await?;
        eprintln!("    ← discharge received");
        discharges.push(discharge);
    }
    Ok(discharges)
}

/// The request path of a TPC `location` (a full URL, e.g.
/// `http://localhost/v1/discharge`). The host is not dialed — the saved
/// transport supplies the connection — so only the path is taken.
fn discharge_path(location: &str) -> Result<String, ClientError> {
    crate::tpc::location_path(location).ok_or(ClientError::BadFile("tpc location"))
}

/// POST the CID + requested `scope` to the authority's `/v1/discharge`
/// under the session bearer and decode the returned discharge macaroon.
/// The session's `Subject` is what the discharge attests; auth issues
/// only if the session grants `scope`, and stamps it as the discharge's
/// `Scope` caveat for the gate to clear.
async fn fetch_discharge(
    transport: &str,
    location: &str,
    cid: &[u8],
    session: &str,
    scope: &str,
) -> Result<Macaroon, ClientError> {
    let cid_b64 = BASE64.encode(cid);
    let body = serde_json::json!({ "cid": cid_b64, "scope": scope }).to_string();
    let headers = [
        ("content-type", "application/json".into()),
        ("authorization", format!("Bearer {session}")),
    ];
    let path = discharge_path(location)?;
    let (status, text) = send(transport, &path, &headers, body).await?;
    if status != 200 {
        return Err(ClientError::Server { status, body: text });
    }
    let discharge = json_field(&text, "discharge")?;
    Macaroon::decode(&discharge).map_err(|_| ClientError::BadFile("discharge"))
}

/// First value of first-party caveat `name` in `m`, if present.
fn caveat_value<'a>(m: &'a Macaroon, target: &str) -> Option<&'a str> {
    m.caveats().iter().find_map(|c| match c {
        Caveat::FirstParty { name, value } if name == target => Some(value.as_str()),
        _ => None,
    })
}

/// Decode the held credential for `role` from `credentials/<role>`.
fn load_credential(dir: &Path, role: &str) -> Result<Macaroon, ClientError> {
    let path = dir.join(credential_path(role));
    let raw = read_text(&path, "run `mint client exchange --role <role>` first")?;
    Macaroon::decode(raw.trim()).map_err(|_| ClientError::BadFile("credential"))
}

/// `mint client credential list`: enumerate the per-role credentials
/// held under `credentials/`. Local-only — no network, no PoP.
pub fn credential_list(dir: &Path) -> Result<(), ClientError> {
    let cdir = dir.join(CREDENTIALS_DIR);
    let mut held: Vec<(String, Macaroon)> = match fs::read_dir(&cdir) {
        Ok(rd) => {
            let mut v = Vec::new();
            for entry in rd {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let role = entry.file_name().to_string_lossy().into_owned();
                let raw = fs::read_to_string(entry.path())?;
                let mac =
                    Macaroon::decode(raw.trim()).map_err(|_| ClientError::BadFile("credential"))?;
                v.push((role, mac));
            }
            v
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(ClientError::Io(e)),
    };
    if held.is_empty() {
        eprintln!(
            "no credentials held in {} — run `mint client exchange --role <role>`",
            cdir.display()
        );
        return Ok(());
    }
    held.sort_by(|a, b| a.0.cmp(&b.0));
    println!("{:<16} {:<28} {:>7}  SUB", "ROLE", "ROLE-CAVEAT", "CAVEATS");
    for (file_role, mac) in &held {
        // The filename is authoritative for *which* credential this is;
        // the `role` caveat is what the credential actually carries. A
        // mismatch is worth seeing, so show both rather than collapsing.
        let role_cav = caveat_value(mac, name::ROLE).unwrap_or("(none)");
        let sub = caveat_value(mac, name::SUB).unwrap_or("(none)");
        println!(
            "{:<16} {:<28} {:>7}  {sub}",
            file_role,
            role_cav,
            mac.caveats().len()
        );
    }
    Ok(())
}

/// `mint client credential inspect <role>`: narrate the held
/// credential's caveat chain (the same rendering `exchange` prints when
/// it receives it). Local-only — no network, no PoP.
pub fn credential_inspect(dir: &Path, role: &str) -> Result<(), ClientError> {
    let mac = load_credential(dir, role)?;
    eprintln!(
        "credential for role `{role}` ({}):",
        dir.join(credential_path(role)).display()
    );
    describe("credential (what you hold)", &mac);
    Ok(())
}

/// Convenience for callers that take a `--client-dir`.
pub fn client_dir(arg: Option<PathBuf>) -> PathBuf {
    arg.unwrap_or_else(|| PathBuf::from("mint_client"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_mints_and_persists_a_stable_identity() {
        let d = tempfile::tempdir().unwrap();
        // No key on disk yet — the first identity read mints the pair.
        assert!(!d.path().join(KEY_FILE).exists());
        let (cnf, fp) = identity(d.path()).unwrap();
        assert!(cnf.starts_with("ed25519:"));
        assert_eq!(fp.len(), 16); // 8 bytes hex
        assert!(d.path().join(KEY_FILE).exists());
        assert!(d.path().join(PUB_FILE).exists());
        // The identity is stable: a later read reuses the same key.
        assert_eq!(identity(d.path()).unwrap().0, cnf);
    }

    #[test]
    fn key_file_is_0600_hex_with_newline() {
        let d = tempfile::tempdir().unwrap();
        generate_identity(d.path()).unwrap();
        let raw = fs::read_to_string(d.path().join(KEY_FILE)).unwrap();
        assert!(raw.ends_with('\n'));
        assert_eq!(raw.trim().len(), 64);
        let mode = fs::metadata(d.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn bad_key_file_is_reported() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path()).unwrap();
        fs::write(d.path().join(KEY_FILE), "not-hex").unwrap();
        assert!(matches!(identity(d.path()), Err(ClientError::BadFile(_))));
    }

    #[test]
    fn invite_arg_accepts_inline_and_rejects_non_macaroon() {
        let wire = crate::issuance::mint_invite(
            &crate::keyring::Keyring::single([1u8; 32]),
            &[9u8; 32],
            "mint",
            "nonce",
            "org_demo",
            "https://auth.example/v1/discharge",
        )
        .encode();
        // inline: the value itself is the macaroon (surrounding whitespace trimmed)
        assert!(parse_invite(&wire).is_ok());
        assert!(parse_invite(&format!("  {wire}\n")).is_ok());
        // anything that does not decode → clear error, no panic
        assert!(matches!(
            parse_invite("not-a-macaroon"),
            Err(ClientError::BadFile(_))
        ));
    }

    #[test]
    fn request_body_carries_only_client_owned_fields() {
        // The body is exactly the client-owned conventional fields — mint
        // reads nothing else, so the client sends nothing else.
        let b = build_request_body("read", 900, 1000);
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["ts"], 1000);
        assert_eq!(v["role"], "read");
        assert_eq!(v["ttl_seconds"], 900);
        assert_eq!(
            v.as_object().unwrap().len(),
            3,
            "only ts/role/ttl_seconds are sent"
        );
    }

    #[test]
    fn caveat_parsing_is_vocabulary_agnostic() {
        let ok = parse_caveats(&[
            "elide:Volume=01VOL".into(),
            "Region=eu=west".into(), // only the first '=' splits
        ])
        .unwrap();
        assert_eq!(ok[0], CaveatArg::new("elide:Volume", "01VOL"));
        assert_eq!(ok[1], CaveatArg::new("Region", "eu=west"));
        for bad in ["novalue", "=novalue"] {
            assert!(matches!(
                parse_caveats(&[bad.to_string()]),
                Err(ClientError::BadCaveat(_))
            ));
        }
    }

    #[tokio::test]
    async fn attest_discharges_skips_when_no_tpc() {
        // A credential with no TPC yields an empty list regardless of
        // `--attest`, touching neither session nor transport. (An empty
        // `--attest` is no longer pre-rejected — a gate-only role
        // discharges its TPC with no values; the authority/finalize enforce
        // the values a values-required role needs.)
        let no_tpc = crate::macaroon::mint(
            &crate::keyring::Keyring::single([7u8; 32]),
            vec![Caveat::scalar(name::OP, "assume-role")],
        );
        assert!(attest_discharges(&no_tpc, &[]).await.unwrap().is_empty());
    }

    #[test]
    fn credential_list_and_inspect_are_local_and_fail_actionably() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();

        // No credentials/ dir yet: list is a clean no-op (not an error),
        // inspect of an absent role points at the prerequisite command.
        assert!(credential_list(dir).is_ok());
        assert!(matches!(
            credential_inspect(dir, "write"),
            Err(ClientError::Missing { .. })
        ));

        // Persist a real minted credential at credentials/write.
        let cred = crate::issuance::mint_credential(
            &crate::keyring::Keyring::single([7u8; 32]),
            "mint",
            "coord-1",
            "ed25519:k",
            "write",
            0,
            &[],
        );
        save_macaroon(dir, &credential_path("write"), &cred.encode()).unwrap();
        assert!(credential_list(dir).is_ok());
        assert!(credential_inspect(dir, "write").is_ok());

        // A corrupt credential file is reported, not panicked on, by both.
        save_macaroon(dir, &credential_path("read"), &cred.encode()).unwrap();
        fs::write(dir.join(credential_path("read")), "not-a-macaroon").unwrap();
        assert!(matches!(
            credential_list(dir),
            Err(ClientError::BadFile("credential"))
        ));
        assert!(matches!(
            credential_inspect(dir, "read"),
            Err(ClientError::BadFile("credential"))
        ));
    }
}
