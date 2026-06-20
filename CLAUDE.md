# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mint` is macaroon-authenticated, scoped-credential vending for Tigris (an S3-compatible
object store). The mint verifies a caller-presented macaroon against its root keyring, looks
up a role, renders the role's IAM-policy template from the macaroon's caveats, mints a scoped
short-lived Tigris keypair, and returns it. **The mint is never in the data path** — it hands
out credentials, it does not proxy I/O.

It implements the settled design in `docs/design-mint.md` (in the
[elide repo](https://github.com/soulware/elide), alongside `docs/design-auth-service.md` and
`docs/design-mint-template-seal.md`). It was extracted from elide and is deliberately free of
`elide-*` dependencies — a standalone Cargo workspace destined to become its own OSS project.

## Commands

```sh
cargo build && cargo test          # standard build + full test suite
cargo test --no-fail-fast          # what CI runs
cargo test --test assume_role      # one integration test file (tests/assume_role.rs)
cargo test --test assume_role -- name_substring   # one test within it
cargo fmt --check                  # CI gate
cargo clippy --all-targets --features e2e-harness -- -D warnings   # CI gate; -D warnings is enforced
```

CI (`.github/workflows/ci.yml`) runs exactly these three: `fmt --check`, `clippy` (with
`-D warnings`), and `test --no-fail-fast`. Clippy must be run with `--features e2e-harness` so
the `mint-e2e` harness bin is linted too.

### Conventions

- Land changes via PR — never push directly to `main`.
- Rust edition 2024.

## Running it

clap CLI; `--config` defaults to `mint.toml`, overridden by the `MINT_CONFIG` env var. The
standard setup is to copy the example config into the repo root, edit it (bucket name, etc.), and
export `MINT_CONFIG` so no command needs `--config`:

```sh
cp examples/mint-demo.toml ./mint-demo.toml   # then edit: bucket, audience, roles, …
export MINT_CONFIG=./mint-demo.toml
```

`./mint-demo.toml` is gitignored and is assumed by the examples below. `mint serve` always runs
against real Tigris IAM (or any S3-compatible backend speaking the IAM API) and needs an `AWS_*`
admin credential in the environment — never in the TOML. There is **no in-process dev backend** on
the operator/serve surface.

To supply the `AWS_*` admin credential from 1Password rather than exporting raw secrets, use
`op run` with the example env file (which holds `op://…` *references*, not secrets, so it's
committed). Only `serve` touches IAM, so only it needs the wrapper:

```sh
cp examples/mint-demo.env ./mint-demo.env     # then edit refs for your vault
op run --env-file ./mint-demo.env -- mint serve
```

`./mint-demo.env` is gitignored. `op run` resolves the refs and injects the values into mint's
process env only — nothing secret lands in the shell, history, or on disk.

Operator side (server host):
```sh
mint serve                          # vending HTTP surface; AWS_* in env
mint login                          # operator session, gates the admin/discharge plane
mint seal                           # publish the template seal; serve is DORMANT until sealed
mint invite                         # print the invite macaroon (to stdout; diagnostics to stderr)
mint enroll list / approve <sub> / revoke <sub>
mint role list / inspect <name>
```

Client side (the client's half; identity under `./mint_client`):
```sh
mint client fingerprint                         # mints identity on first use; operator compares this during approve
mint client enroll  --id <sub> <invite>         # attenuates the invite with sub+cnf
mint client exchange [--attest N=V] <role>      # exits 2 until approved; --attest for an attested role (baked in here)
mint client assume-role [--req '{...}'] [--caveat N=V] <role>   # no attestation here — the credential is a bare primary
```

The **hermetic** shape (no cloud) is the `mint-e2e` harness bin: the same `serve::run` loop over
`Store::open_local` + `iam::FakeMinter`. Built with
`cargo build --features e2e-harness --bin mint-e2e` and spawned as a process by cross-workspace
end-to-end tests (the elide workspace cannot link mint as a library).

## Architecture

### Caveat vocabulary (from the RFCs, see README)
`aud`, `exp`, `sub` (opaque principal — a client ULID), `cnf` (RFC 7800 holder-of-key,
`ed25519:<pub>`) are standard. Mint-coined: `op` (endpoint partition — **positively required**
at every endpoint, never absence-tested; values `enroll` / `enroll-exchange` / `exchange-finalize`
/ `assume-role`), `role`, `epoch` (revocation generation), `invite` (rotation nonce). `caveat::name`
/ `caveat::op` hold the canonical constants.

### The three core invariants
- **Fail closed on caveat ambiguity.** `caveat::EffectiveCaveats` resolves a name to a tri-state
  — `Absent` / `Value` / `Unsatisfiable`. ≥2 disagreeing occurrences of a name are
  `Unsatisfiable` (the append-a-contradictory-copy defence). Caveats are **named scalars**, MAC'd
  with chained BLAKE3, base64 on the wire.
- **Holder-of-key PoP on every operation.** `pop` is the `cnf` gate: Ed25519 over
  `tail ‖ BLAKE3(raw-body)`, with a freshness `ts` carried in the body. Required on all three
  mint operations.
- **Dormant until sealed.** A daemon serves nothing from `/v1/assume-role` until an operator
  publishes a template seal. See `seal` / `sealed_cache` below.

### Request surface (`http.rs`)
```
POST /v1/assume-role      op=assume-role       (per request)
POST /v1/enroll           op=enroll            (creates a pending record)
POST /v1/enroll-exchange  op=enroll-exchange   (403 until approved)
POST /v1/exchange-finalize op=exchange-finalize (step 2 for attested roles)
POST /v1/verify           discharge verification
GET  /healthz             liveness (seal-independent)
GET  /readyz              503 while Dormant, 200 once Serving
```
Auth is identical across the mint ops: MAC against the keyring, the endpoint's required
`op`, `aud`, and PoP. **Every auth failure is an opaque `401` with no detail** so causes can't be
distinguished; role/caveat denial is `400`, backend failure `503`. The *only* non-401 authz
outcome is `/v1/enroll-exchange` / `/v1/exchange-finalize` returning `403` for a not-yet-approved
record — an awaited state.

### Two flows
**Enrollment**: `mint invite` → client attenuates `sub`+`cnf` and `POST /v1/enroll` (creates a
pending record + short intermediate) → operator verifies the `cnf` fingerprint out of band and
`enroll approve <sub>` → client `POST /v1/enroll-exchange` (403 until approved, then mint re-mints
the non-expiring primary from root). `mint invite --rotate` draws a new nonce, cancelling in-flight
enrollments; outstanding primaries are unaffected.

**Vending**: client attenuates its held primary (`exp`, `elide:Volume`, …) → `POST /v1/assume-role`
+ PoP → role gate → handlebars policy render → Tigris keypair. **No attestation runs here** — the
credential is a bare primary.

**Attestation is point-in-time, at exchange.** A role declaring `[role.attestation]` exchanges in
two steps: `POST /v1/enroll-exchange` returns an `op=exchange-finalize` *intermediate*
carrying an undischarged attested third-party caveat; the client discharges it at the attestation
authority and `POST /v1/exchange-finalize` **bakes** the attested values into the credential as
ordinary MAC'd caveats. The intermediate's lifetime is the role's required
`[role.attestation].intermediate_ttl_seconds`: `0` ⟹ no `exp`, so the holder keeps it and finalizes
per-use (e.g. a coordinator minting a credential per volume); `n > 0` ⟹ it expires after `n` seconds
(a single back-to-back finalize). Thereafter they are indistinguishable from the issuer-stamped `sub` and
render as `{{caveat.X}}` (there is no `{{attested.X}}` namespace). The attested names are declared
in `[role.attestation].attested` and must be a **subset of** `[role.template].caveat`; an empty
list is a gate-only role (a discharge is still required to finalize, but no value is baked). The
demo attestation authority is **echo-only** — real plumbing (`K_M-B`, an `r`-bound discharge), but
the verdict is stubbed to "approve whatever value is asked"; a production authority derives or
validates the value from `(sub, mode)`.

### Module map
- `caveat` / `macaroon` — the caveat algebra and wire format (above).
- `pop` — the holder-of-key gate.
- `issuance` — `mint_invite` / `mint_credential_ticket` / `mint_intermediate` (attested step 1) /
  `mint_credential` (the primary; bakes the credential's source-stamped caveats — holder-supplied
  values fixed at exchange and, for attested roles, the discharged attested values) — each a
  fresh chain from root — plus `mint_admin_service_token`, `bound_identity`.
- `keyring` — the **root-key keyring**: ordered `(kid, key)` generations + a `current` pointer.
  Verification accepts any kid still in the ring; minting always uses `current`. Stored as a
  directory of numbered files (`<data_dir>/root_keys/0000`, `…/current`) — `ls`-inspectable.
- `state` — persisted invite nonce + transient pending table as a directory of files
  (`invite`, `clients/pending/<sub>.json`, `clients/enrolled/<sub>`) so the lifecycle is
  `ls`-inspectable. `Store::open_remote` (Tigris-backed, the production path), `Store::open_local`
  / `Store::open_in_memory` (tests/harness only). Idempotent same-`(sub,pub)`, conflict on a
  different key, GC of stale pending, consume-on-exchange.
- `seal` / `sealed_cache` — the **template seal**: an operator-signed manifest pinning each role's
  TTL bounds + BLAKE3 of its policy template, MAC'd under the keyring (a bucket-credential holder
  cannot forge one). Authored by `POST /v1/admin/seal`, served from an immutable in-memory
  `TemplateSet` — the request path never re-reads disk. `SealState` is `Serving` or `Dormant`,
  held in an `ArcSwap` so `mint seal` swaps the served surface live, no restart.
- `role` / `template` / `audit` — role gate, handlebars policy render, JSON audit lines. A policy
  template substitutes values from three namespaces: `{{caveat.X}}` (MAC-verified, including the
  attestation-baked values), `{{env.X}}` (config), `{{mint.X}}` (mint-computed).
- `config` — TOML (audience, `data_dir`, `roles_dir`, tenant, per-role metadata). Each role's
  policy template is a separate file under `roles_dir` (`<name>.json`, or `policy_file`). The
  macaroon root key is **not** config. Admin credential from `AWS_*`, never TOML.
- `iam` — `KeypairMinter` trait; `TigrisMinter` (real, in `tigris.rs`) and `FakeMinter` (tests).
- `tigris` / `mint_rw` — the real IAM minter, and the self-vended `mint-rw` keypair that routes
  `_mint/*` store I/O (with a background task re-minting it before its `DateLessThan` expiry).
- `auth` / `session` / `operator` / `admin` — the operator admin plane and the **demo-only**
  discharge issuer. `mint login` mints a session (under `K_session`) that gates `/v1/discharge`;
  the operator's authority is the **admin-service** machine token (written by `serve` at first
  start) + a fresh discharge + per-call PoP. Production runs a standalone auth-service binary
  sharing `K_M-A` with mint; `auth.rs` is its in-tree demo stand-in, mounted on its own UDS only
  when `[auth.demo].enabled`.
- `attest` / `tpc` — third-party-caveat (TPC) primitives and the **demo-only** attestation-discharge
  issuer (mounted only under `[attestation.demo]`). `tpc` builds the AEAD-encrypted `(VID, CID)`
  payload: a fresh ephemeral root `r` is sealed in VID under the chain tag `T_{n-1}` (so the verifier
  recovers `r` from VID alone) and in CID under `K_M-A`. Production runs a real attestation authority
  sharing `K_M-B` with mint.
- `transport` — shared POST transport: `unix:<path>` (UDS, via hyper + hyperlocal) or
  `http(s)://host` (TCP, via reqwest). The reference client is **UDS-only**.

### Secret material
The root keyring lives at `<data_dir>/root_keys/` (generated on first start). `K_M-A` (auth/TPC),
`K_M-B` (attestation), and `K_session` (demo auth) are auto-generated **only in demo mode**
(`[auth.demo]` / `[attestation.demo]`). A production instance must have them provisioned out of
band and **fails closed if absent**. See `open_store` in `main.rs` for the gating.

## Reference material

Fly.io's macaroon work is the closest public reference implementation and writing — useful
background for the caveat algebra, third-party-caveat discharge, and the operational concerns
this project shares.

- [`macaroon-thought.md`](https://github.com/superfly/macaroon/blob/main/macaroon-thought.md) —
  design notes for Fly's `superfly/macaroon` library; the reference implementation to compare
  against.
- ["Macaroons Escalated Quickly"](https://fly.io/blog/macaroons-escalated-quickly/) — the
  conceptual introduction: what macaroons are, caveats, and attenuation.
- ["Operationalizing Macaroons"](https://fly.io/blog/operationalizing-macaroons/) — running
  macaroon auth in production: key management, third-party caveats, and discharge.
