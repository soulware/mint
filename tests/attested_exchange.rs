//! End-to-end through mint's attested-exchange path against a *simulated*
//! external attestation authority: mint the intermediate carrying the
//! undischarged attested TPC → an authority discharge (recover `r` from the
//! CID under `K_M-B` and mint rooted at it, exactly as elide's coord B does)
//! → `exchange-finalize` bakes the attested value into the credential →
//! assume-role renders a policy substituting every template namespace
//! (`mint`, `caveat` — the attested value now resolves as `{{caveat.X}}`).
//! mint no longer stands up an attestation authority itself; this exercises
//! mint's issuer/verifier half without a live Tigris or a real authority.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use mint::audit::AuditLog;
use mint::caveat::{Caveat, name};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::{AttestedTpc, mint_intermediate};
use mint::keyring::Keyring;
use mint::macaroon::{KeyRef, Macaroon, mint_under_key_with_nonce};
use mint::pop;
use mint::state::{KeyProvisioning, Store};
use mint::tpc;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const CLIENT_SEED: [u8; 32] = [7u8; 32];
const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ATTEST_LOCATION: &str = "https://attest.elide.internal/v1/discharge";
/// The project the authority attests; baked into the credential at finalize
/// and substituted by the policy as `{{caveat.project}}`.
const PROJECT: &str = "apollo";

const TOML_TEMPLATE: &str = r#"
audience = "mint"
[store]
bucket = "mint-demo"
[attestation]
location = "https://attest.elide.internal/v1/discharge"
[[role]]
name = "attested-write"
ttl_seconds = 300
policy_file = "attested-write.json"

[[profile]]
name = "client"
roles = ["attested-write"]
"#;

/// The shipped demo template: a literal bucket/prefix plus the caveat and
/// mint namespaces. The attestation-sourced `project` resolves through
/// `{{caveat.X}}` like the issuer-stamped `sub`.
const POLICY: &str = r#"
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::mint-demo/demo/{{caveat.sub}}/{{caveat.project}}/*"],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}
"#;

fn config() -> Config {
    common::parse_config(TOML_TEMPLATE, &[("attested-write.json", POLICY)])
}

/// AppState with the keys `mint serve` provisions for an attested role:
/// K_M-A (settling org = "demo") and K_M-B (the attestation wrapping key mint
/// stamps CIDs under). Returns the generated K_M-B so the test can stamp the
/// intermediate's attested TPC the way issuance does and recover `r` the way
/// the authority does.
async fn state() -> (AppState, Arc<FakeMinter>, [u8; 32], tempfile::TempDir) {
    let minter = Arc::new(FakeMinter::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config();
    let seal = Arc::new(arc_swap::ArcSwap::from_pointee(
        mint::sealed_cache::serving_from_config(&cfg),
    ));
    let mut store = Store::open_local_with_initial_key(dir.path(), Some(ROOT))
        .await
        .expect("store");
    store
        .init_k_m_a(dir.path(), KeyProvisioning::GenerateIfAbsent)
        .expect("k_m_a");
    store
        .init_k_m_b(dir.path(), KeyProvisioning::GenerateIfAbsent)
        .expect("k_m_b");
    let k_m_b = *store.k_m_b().expect("k_m_b generated");
    store
        .approve(
            SUB,
            &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            "client",
            "usr_test",
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .expect("approve");
    let state = AppState {
        config: Arc::new(cfg),
        minter: minter.clone(),
        audit: Arc::new(AuditLog::new(Box::new(std::io::sink()))),
        store: Arc::new(store),
        seal,
    };
    (state, minter, k_m_b, dir)
}

fn far_future() -> u64 {
    (chrono::Utc::now().timestamp() as u64) + 365 * 24 * 3600
}

/// The `op=exchange-finalize` intermediate the client holds at step 1 for
/// the `attested-write` role, carrying the undischarged attested TPC its
/// role declares.
fn intermediate(k_m_b: &[u8; 32]) -> Macaroon {
    mint_intermediate(
        &Keyring::single(ROOT),
        "mint",
        SUB,
        &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
        "attested-write",
        0,
        AttestedTpc {
            k_m_b,
            org_id: "demo",
            role: "attested-write",
            location: ATTEST_LOCATION,
        },
    )
}

fn tpc_cid(m: &Macaroon) -> Vec<u8> {
    m.caveats()
        .iter()
        .find_map(|c| match c {
            Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
            _ => None,
        })
        .expect("the intermediate carries the attested TPC")
}

/// Mint the attestation discharge the way an external authority does: recover
/// `r` from the intermediate's attested TPC CID under `K_M-B`
/// (`tpc::decrypt_cid_attested` — the authority has no `K_M`, so it must
/// decrypt the CID), then mint a discharge rooted at `r` carrying each
/// requested `(name, value)` plus `exp`. Mirrors `coord_b_discharge` in
/// `discharge_verify.rs` and the elide attestation coordinator.
fn authority_discharge(
    k_m_b: &[u8; 32],
    intermediate: &Macaroon,
    caveats: &[(&str, &str)],
) -> Macaroon {
    let cid = tpc_cid(intermediate);
    let pt = tpc::decrypt_cid_attested(k_m_b, &cid).expect("recover r from attested cid");
    let mut cvs: Vec<Caveat> = caveats.iter().map(|&(n, v)| Caveat::scalar(n, v)).collect();
    cvs.push(Caveat::scalar(name::EXP, far_future().to_string()));
    mint_under_key_with_nonce(&pt.r, KeyRef::Discharge, tpc::ticket_id(&cid), cvs)
}

async fn body_string(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

/// `POST /v1/exchange-finalize` with the intermediate + attestation
/// discharge bundle, PoP-signed under the client key.
async fn finalize(
    state: &AppState,
    intermediate: &Macaroon,
    discharge: &Macaroon,
) -> (StatusCode, String) {
    let ts = chrono::Utc::now().timestamp() as u64;
    let body = format!("{{\"ts\":{ts}}}");
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        intermediate.tail(),
        body.as_bytes(),
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/exchange-finalize")
        .header(
            "authorization",
            format!("MintV1 {},{}", intermediate.encode(), discharge.encode()),
        )
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    body_string(router(state.clone()).oneshot(req).await.unwrap()).await
}

fn json_str(body: &str, key: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(key).and_then(|s| s.as_str()).map(str::to_string))
        .unwrap_or_else(|| panic!("no {key:?} in: {body}"))
}

#[tokio::test]
async fn attested_exchange_bakes_then_renders() {
    let (state, minter, k_m_b, _dir) = state().await;
    let interm = intermediate(&k_m_b);

    // The authority discharges the intermediate's TPC, vouching `project`.
    let discharge = authority_discharge(&k_m_b, &interm, &[("project", PROJECT)]);

    // exchange-finalize bakes `project` into the credential.
    let (status, body) = finalize(&state, &interm, &discharge).await;
    assert_eq!(status, StatusCode::OK, "finalize: {body}");
    let cred = Macaroon::decode(&json_str(&body, "credential"))
        .expect("credential decodes")
        .attenuate(Caveat::scalar(name::EXP, far_future().to_string()));

    // assume-role with the bare credential — no discharge in the bundle.
    let ts = chrono::Utc::now().timestamp() as u64;
    let body = format!("{{\"ts\":{ts},\"role\":\"attested-write\"}}");
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        cred.tail(),
        body.as_bytes(),
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header("authorization", format!("MintV1 {}", cred.encode()))
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, body) = body_string(router(state).oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "assume-role: {body}");

    // One rendered policy, every value in its slot: a literal bucket/prefix,
    // caveat.sub (issuer-stamped), caveat.project (attestation-baked), and
    // mint.expiry (computed).
    let calls = minter.calls();
    assert_eq!(calls.len(), 1);
    let policy = &calls[0].policy_json;
    assert!(
        policy.contains(&format!("arn:aws:s3:::mint-demo/demo/{SUB}/{PROJECT}/*")),
        "policy: {policy}"
    );
    assert!(policy.contains("aws:CurrentTime"), "policy: {policy}");
    // The IAM policy name's scope segment is the attestation-baked value.
    assert!(
        calls[0].policy_name.contains(PROJECT),
        "policy name: {}",
        calls[0].policy_name
    );
}

#[tokio::test]
async fn finalize_missing_attested_value_is_400() {
    // The `attested-write` role requires `project`. A gate-only discharge
    // (empty attested set) verifies and clears the TPC, but carries no
    // `project` — finalize must reject it with a clean 400 before minting,
    // never baking an unscoped credential.
    let (state, _minter, k_m_b, _dir) = state().await;
    let interm = intermediate(&k_m_b);
    let discharge = authority_discharge(&k_m_b, &interm, &[]);
    let (status, _) = finalize(&state, &interm, &discharge).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing attested value must 400"
    );
}

#[tokio::test]
async fn finalize_without_the_discharge_is_refused() {
    // The intermediate carries the attested TPC; presenting it bare to
    // exchange-finalize must fail verification — the discharge is not
    // optional, and no credential is minted.
    let (state, _minter, k_m_b, _dir) = state().await;
    let interm = intermediate(&k_m_b);
    let ts = chrono::Utc::now().timestamp() as u64;
    let body = format!("{{\"ts\":{ts}}}");
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        interm.tail(),
        body.as_bytes(),
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/exchange-finalize")
        .header("authorization", format!("MintV1 {}", interm.encode()))
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, _) = body_string(router(state).oneshot(req).await.unwrap()).await;
    assert_ne!(status, StatusCode::OK);
}
