//! `mint render` — the build-time pass that bakes `{{build.X}}` deployment
//! constants into role templates (`src/render.rs`). The command reads no
//! config and no keyring: a pure transform from a source roles dir to an
//! output one. These tests drive the compiled binary end to end, asserting
//! the rendered output, the unresolved-token failure, and the unused-var
//! warning.

use std::path::Path;
use std::process::{Command, Output};

/// A template binding a build-time bucket and request-time caveat/mint
/// tokens — the shape elide ships: the bucket is fixed at build, the rest
/// stays for the request-time pass.
const ATTESTED: &str = r#"{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Resource": ["arn:aws:s3:::{{build.bucket}}/{{caveat.project}}/*"],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}"#;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mint"))
        .args(args)
        .output()
        .expect("run mint")
}

/// Write `templates` (name, body) into a fresh `src` subdir of `d`.
fn write_src(d: &Path, templates: &[(&str, &str)]) {
    let src = d.join("src");
    std::fs::create_dir_all(&src).unwrap();
    for (name, body) in templates {
        std::fs::write(src.join(name), body).unwrap();
    }
}

#[test]
fn bakes_build_constant_and_keeps_request_tokens() {
    let d = tempfile::tempdir().unwrap();
    write_src(d.path(), &[("demo-attested.json", ATTESTED)]);
    let src = d.path().join("src");
    let out = d.path().join("out");

    let res = run(&[
        "render",
        "--in-dir",
        src.to_str().unwrap(),
        "--build",
        "bucket=elide-prod",
        "--out-dir",
        out.to_str().unwrap(),
    ]);
    assert!(res.status.success(), "render failed: {res:?}");

    let rendered = std::fs::read_to_string(out.join("demo-attested.json")).unwrap();
    // The build constant is baked; the request-time tokens survive verbatim.
    assert!(
        rendered.contains("arn:aws:s3:::elide-prod/{{caveat.project}}/*"),
        "{rendered}"
    );
    assert!(rendered.contains("{{mint.expiry}}"), "{rendered}");
    assert!(
        !rendered.contains("{{build."),
        "no build token survives: {rendered}"
    );
    // Output is valid JSON.
    serde_json::from_str::<serde_json::Value>(&rendered).expect("valid json");
}

#[test]
fn missing_build_value_fails_and_writes_nothing() {
    let d = tempfile::tempdir().unwrap();
    // References two build constants; only one is supplied.
    let tpl = r#"{"r":["arn:aws:s3:::{{build.bucket}}/{{build.prefix}}/*"]}"#;
    write_src(d.path(), &[("r.json", tpl)]);
    let src = d.path().join("src");
    let out = d.path().join("out");

    let res = run(&[
        "render",
        "--in-dir",
        src.to_str().unwrap(),
        "--build",
        "bucket=elide-prod",
        "--out-dir",
        out.to_str().unwrap(),
    ]);
    assert!(!res.status.success(), "must fail on an unresolved token");
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("unresolved"), "{stderr}");
    assert!(stderr.contains("{{build.prefix}}"), "{stderr}");
    // Atomic: nothing is written when a template is unresolved.
    assert!(
        !out.join("r.json").exists(),
        "output written despite failure"
    );
}

#[test]
fn unused_build_var_warns_but_succeeds() {
    let d = tempfile::tempdir().unwrap();
    write_src(d.path(), &[("demo-attested.json", ATTESTED)]);
    let src = d.path().join("src");
    let out = d.path().join("out");

    let res = run(&[
        "render",
        "--in-dir",
        src.to_str().unwrap(),
        "--build",
        "bucket=elide-prod",
        "--build",
        "bukcet=typo", // not referenced by any template
        "--out-dir",
        out.to_str().unwrap(),
    ]);
    assert!(res.status.success(), "render failed: {res:?}");
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("warning"), "{stderr}");
    assert!(stderr.contains("bukcet"), "names the unused key: {stderr}");
}
