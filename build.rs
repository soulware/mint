//! Bakes the version `mint --version` reports into the build.
//!
//! The git tag is the single source of truth for a release version: the release
//! workflow passes it as `MINT_RELEASE_VERSION` and it is baked in here. Local
//! and CI builds report a `-dev` version from the manifest placeholder. See
//! `docs/release-artifacts.md`.

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=MINT_RELEASE_VERSION");

    let version = match env::var("MINT_RELEASE_VERSION") {
        // Release build: the tag (e.g. `v0.1.1`), normalised to `0.1.1`.
        Ok(tag) if !tag.trim().is_empty() => tag.trim().trim_start_matches('v').to_string(),
        // Local or CI build: a `-dev` version from the manifest placeholder.
        _ => format!("{}-dev", env::var("CARGO_PKG_VERSION").unwrap_or_default()),
    };
    println!("cargo:rustc-env=MINT_VERSION={version}");
}
