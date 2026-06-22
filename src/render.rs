//! Build-time policy-template rendering — the `mint render` pass.
//!
//! A role policy template carries substitution namespaces split by *when*
//! the value is known:
//!
//! - `{{build.X}}` — a deployment constant fixed at build/deploy time (the
//!   bucket name, a region, …). [`render_dir`] resolves these once, from
//!   explicit `--build key=value` inputs, and writes the result to a new
//!   roles directory consumed by `mint serve` / `mint seal`.
//! - `{{caveat.X}}` / `{{mint.X}}` — request-time values (see
//!   [`crate::template`]). Render copies these through verbatim; they are
//!   resolved per request when `assume-role` renders the sealed template.
//!
//! Render owns the whole `build` namespace and nothing else: every
//! `{{build.X}}` is either substituted or reported unresolved, and every
//! other `{{…}}` token is emitted byte-for-byte. `build` is therefore only
//! ever a build-time namespace — a `{{build.X}}` that survives into a
//! sealed template is an unknown namespace to [`crate::template`], so seal
//! authoring rejects it as a malformed token and the daemon fails closed.
//!
//! Substitution is into the **string leaves** of the parsed JSON, exactly
//! as [`crate::template::render_policy`] does: a build value is escaped into
//! its string slot by serde on the way out, so it lands intact whatever it
//! contains and can never break out of its slot or alter the document's
//! structure. A `{{build.X}}` token outside a string value makes the
//! template invalid JSON and is rejected at parse. The output is the
//! re-serialised document, so whitespace and object-key order are
//! normalised — order-independent for an IAM policy, and the same round-trip
//! the request path performs.
//!
//! Build values are explicit CLI inputs, not a config table: the pass is a
//! visible, auditable step in the build pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The build-time substitution namespace. A token `{{build.X}}` is the
/// only kind this pass resolves; everything else is request-time and copied
/// through.
const BUILD_NS: &str = "build";

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("--build argument {arg:?} is not KEY=VALUE (e.g. --build bucket=my-bucket)")]
    BadBuildArg { arg: String },
    #[error("--build key {key:?} given more than once")]
    DuplicateBuildKey { key: String },
    #[error("read roles dir {dir}: {source}")]
    ReadDir {
        dir: String,
        #[source]
        source: std::io::Error,
    },
    #[error("no *.json templates found in {dir}")]
    NoTemplates { dir: String },
    #[error("read template {file}: {source}")]
    ReadTemplate {
        file: String,
        #[source]
        source: std::io::Error,
    },
    #[error("template {file:?} is not valid JSON: {source}")]
    NotJson {
        file: String,
        source: serde_json::Error,
    },
    #[error("serialise rendered template {file:?}: {source}")]
    Serialize {
        file: String,
        source: serde_json::Error,
    },
    #[error("create output dir {dir}: {source}")]
    CreateOut {
        dir: String,
        #[source]
        source: std::io::Error,
    },
    #[error("write rendered template {file}: {source}")]
    WriteTemplate {
        file: String,
        #[source]
        source: std::io::Error,
    },
    /// One or more `{{build.X}}` tokens were left unresolved — a missing
    /// `--build` value or a malformed `build` token. The payload is a
    /// per-file list of the offending tokens. Render writes nothing in this
    /// case, so a half-substituted roles dir never reaches the seal.
    #[error("unresolved build token(s) — pass the missing --build values:\n{0}")]
    Unresolved(String),
}

/// Parse repeatable `--build key=value` arguments into a lookup. The key is
/// split on the first `=`, so a value may itself contain `=` or be empty
/// (`--build prefix=`). A duplicate key is rejected rather than silently
/// taking the last — build inputs are explicit, so an ambiguous one fails
/// closed.
pub fn parse_build_vars(args: &[String]) -> Result<BTreeMap<String, String>, RenderError> {
    let mut vars = BTreeMap::new();
    for arg in args {
        let (key, value) = arg
            .split_once('=')
            .ok_or_else(|| RenderError::BadBuildArg { arg: arg.clone() })?;
        if key.is_empty() || key.contains(char::is_whitespace) {
            return Err(RenderError::BadBuildArg { arg: arg.clone() });
        }
        if vars.insert(key.to_string(), value.to_string()).is_some() {
            return Err(RenderError::DuplicateBuildKey {
                key: key.to_string(),
            });
        }
    }
    Ok(vars)
}

/// Summary of a [`render_dir`] run, for operator-facing reporting.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RenderReport {
    /// The filenames written to the output directory, sorted.
    pub rendered: Vec<String>,
    /// `--build` keys that no template referenced, sorted. A likely typo
    /// (the value was supplied but its token is spelled differently), so
    /// the caller surfaces these as a warning.
    pub unused_vars: Vec<String>,
}

/// Render every `*.json` template in `src` with the build `vars`, writing
/// the results into `dst` under the same filenames.
///
/// The whole set is rendered in memory and validated before anything is
/// written: if any template carries an unresolved `{{build.X}}` token the
/// run fails with [`RenderError::Unresolved`] and `dst` is left untouched,
/// so a partially-substituted roles dir can never be sealed. `dst` is
/// created if absent; existing files of the same name are overwritten.
pub fn render_dir(
    src: &Path,
    dst: &Path,
    vars: &BTreeMap<String, String>,
) -> Result<RenderReport, RenderError> {
    let mut templates: Vec<(String, PathBuf)> = Vec::new();
    let entries = std::fs::read_dir(src).map_err(|source| RenderError::ReadDir {
        dir: src.display().to_string(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| RenderError::ReadDir {
            dir: src.display().to_string(),
            source,
        })?;
        let path = entry.path();
        let is_json = path.extension().and_then(|e| e.to_str()) == Some("json");
        if is_json && path.is_file() {
            templates.push((entry.file_name().to_string_lossy().into_owned(), path));
        }
    }
    if templates.is_empty() {
        return Err(RenderError::NoTemplates {
            dir: src.display().to_string(),
        });
    }
    // Deterministic order so the report and any diagnostics are stable.
    templates.sort();

    let mut outputs: Vec<(String, String)> = Vec::new();
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    let mut unresolved: Vec<(String, Vec<String>)> = Vec::new();
    for (name, path) in &templates {
        let template =
            std::fs::read_to_string(path).map_err(|source| RenderError::ReadTemplate {
                file: path.display().to_string(),
                source,
            })?;
        let outcome = render_template(name, &template, vars)?;
        referenced.extend(outcome.referenced);
        if outcome.unresolved.is_empty() {
            outputs.push((name.clone(), outcome.json));
        } else {
            unresolved.push((name.clone(), outcome.unresolved));
        }
    }
    if !unresolved.is_empty() {
        let mut msg = String::new();
        for (file, tokens) in &unresolved {
            msg.push_str(&format!("  {file}: {}\n", tokens.join(", ")));
        }
        return Err(RenderError::Unresolved(msg.trim_end().to_string()));
    }

    std::fs::create_dir_all(dst).map_err(|source| RenderError::CreateOut {
        dir: dst.display().to_string(),
        source,
    })?;
    let mut rendered = Vec::new();
    for (name, json) in outputs {
        let path = dst.join(&name);
        std::fs::write(&path, format!("{json}\n")).map_err(|source| {
            RenderError::WriteTemplate {
                file: path.display().to_string(),
                source,
            }
        })?;
        rendered.push(name);
    }

    let unused_vars = vars
        .keys()
        .filter(|k| !referenced.contains(k.as_str()))
        .cloned()
        .collect();
    Ok(RenderReport {
        rendered,
        unused_vars,
    })
}

/// The result of substituting one template's build tokens.
#[derive(Debug)]
struct TemplateOutcome {
    /// The rendered JSON, pretty-printed. Build tokens are substituted;
    /// `{{caveat.X}}` / `{{mint.X}}` tokens are preserved verbatim.
    json: String,
    /// Build keys this template referenced and resolved — feeds the
    /// unused-var report.
    referenced: BTreeSet<String>,
    /// Build tokens that could not be resolved (no `--build` value, or a
    /// malformed `build` token), as their original `{{…}}` text. Empty ⟹
    /// the template rendered cleanly.
    unresolved: Vec<String>,
}

/// Substitute the `{{build.X}}` tokens in one JSON template. The document is
/// parsed, substitution happens only into string leaves, and the result is
/// re-serialised — so the output is valid JSON by construction and a build
/// value is escaped into its string slot, never able to alter structure.
fn render_template(
    file: &str,
    template: &str,
    vars: &BTreeMap<String, String>,
) -> Result<TemplateOutcome, RenderError> {
    let mut doc: Value = serde_json::from_str(template).map_err(|source| RenderError::NotJson {
        file: file.to_string(),
        source,
    })?;
    let mut referenced = BTreeSet::new();
    let mut unresolved = Vec::new();
    substitute_value(&mut doc, vars, &mut referenced, &mut unresolved);
    let json = serde_json::to_string_pretty(&doc).map_err(|source| RenderError::Serialize {
        file: file.to_string(),
        source,
    })?;
    Ok(TemplateOutcome {
        json,
        referenced,
        unresolved,
    })
}

/// Recurse the parsed template, substituting build tokens into every string
/// leaf. Numbers, bools, null, and object keys carry no tokens.
fn substitute_value(
    value: &mut Value,
    vars: &BTreeMap<String, String>,
    referenced: &mut BTreeSet<String>,
    unresolved: &mut Vec<String>,
) {
    match value {
        Value::String(s) => {
            if s.contains("{{") {
                *s = substitute_string(s, vars, referenced, unresolved);
            }
        }
        Value::Array(items) => {
            for item in items {
                substitute_value(item, vars, referenced, unresolved);
            }
        }
        Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                substitute_value(val, vars, referenced, unresolved);
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

/// Replace every `{{build.X}}` token in one string leaf. A request-time
/// token (`{{caveat.X}}`, `{{mint.X}}`, or anything not in the `build`
/// namespace) is emitted verbatim, original spacing and all. A substituted
/// value is emitted once and never re-scanned, so a build value that itself
/// contains `{{…}}` is inert text.
fn substitute_string(
    s: &str,
    vars: &BTreeMap<String, String>,
    referenced: &mut BTreeSet<String>,
    unresolved: &mut Vec<String>,
) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            // Unterminated `{{`: not a complete token. Leave it and the
            // remainder verbatim — the seal-time lint judges what render
            // does not own.
            out.push_str(&rest[open..]);
            return out;
        };
        let token = &rest[open..open + 2 + close + 2];
        match classify_build(after[..close].trim()) {
            Build::Key(key) => match vars.get(key) {
                Some(value) => {
                    out.push_str(value);
                    referenced.insert(key.to_string());
                }
                None => {
                    out.push_str(token);
                    unresolved.push(token.to_string());
                }
            },
            Build::Malformed => {
                out.push_str(token);
                unresolved.push(token.to_string());
            }
            Build::Other => out.push_str(token),
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

/// How one `{{…}}` token's trimmed interior relates to the `build`
/// namespace.
enum Build<'a> {
    /// A well-formed `build.<key>` token; `key` is the lookup into the
    /// build vars.
    Key(&'a str),
    /// A `build`-namespaced token that is not a clean `build.<key>` path
    /// (no key, or embedded whitespace) — render owns it, so it is an error
    /// rather than passed through.
    Malformed,
    /// Not the `build` namespace — a request-time token render leaves alone.
    Other,
}

/// Classify a token's already-trimmed interior. Render owns exactly the
/// `build` namespace: a clean `build.<key>` resolves, a malformed `build.*`
/// token is an error, and every other namespace is left for the
/// request-time pass.
fn classify_build(inner: &str) -> Build<'_> {
    let (ns, key) = match inner.split_once('.') {
        Some((ns, key)) => (ns, key),
        None => (inner, ""),
    };
    if ns.trim() != BUILD_NS {
        return Build::Other;
    }
    if key.is_empty() || inner.contains(char::is_whitespace) {
        return Build::Malformed;
    }
    Build::Key(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn render(template: &str, pairs: &[(&str, &str)]) -> TemplateOutcome {
        render_template("t.json", template, &vars(pairs)).expect("render ok")
    }

    #[test]
    fn substitutes_build_and_leaves_request_tokens() {
        // The build bucket is fixed now; the caveat/mint tokens are copied
        // through for the request-time pass.
        const TPL: &str = r#"{"Resource":["arn:aws:s3:::{{build.bucket}}/{{caveat.project}}/*"],"Exp":"{{mint.expiry}}"}"#;
        let out = render(TPL, &[("bucket", "elide-prod")]);
        let v: Value = serde_json::from_str(&out.json).expect("valid json");
        assert_eq!(
            v["Resource"][0].as_str().unwrap(),
            "arn:aws:s3:::elide-prod/{{caveat.project}}/*"
        );
        assert_eq!(v["Exp"].as_str().unwrap(), "{{mint.expiry}}");
        assert!(out.unresolved.is_empty());
        assert_eq!(out.referenced, ["bucket".to_string()].into_iter().collect());
    }

    #[test]
    fn unknown_namespaces_are_left_untouched() {
        // Only `build` is render's; a misspelled `caveat` or any other
        // namespace passes through for the later seal-time lint to judge.
        const TPL: &str = r#"{"a":"{{caveat.sub}}","b":"{{mint.expiry}}","c":"{{cavaet.typo}}"}"#;
        let out = render(TPL, &[("bucket", "b")]);
        let v: Value = serde_json::from_str(&out.json).expect("valid json");
        assert_eq!(v["a"].as_str().unwrap(), "{{caveat.sub}}");
        assert_eq!(v["b"].as_str().unwrap(), "{{mint.expiry}}");
        assert_eq!(v["c"].as_str().unwrap(), "{{cavaet.typo}}");
        assert!(out.unresolved.is_empty());
    }

    #[test]
    fn missing_build_value_is_unresolved() {
        const TPL: &str = r#"{"r":"{{build.bucket}}/{{build.region}}"}"#;
        let out = render(TPL, &[("bucket", "b")]);
        assert_eq!(out.unresolved, vec!["{{build.region}}".to_string()]);
    }

    #[test]
    fn malformed_build_token_is_unresolved() {
        // A `build`-namespaced token with no key is render's to reject, not
        // pass through — render owns the whole namespace.
        for (tpl, token) in [
            (r#"{"r":"{{build.}}"}"#, "{{build.}}"),
            (r#"{"r":"{{build}}"}"#, "{{build}}"),
            (r#"{"r":"{{ build . x }}"}"#, "{{ build . x }}"),
        ] {
            let out = render(tpl, &[("x", "v")]);
            assert_eq!(out.unresolved, vec![token.to_string()], "{tpl}");
        }
    }

    #[test]
    fn dotted_build_key_resolves() {
        // The key is everything after the first dot, so a dotted key works.
        const TPL: &str = r#"{"r":"{{build.tigris.bucket}}"}"#;
        let out = render(TPL, &[("tigris.bucket", "scoped")]);
        let v: Value = serde_json::from_str(&out.json).expect("valid json");
        assert_eq!(v["r"].as_str().unwrap(), "scoped");
    }

    #[test]
    fn build_value_is_escaped_into_its_slot() {
        // A value full of JSON metacharacters cannot break out of its
        // string slot or inject structure — serde escapes it on the way out.
        const TPL: &str =
            r#"{"Statement":[{"Effect":"Allow","Resource":["arn:{{build.bucket}}"]}]}"#;
        let evil = r#"x","Effect":"Deny"},{"Resource":"*"#;
        let out = render(TPL, &[("bucket", evil)]);
        let v: Value = serde_json::from_str(&out.json).expect("valid json");
        let stmts = v["Statement"].as_array().expect("statement array");
        assert_eq!(stmts.len(), 1, "value injected a statement: {}", out.json);
        assert_eq!(stmts[0]["Effect"], "Allow");
        assert_eq!(
            stmts[0]["Resource"][0].as_str().unwrap(),
            format!("arn:{evil}")
        );
    }

    #[test]
    fn substituted_value_is_not_rescanned() {
        // A build value that itself looks like a token stays literal text;
        // the (differently-valued) real key never bleeds in.
        const TPL: &str = r#"{"r":"{{build.a}}"}"#;
        let out = render(TPL, &[("a", "{{build.b}}"), ("b", "SHOULD_NOT_APPEAR")]);
        let v: Value = serde_json::from_str(&out.json).expect("valid json");
        assert_eq!(v["r"].as_str().unwrap(), "{{build.b}}");
        assert!(!out.json.contains("SHOULD_NOT_APPEAR"));
    }

    #[test]
    fn token_outside_a_string_is_invalid_json() {
        // A build token in array position is not valid JSON — there is no
        // unsafe non-string substitution slot to reach.
        let err = render_template(
            "t.json",
            r#"{"r":[{{build.bucket}}]}"#,
            &vars(&[("bucket", "b")]),
        );
        assert!(matches!(err, Err(RenderError::NotJson { .. })), "{err:?}");
    }

    #[test]
    fn unterminated_token_passes_through() {
        // An unterminated `{{` is not a complete token; render leaves it for
        // the seal-time lint rather than guessing.
        const TPL: &str = r#"{"r":"arn:{{build.bucket"}"#;
        let out = render(TPL, &[("bucket", "b")]);
        let v: Value = serde_json::from_str(&out.json).expect("valid json");
        assert_eq!(v["r"].as_str().unwrap(), "arn:{{build.bucket");
        assert!(out.unresolved.is_empty());
    }

    #[test]
    fn parse_build_vars_splits_on_first_equals() {
        let v = parse_build_vars(&["url=https://x?a=b".to_string(), "empty=".to_string()]).unwrap();
        assert_eq!(v["url"], "https://x?a=b");
        assert_eq!(v["empty"], "");
    }

    #[test]
    fn parse_build_vars_rejects_bad_and_duplicate() {
        assert!(matches!(
            parse_build_vars(&["noequals".to_string()]),
            Err(RenderError::BadBuildArg { .. })
        ));
        assert!(matches!(
            parse_build_vars(&["=value".to_string()]),
            Err(RenderError::BadBuildArg { .. })
        ));
        assert!(matches!(
            parse_build_vars(&["bucket=a".to_string(), "bucket=b".to_string()]),
            Err(RenderError::DuplicateBuildKey { key }) if key == "bucket"
        ));
    }
}
