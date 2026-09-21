//! Boot-time registry lint.
//!
//! Runs in `main()` BEFORE `TcpListener::bind`. A violation exits non-zero
//! naming the offending capability and rule, and the port never opens — a
//! malformed policy file fails loudly at startup rather than at the first
//! click.
//!
//! Rule 5 is the load-bearing one: only `enum` and `server` kinds may appear
//! in an argv template. `multi-enum`, `int` and `bool` are argv-forbidden, so
//! the only caller-influenced argv elements are members of a server-enumerated
//! option set. Together with `Token`'s deserialize rule (a brace must wrap a
//! whole token) this makes "every argv element is a literal, the server's
//! interpreter, a server-generated token, or a set member" structural rather
//! than aspirational.
use std::collections::HashSet;
use std::path::Path;

use crate::registry::{ArgSpec, Authz, Entry, Kind, Registry, Runner, Source, Token};

#[derive(Debug)]
pub struct LintError {
    pub capability: String,
    pub rule: &'static str,
    pub detail: String,
}

impl std::fmt::Display for LintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.capability, self.rule, self.detail)
    }
}

const EFFECT_VOCAB: &[&str] = &[
    "appends_telemetry",
    "binds_port",
    "contacts_host",
    "spawns_long_lived",
    "writes_repo_file",
    "writes_state_dir",
];

const GENERATOR_VOCAB: &[&str] = &["timestamp_path"];

const ID_OK: fn(&str) -> bool = |id| {
    !id.is_empty()
        && id.contains('.')
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-')
        && !id.starts_with('.')
        && !id.ends_with('.')
};

pub fn lint(reg: &Registry, repo_dir: &Path) -> Result<(), Vec<LintError>> {
    let mut errs = Vec::new();
    let mut seen_ids: HashSet<&str> = HashSet::new();

    for entry in &reg.capabilities {
        let id = entry.id.as_str();
        let mut err = |rule: &'static str, detail: String| {
            errs.push(LintError { capability: id.to_string(), rule, detail })
        };

        // 1. ids unique and well-formed
        if !seen_ids.insert(id) {
            err("R1/unique-id", format!("duplicate capability id {id:?}"));
        }
        if !ID_OK(id) {
            err("R1/id-shape", format!("id {id:?} must be dotted lowercase [a-z0-9._-]"));
        }

        let args = reg.args_of(entry);
        let arg_names: HashSet<&str> = args.iter().map(|a| a.name.as_str()).collect();
        let kind_of = |n: &str| args.iter().find(|a| a.name == n).map(|a| a.kind);

        // 13. an args-link must point at an entry that declares args inline
        if let ArgSpec::From { from } = &entry.args {
            match reg.get(from) {
                None => err("R13/args-link", format!("args.from {from:?} is not a capability")),
                Some(t) => {
                    if matches!(t.args, ArgSpec::From { .. }) {
                        err("R13/args-link", format!("args.from {from:?} itself links; nesting is not allowed"));
                    }
                }
            }
        }

        // --- argv rules -------------------------------------------------
        if let Some(argv) = &entry.argv {
            // 2. argv[0] is {python} and is the only one
            match argv.first() {
                Some(Token::Brace(n)) if n == "python" => {}
                _ => err("R2/python-first", "argv[0] must be the token \"{python}\"".into()),
            }
            let pythons = argv.iter().filter(|t| t.brace_name() == Some("python")).count();
            if pythons != 1 {
                err("R2/python-once", format!("\"{{python}}\" appears {pythons} times; expected exactly 1"));
            }

            // 3. the script is a .py inside repo_dir (no ../ escape)
            let script = argv
                .iter()
                .skip(1)
                .find_map(|t| match t {
                    Token::Lit(s) if s == "-u" => None,
                    Token::Lit(s) => Some(s.clone()),
                    Token::Brace(_) => Some(String::new()),
                })
                .unwrap_or_default();
            if !script.ends_with(".py") {
                err("R3/script", format!("first literal after {{python}} must be a .py file, got {script:?}"));
            } else {
                let joined = repo_dir.join(&script);
                match joined.canonicalize() {
                    Err(e) => err("R3/script", format!("{script:?} not resolvable under repo_dir: {e}")),
                    Ok(canon) => {
                        let root = repo_dir.canonicalize().unwrap_or_else(|_| repo_dir.to_path_buf());
                        if !canon.starts_with(&root) {
                            err("R3/escape", format!("{script:?} resolves outside repo_dir: {}", canon.display()));
                        } else if !canon.is_file() {
                            err("R3/script", format!("{script:?} is not a regular file"));
                        }
                    }
                }
            }

            for tok in argv {
                if let Token::Brace(n) = tok {
                    if n == "python" {
                        continue;
                    }
                    // 4. every placeholder names a declared arg
                    if !arg_names.contains(n.as_str()) {
                        err("R4/undeclared", format!("argv placeholder {{{n}}} is not a declared arg"));
                        continue;
                    }
                    // 5. THE CLOSED-SET RULE
                    match kind_of(n) {
                        Some(k) if k.allowed_in_argv() => {}
                        Some(k) => err(
                            "R5/closed-set",
                            format!(
                                "arg {n:?} has kind {k:?}, which may not appear in argv. Only \
                                 enum and server kinds reach an argv element — that is what \
                                 keeps every element a set member or a server value."
                            ),
                        ),
                        None => {}
                    }
                }
            }
        }

        // --- runner coherence -------------------------------------------
        match entry.runner {
            Runner::ReadView => {
                // 7. a read view mutates nothing, spawns nothing, needs no gate
                if entry.mutating {
                    err("R7/read-view", "read_view must not be mutating".into());
                }
                if entry.argv.is_some() {
                    err("R7/read-view", "read_view must not declare argv".into());
                }
                if entry.authz.is_some() {
                    err("R7/read-view", "read_view must not declare authz".into());
                }
                match &entry.http {
                    None => err("R7/read-view", "read_view requires an http block".into()),
                    Some(h) => {
                        for q in &h.query {
                            if !arg_names.contains(q.arg.as_str()) {
                                err("R7/http-query", format!("http.query references undeclared arg {:?}", q.arg));
                            }
                        }
                    }
                }
            }
            Runner::Service => {
                // 8. a service is long-lived, mutating, and has an argv
                if !entry.mutating {
                    err("R8/service", "service runner implies mutating: true".into());
                }
                if entry.service.is_none() {
                    err("R8/service", "service runner requires a service block".into());
                }
                if entry.argv.is_none() {
                    err("R8/service", "service runner requires argv".into());
                }
            }
            Runner::Exec => {
                if entry.argv.is_none() && entry.enabled {
                    err("R8/exec", "exec runner requires argv".into());
                }
            }
        }

        // 9/10. effects vocabulary, and host contact demands a gate
        if entry.mutating && entry.effects.is_empty() {
            err("R9/effects", "mutating: true requires a non-empty effects list".into());
        }
        for e in &entry.effects {
            if !EFFECT_VOCAB.contains(&e.as_str()) {
                err("R9/effects", format!("unknown effect {e:?}; vocabulary is {EFFECT_VOCAB:?}"));
            }
        }
        if entry.effects.iter().any(|e| e == "contacts_host") && entry.authz.is_none() {
            err(
                "R10/gate",
                "effects include contacts_host, so an authz block is required — reaching a \
                 real host without a signed allow is the one thing the gate exists to stop"
                    .into(),
            );
        }

        // 11. authz target names a declared arg
        if let Some(Authz { target, .. }) = &entry.authz {
            if !arg_names.contains(target.arg.as_str()) {
                err("R11/authz-target", format!("authz.target.arg {:?} is not a declared arg", target.arg));
            }
        }

        // 12/14. option sources
        for arg in args {
            match (&arg.source, arg.kind) {
                (Some(Source::Server { generator, .. }), Kind::Server) => {
                    if !GENERATOR_VOCAB.contains(&generator.as_str()) {
                        err("R14/generator", format!("unknown generator {generator:?}"));
                    }
                }
                (Some(Source::Server { .. }), k) => {
                    err("R14/server-kind", format!("arg {:?} uses a server source but kind is {k:?}", arg.name))
                }
                (_, Kind::Server) => err(
                    "R14/server-kind",
                    format!("arg {:?} has kind server but no server source", arg.name),
                ),
                (Some(Source::View { capability, .. }), _) => match reg.get(capability) {
                    None => err("R12/view-source", format!("source capability {capability:?} does not exist")),
                    Some(t) => {
                        if t.runner != Runner::ReadView || t.mutating {
                            err(
                                "R12/view-source",
                                format!("source capability {capability:?} must be a non-mutating read_view"),
                            );
                        }
                    }
                },
                _ => {}
            }
            if let Some(dep) = &arg.depends_on {
                if !arg_names.contains(dep.as_str()) {
                    err("R12/depends-on", format!("arg {:?} depends_on undeclared arg {dep:?}", arg.name));
                }
            }
        }

        // 15. a mutating row must never be on an auto-refresh timer
        if let Some(d) = &entry.dashboard {
            if d.refresh_seconds > 0 && entry.mutating && entry.runner != Runner::Service {
                err(
                    "R15/no-auto-mutate",
                    format!(
                        "dashboard.refresh_seconds is {} on a mutating non-service capability — \
                         an auto-refresh timer must never fire something that writes",
                        d.refresh_seconds
                    ),
                );
            }
        }

        // 16. documented writes stay inside the repo
        for w in entry.writes.iter().flatten() {
            if w.starts_with('/') || w.contains("..") {
                err("R16/writes", format!("declared write {w:?} must be repo-relative with no .."));
            }
        }

        // 17. bounded timeout
        if let Some(t) = entry.timeout_ms {
            if t == 0 || t > 120_000 {
                err("R17/timeout", format!("timeout_ms {t} outside (0, 120000]"));
            }
        }

        // 13b. requires_preview points at a real entry with the same args
        if let Some(prev) = &entry.requires_preview {
            match reg.get(prev) {
                None => err("R13/preview", format!("requires_preview {prev:?} is not a capability")),
                Some(p) => {
                    let pa: HashSet<&str> = reg.args_of(p).iter().map(|a| a.name.as_str()).collect();
                    if pa != arg_names {
                        err(
                            "R13/preview",
                            format!("requires_preview {prev:?} declares args {pa:?}, this entry has {arg_names:?}"),
                        );
                    }
                }
            }
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Summary used in the boot log, so the operator can see what was admitted.
pub fn summarize(reg: &Registry) -> String {
    let total = reg.capabilities.len();
    let enabled = reg.capabilities.iter().filter(|e| e.enabled).count();
    let mutating = reg.capabilities.iter().filter(|e| e.mutating && e.enabled).count();
    let gated = reg.capabilities.iter().filter(|e| e.authz.is_some()).count();
    format!("{total} capabilities ({enabled} enabled, {mutating} mutating, {gated} gated)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_from(json: serde_json::Value) -> Registry {
        let mut r: Registry = serde_json::from_value(json).expect("registry parses");
        r.index();
        r
    }

    fn base_entry(extra: serde_json::Value) -> serde_json::Value {
        let mut e = serde_json::json!({
            "id": "test.cap", "label": "t", "group": "g", "summary": "s",
            "mutating": false, "runner": "exec",
            "argv": ["{python}", "nodebox_cli.py", "stack"],
            "args": [], "output": {"kind": "text-lines"}
        });
        if let (Some(a), Some(b)) = (e.as_object_mut(), extra.as_object()) {
            for (k, v) in b {
                a.insert(k.clone(), v.clone());
            }
        }
        e
    }

    fn dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    #[test]
    fn clean_entry_passes() {
        let r = reg_from(serde_json::json!({
            "version": 1, "schema": "x", "capabilities": [base_entry(serde_json::json!({}))]
        }));
        assert!(lint(&r, &dir()).is_ok());
    }

    #[test]
    fn multi_enum_in_argv_is_refused() {
        let r = reg_from(serde_json::json!({
            "version": 1, "schema": "x", "capabilities": [base_entry(serde_json::json!({
                "argv": ["{python}", "nodebox_cli.py", "{caps}"],
                "args": [{"name":"caps","label":"c","kind":"multi-enum","required":false,
                          "source":{"from":"static","values":[{"value":"A","label":"A"}]}}]
            }))]
        }));
        let errs = lint(&r, &dir()).unwrap_err();
        assert!(errs.iter().any(|e| e.rule == "R5/closed-set"), "{errs:?}");
    }

    #[test]
    fn script_outside_repo_is_refused() {
        let r = reg_from(serde_json::json!({
            "version": 1, "schema": "x", "capabilities": [base_entry(serde_json::json!({
                "argv": ["{python}", "../../../../etc/passwd.py"]
            }))]
        }));
        assert!(lint(&r, &dir()).is_err());
    }

    #[test]
    fn contacts_host_without_authz_is_refused() {
        let r = reg_from(serde_json::json!({
            "version": 1, "schema": "x", "capabilities": [base_entry(serde_json::json!({
                "mutating": true, "effects": ["contacts_host"]
            }))]
        }));
        let errs = lint(&r, &dir()).unwrap_err();
        assert!(errs.iter().any(|e| e.rule == "R10/gate"), "{errs:?}");
    }

    #[test]
    fn auto_refresh_on_a_mutating_row_is_refused() {
        let r = reg_from(serde_json::json!({
            "version": 1, "schema": "x", "capabilities": [base_entry(serde_json::json!({
                "mutating": true, "effects": ["writes_repo_file"],
                "dashboard": {"panel":"p","order":1,"refresh_seconds":5}
            }))]
        }));
        let errs = lint(&r, &dir()).unwrap_err();
        assert!(errs.iter().any(|e| e.rule == "R15/no-auto-mutate"), "{errs:?}");
    }

    #[test]
    fn the_real_registry_passes_its_own_lint() {
        let path = dir().join("toolbox_registry.json");
        let text = std::fs::read_to_string(&path).expect("registry readable");
        let mut r: Registry = serde_json::from_str(&text).expect("registry parses");
        r.index();
        match lint(&r, &dir()) {
            Ok(()) => {}
            Err(errs) => panic!("shipped registry fails lint:\n{}",
                errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n")),
        }
    }
}
