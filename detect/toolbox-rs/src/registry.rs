//! The registry data model.
//!
//! `toolbox_registry.json` is an operator-authored **policy file**, the same
//! trust class as `authz_policy.yml` / `log_allowlist.yml`. Its literals become
//! argv elements, so whoever can edit it can run repo scripts with fixed
//! arguments. It ships in git, is lint-checked before the listener binds, and
//! its sha256 travels in every response envelope.
//!
//! The load-bearing type here is `Token`. An argv template is a list of
//! strings, and each one is classified at DESERIALIZE time into exactly one of:
//!
//!   * `Token::Brace("python")` — the server's own `--python` path
//!   * `Token::Brace(name)`     — one whole argv element, filled from a bound arg
//!   * `Token::Lit(s)`          — a literal, containing no brace at all
//!
//! A string with a brace anywhere other than as a complete token is a
//! deserialize **error**. That is the point: `"--node={node}"` or
//! `"pre{x}post"` cannot be represented, so substring interpolation is not a
//! rule the lint has to catch — it is a shape the type system refuses to hold.
//! Combined with the lint's "only `enum`/`server` kinds may appear in argv",
//! every argv element is a registry literal, the server's interpreter path, a
//! server-generated token, or a member of an option set the server itself
//! enumerated from an operator-controlled file. A caller supplies an index
//! into a set, never a string.
use std::collections::HashMap;

use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub version: u32,
    pub schema: String,
    #[serde(default)]
    pub note: Option<String>,
    pub capabilities: Vec<Entry>,
    #[serde(skip)]
    pub by_id: HashMap<String, usize>,
}

impl Registry {
    pub fn index(&mut self) {
        self.by_id = self
            .capabilities
            .iter()
            .enumerate()
            .map(|(i, e)| (e.id.clone(), i))
            .collect();
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.by_id.get(id).map(|i| &self.capabilities[*i])
    }

    /// Resolve an entry's arg list, following an `args: {from: "<id>"}` link.
    /// The link is one level deep by construction — a linked entry must itself
    /// declare its args inline (lint rule 13).
    pub fn args_of<'a>(&'a self, entry: &'a Entry) -> &'a [Arg] {
        match &entry.args {
            ArgSpec::Inline(v) => v,
            ArgSpec::From { from } => match self.get(from) {
                Some(target) => match &target.args {
                    ArgSpec::Inline(v) => v,
                    ArgSpec::From { .. } => &[],
                },
                None => &[],
            },
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub label: String,
    pub group: String,
    pub summary: String,
    pub mutating: bool,
    pub runner: Runner,
    pub args: ArgSpec,
    pub output: Output,

    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub effects: Vec<String>,
    #[serde(default)]
    pub argv: Option<Vec<Token>>,
    #[serde(default)]
    pub http: Option<Http>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub confirm: Option<Confirm>,
    #[serde(default)]
    pub requires_preview: Option<String>,
    #[serde(default)]
    pub writes: Option<Vec<String>>,
    #[serde(default)]
    pub authz: Option<Authz>,
    #[serde(default)]
    pub service: Option<ServiceCfg>,
    #[serde(default)]
    pub dashboard: Option<Dashboard>,
    #[serde(default)]
    pub docs: Option<Docs>,
}

impl Entry {
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.timeout_ms.unwrap_or(30_000))
    }
    pub fn confirm_mode(&self) -> Confirm {
        self.confirm.unwrap_or(Confirm::None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runner {
    ReadView,
    Exec,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confirm {
    None,
    Click,
    TypeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Enum,
    MultiEnum,
    Int,
    Bool,
    Server,
}

impl Kind {
    /// The closed-set rule: only these kinds may ever reach an argv element.
    pub fn allowed_in_argv(self) -> bool {
        matches!(self, Kind::Enum | Kind::Server)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ArgSpec {
    Inline(Vec<Arg>),
    From { from: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arg {
    pub name: String,
    pub label: String,
    pub kind: Kind,
    pub required: bool,
    #[serde(default)]
    pub default: Option<Value>,
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
    #[serde(default)]
    pub depends_on: Option<String>,
    #[serde(default)]
    pub source: Option<Source>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum Source {
    /// Values written verbatim in the registry.
    Static { values: Vec<Opt> },
    /// Values enumerated from another read-view capability's own output, so a
    /// dropdown's option set is derived from an operator-controlled file
    /// (inventory.json, log_allowlist.yml) rather than typed by a caller.
    View {
        capability: String,
        #[serde(default)]
        args: Map<String, Value>,
        items: String,
        value: String,
        label: String,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default, rename = "where")]
        filters: Option<Vec<Where>>,
        #[serde(default)]
        explode: Option<String>,
    },
    /// Produced by the server; a caller-supplied value is always a 400.
    Server {
        generator: String,
        #[serde(default)]
        params: Map<String, Value>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opt {
    pub value: Value,
    pub label: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Where {
    pub path: String,
    pub op: String,
    pub value: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http {
    pub path: String,
    pub query: Vec<QueryParam>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryParam {
    pub arg: String,
    pub param: String,
    #[serde(default)]
    pub repeat: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authz {
    pub action: String,
    pub target: AuthzTarget,
    pub required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthzTarget {
    pub arg: String,
    pub prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCfg {
    #[serde(default)]
    pub singleton: bool,
    #[serde(default = "default_log_cap")]
    pub log_cap: usize,
    #[serde(default)]
    pub stop_signal: Option<String>,
    #[serde(default = "default_grace")]
    pub grace_ms: u64,
    #[serde(default = "default_reap")]
    pub reap_poll_ms: u64,
}

fn default_log_cap() -> usize {
    500
}
fn default_grace() -> u64 {
    2000
}
fn default_reap() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dashboard {
    pub panel: String,
    pub order: i64,
    #[serde(default)]
    pub refresh_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Docs {
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub hazard: Option<String>,
}

/// Rendering hints. Rust never interprets these beyond `kind` — the frontend
/// owns presentation, so new output shapes are a registry + TS concern and
/// never touch the dispatcher.
#[derive(Debug, Deserialize)]
pub struct Output {
    pub kind: String,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

// ----------------------------------------------------------------------- //
// Token — the whole safety story lives in this Deserialize impl.
// ----------------------------------------------------------------------- //

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Lit(String),
    Brace(String),
}

impl Token {
    pub fn brace_name(&self) -> Option<&str> {
        match self {
            Token::Brace(n) => Some(n),
            Token::Lit(_) => None,
        }
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let opens = s.matches('{').count();
        let closes = s.matches('}').count();

        if opens == 0 && closes == 0 {
            return Ok(Token::Lit(s));
        }
        // Exactly one brace pair, and it must wrap the ENTIRE token.
        if opens == 1 && closes == 1 && s.starts_with('{') && s.ends_with('}') && s.len() > 2 {
            let name = &s[1..s.len() - 1];
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(de::Error::custom(format!(
                    "argv placeholder {s:?} must name an arg using [A-Za-z0-9_-]"
                )));
            }
            return Ok(Token::Brace(name.to_string()));
        }
        Err(de::Error::custom(format!(
            "argv token {s:?} mixes text with a placeholder. A token is either a \
             literal with no braces, or exactly \"{{name}}\". Substring \
             interpolation is not representable — split it into separate argv \
             elements (e.g. [\"--node\", \"{{node}}\"], not [\"--node={{node}}\"])."
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(s: &str) -> Result<Token, serde_json::Error> {
        serde_json::from_value(Value::String(s.to_string()))
    }

    #[test]
    fn plain_literal_is_a_literal() {
        assert_eq!(tok("--node").unwrap(), Token::Lit("--node".into()));
        assert_eq!(tok("nodebox_cli.py").unwrap(), Token::Lit("nodebox_cli.py".into()));
    }

    #[test]
    fn whole_placeholder_is_a_brace() {
        assert_eq!(tok("{node}").unwrap(), Token::Brace("node".into()));
        assert_eq!(tok("{python}").unwrap(), Token::Brace("python".into()));
    }

    #[test]
    fn substring_interpolation_is_unrepresentable() {
        // The core claim: these cannot be loaded at all, so no lint rule and no
        // runtime check has to catch them.
        for bad in [
            "--node={node}",
            "{node}suffix",
            "prefix{node}",
            "{a}{b}",
            "{node",
            "node}",
            "--flag={a}--other={b}",
            "{}",
        ] {
            assert!(tok(bad).is_err(), "{bad:?} should be rejected at deserialize");
        }
    }

    #[test]
    fn placeholder_charset_is_bounded() {
        assert!(tok("{node name}").is_err());
        assert!(tok("{../etc/passwd}").is_err());
        assert!(tok("{node_id}").is_ok());
        assert!(tok("{rules-dir}").is_ok());
    }
}
