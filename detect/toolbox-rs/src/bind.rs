//! Argument binding and argv construction.
//!
//! `Bound` is the type that makes "one arg became two argv elements"
//! impossible: `as_single()` exists only on the single-valued variants, so a
//! multi-valued or absent binding cannot be spliced into an argv slot — that
//! is a compile error, not a runtime hazard.
use std::collections::BTreeMap;

use serde_json::Value;

use crate::registry::{Arg, Entry, Kind, Token};

#[derive(Debug, Clone)]
pub enum Bound {
    Single(String),
    Multi(Vec<String>),
    Int(i64),
    Bool(bool),
}

impl Bound {
    /// Exactly one argv element. Only ever available for single-valued kinds.
    pub fn as_single(&self) -> Option<&str> {
        match self {
            Bound::Single(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_multi(&self) -> Vec<String> {
        match self {
            Bound::Single(s) => vec![s.clone()],
            Bound::Multi(v) => v.clone(),
            Bound::Int(i) => vec![i.to_string()],
            Bound::Bool(b) => vec![b.to_string()],
        }
    }
    pub fn to_query_value(&self) -> String {
        match self {
            Bound::Single(s) => s.clone(),
            Bound::Int(i) => i.to_string(),
            Bound::Bool(b) => b.to_string(),
            Bound::Multi(v) => v.join(","),
        }
    }
    pub fn to_json(&self) -> Value {
        match self {
            Bound::Single(s) => Value::String(s.clone()),
            Bound::Multi(v) => Value::Array(v.iter().map(|s| Value::String(s.clone())).collect()),
            Bound::Int(i) => Value::from(*i),
            Bound::Bool(b) => Value::Bool(*b),
        }
    }
}

pub type Bindings = BTreeMap<String, Bound>;

#[derive(Debug)]
pub enum Invalid {
    UnknownArg(String),
    Missing(String),
    NotAMember { arg: String, value: String },
    OutOfRange { arg: String, detail: String },
    WrongType { arg: String, expected: &'static str },
    ServerArg(String),
}

impl Invalid {
    pub fn message(&self) -> String {
        match self {
            Invalid::UnknownArg(a) => format!("unknown argument {a:?}"),
            Invalid::Missing(a) => format!("missing required argument {a:?}"),
            Invalid::NotAMember { arg, value } => format!(
                "{value:?} is not a member of the option set for {arg:?} — a caller picks from \
                 the server's set, it does not supply a string"
            ),
            Invalid::OutOfRange { arg, detail } => format!("{arg:?} out of range: {detail}"),
            Invalid::WrongType { arg, expected } => format!("{arg:?} must be {expected}"),
            Invalid::ServerArg(a) => format!(
                "{a:?} is server-generated; a caller-supplied value is never accepted as an override"
            ),
        }
    }
}

/// Build the argv. Every element is one of: the server's interpreter path, a
/// registry literal, or a single bound value. There is no shell, no joining,
/// and no splitting.
pub fn build_argv(entry: &Entry, bound: &Bindings, python: &str) -> Result<Vec<String>, String> {
    let template = entry.argv.as_ref().ok_or("capability declares no argv")?;
    let mut out = Vec::with_capacity(template.len());
    for tok in template {
        match tok {
            Token::Brace(n) if n == "python" => out.push(python.to_string()),
            Token::Brace(n) => match bound.get(n.as_str()) {
                // Optional-and-absent placeholders are dropped along with
                // nothing else; the lint guarantees required ones are present.
                None => {}
                Some(b) => match b.as_single() {
                    Some(s) => out.push(s.to_string()),
                    None => {
                        return Err(format!(
                            "arg {n:?} is not single-valued and cannot occupy an argv slot"
                        ))
                    }
                },
            },
            Token::Lit(s) => out.push(s.clone()),
        }
    }
    Ok(out)
}

/// Coerce one submitted value against its declared kind. Option-set membership
/// is checked by the caller (it needs async resolution); this handles shape.
pub fn coerce(arg: &Arg, submitted: Option<&Value>) -> Result<Option<Bound>, Invalid> {
    let name = arg.name.clone();

    if arg.kind == Kind::Server {
        if submitted.is_some() {
            return Err(Invalid::ServerArg(name));
        }
        return Ok(None); // filled by a generator later
    }

    let v = match submitted {
        Some(Value::Null) | None => match &arg.default {
            Some(d) if !d.is_null() => d,
            _ => {
                return if arg.required {
                    Err(Invalid::Missing(name))
                } else {
                    Ok(None)
                }
            }
        },
        Some(v) => v,
    };

    let bound = match arg.kind {
        Kind::Enum => match v {
            Value::String(s) => Bound::Single(s.clone()),
            _ => return Err(Invalid::WrongType { arg: name, expected: "a string from the option set" }),
        },
        Kind::MultiEnum => match v {
            Value::Array(items) => {
                let mut out = Vec::new();
                for it in items {
                    match it {
                        Value::String(s) => out.push(s.clone()),
                        _ => return Err(Invalid::WrongType { arg: name, expected: "an array of strings" }),
                    }
                }
                out.sort();
                out.dedup();
                if out.is_empty() && arg.required {
                    return Err(Invalid::Missing(name));
                }
                Bound::Multi(out)
            }
            _ => return Err(Invalid::WrongType { arg: name, expected: "an array of strings" }),
        },
        Kind::Int => {
            let i = v
                .as_i64()
                .ok_or(Invalid::WrongType { arg: name.clone(), expected: "an integer" })?;
            if let Some(min) = arg.min {
                if i < min {
                    return Err(Invalid::OutOfRange { arg: name, detail: format!("{i} < min {min}") });
                }
            }
            if let Some(max) = arg.max {
                if i > max {
                    return Err(Invalid::OutOfRange { arg: name, detail: format!("{i} > max {max}") });
                }
            }
            Bound::Int(i)
        }
        Kind::Bool => match v {
            Value::Bool(b) => Bound::Bool(*b),
            _ => return Err(Invalid::WrongType { arg: name, expected: "a boolean" }),
        },
        Kind::Server => unreachable!("handled above"),
    };
    Ok(Some(bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;

    fn entry(argv: serde_json::Value, args: serde_json::Value) -> Entry {
        serde_json::from_value(serde_json::json!({
            "id":"t.c","label":"t","group":"g","summary":"s","mutating":false,
            "runner":"exec","argv":argv,"args":args,"output":{"kind":"text-lines"}
        }))
        .unwrap()
    }

    #[test]
    fn argv_is_literals_plus_whole_values() {
        let e = entry(
            serde_json::json!(["{python}", "nodebox_cli.py", "ssh", "--node", "{node}"]),
            serde_json::json!([{"name":"node","label":"n","kind":"enum","required":true}]),
        );
        let mut b = Bindings::new();
        b.insert("node".into(), Bound::Single("gateway".into()));
        let argv = build_argv(&e, &b, "/venv/bin/python3").unwrap();
        assert_eq!(argv, vec!["/venv/bin/python3", "nodebox_cli.py", "ssh", "--node", "gateway"]);
    }

    #[test]
    fn a_value_with_spaces_stays_one_element() {
        // The exact failure the old split(' ') reconstruction had.
        let e = entry(
            serde_json::json!(["{python}", "x.py", "{v}"]),
            serde_json::json!([{"name":"v","label":"v","kind":"enum","required":true}]),
        );
        let mut b = Bindings::new();
        b.insert("v".into(), Bound::Single("two words".into()));
        let argv = build_argv(&e, &b, "py").unwrap();
        assert_eq!(argv.len(), 3);
        assert_eq!(argv[2], "two words");
    }

    #[test]
    fn a_value_cannot_inject_an_extra_flag() {
        // Even a value that looks like a flag is still exactly one element.
        let e = entry(
            serde_json::json!(["{python}", "x.py", "{v}"]),
            serde_json::json!([{"name":"v","label":"v","kind":"enum","required":true}]),
        );
        let mut b = Bindings::new();
        b.insert("v".into(), Bound::Single("--execute --other".into()));
        let argv = build_argv(&e, &b, "py").unwrap();
        assert_eq!(argv, vec!["py", "x.py", "--execute --other"]);
        assert_eq!(argv.len(), 3, "must not become 4 elements");
    }

    #[test]
    fn multi_valued_binding_cannot_fill_an_argv_slot() {
        let e = entry(
            serde_json::json!(["{python}", "x.py", "{v}"]),
            serde_json::json!([{"name":"v","label":"v","kind":"enum","required":true}]),
        );
        let mut b = Bindings::new();
        b.insert("v".into(), Bound::Multi(vec!["a".into(), "b".into()]));
        assert!(build_argv(&e, &b, "py").is_err());
    }

    #[test]
    fn server_arg_refuses_a_caller_value() {
        let arg: Arg = serde_json::from_value(serde_json::json!({
            "name":"out","label":"o","kind":"server","required":true,
            "source":{"from":"server","generator":"timestamp_path","params":{}}
        }))
        .unwrap();
        assert!(matches!(
            coerce(&arg, Some(&serde_json::json!("/etc/passwd"))),
            Err(Invalid::ServerArg(_))
        ));
        assert!(coerce(&arg, None).unwrap().is_none());
    }

    #[test]
    fn int_range_is_enforced() {
        let arg: Arg = serde_json::from_value(serde_json::json!({
            "name":"limit","label":"l","kind":"int","required":false,"default":25,"min":1,"max":500
        }))
        .unwrap();
        assert!(matches!(coerce(&arg, Some(&serde_json::json!(9999))), Err(Invalid::OutOfRange { .. })));
        assert!(matches!(coerce(&arg, Some(&serde_json::json!(0))), Err(Invalid::OutOfRange { .. })));
        assert!(coerce(&arg, Some(&serde_json::json!(50))).is_ok());
        // absent -> default
        match coerce(&arg, None).unwrap().unwrap() {
            Bound::Int(i) => assert_eq!(i, 25),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn real_registry_argv_templates_all_build() {
        // Every shipped entry's argv must be constructible once its enum args
        // are bound — proves the template/arg declarations actually agree.
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../toolbox_registry.json");
        let mut reg: Registry = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        reg.index();
        for e in &reg.capabilities {
            if e.argv.is_none() {
                continue;
            }
            let mut b = Bindings::new();
            for a in reg.args_of(e) {
                if a.kind.allowed_in_argv() {
                    b.insert(a.name.clone(), Bound::Single(format!("<{}>", a.name)));
                }
            }
            let argv = build_argv(e, &b, "py").unwrap_or_else(|err| panic!("{}: {err}", e.id));
            assert_eq!(argv[0], "py", "{} argv[0]", e.id);
            assert!(argv.len() >= 2, "{} argv too short", e.id);
        }
    }
}
