//! Option-set resolution — where every dropdown's contents come from.
//!
//! Three providers, and none of them lets a caller name a value:
//!   * `static` — written in the registry.
//!   * `view`   — enumerated from a read-view capability's own JSON, which in
//!                turn reads an operator-controlled file (inventory.json,
//!                log_allowlist.yml). This is the honest phrasing of the
//!                closed-set property: argv values come only from operator
//!                -controlled files, not from compile-time constants.
//!   * `server` — never reachable here (403); generators run inside binding.
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::registry::{Entry, Opt, Source, Where};
use crate::state::SharedState;

const CACHE_TTL: Duration = Duration::from_secs(5);

pub async fn resolve(
    st: &SharedState,
    cap_id: &str,
    arg_name: &str,
    dep: Option<&str>,
) -> Result<Vec<Opt>, String> {
    let key = format!("{cap_id}|{arg_name}|{}", dep.unwrap_or(""));
    {
        let cache = st.options_cache.lock().await;
        if let Some((at, opts)) = cache.get(&key) {
            if at.elapsed() < CACHE_TTL {
                return Ok(opts.clone());
            }
        }
    }

    let entry = st.registry.get(cap_id).ok_or_else(|| format!("unknown capability {cap_id:?}"))?;
    let arg = st
        .registry
        .args_of(entry)
        .iter()
        .find(|a| a.name == arg_name)
        .ok_or_else(|| format!("unknown arg {arg_name:?}"))?;

    let opts = match arg.source.as_ref() {
        None => Vec::new(),
        Some(Source::Static { values }) => values.clone(),
        Some(Source::Server { .. }) => {
            return Err("server-generated arguments have no caller-visible option set".into())
        }
        Some(src @ Source::View { .. }) => resolve_view(st, src, dep).await?,
    };

    st.options_cache.lock().await.insert(key, (Instant::now(), opts.clone()));
    Ok(opts)
}

async fn resolve_view(st: &SharedState, src: &Source, dep: Option<&str>) -> Result<Vec<Opt>, String> {
    let Source::View { capability, args, items, value, label, scope, filters, explode } = src else {
        return Err("not a view source".into());
    };

    let target = st
        .registry
        .get(capability)
        .ok_or_else(|| format!("source capability {capability:?} missing"))?;

    let body = fetch_view(st, target, args).await?;
    let items_val = body.pointer(items).unwrap_or(&Value::Null);

    let rows: Vec<&Value> = match items_val {
        Value::Array(a) => a.iter().collect(),
        Value::Null => Vec::new(),
        other => vec![other],
    };

    let mut out = Vec::new();
    for row in rows {
        if !passes(row, filters) {
            continue;
        }
        let scope_val = scope
            .as_ref()
            .and_then(|p| row.pointer(p))
            .and_then(scalar_string);

        // depends_on: keep only options belonging to the selected parent
        if let (Some(d), Some(s)) = (dep, scope_val.as_deref()) {
            if d != s {
                continue;
            }
        }

        match explode {
            // one option per element of a per-row array/object
            Some(ptr) => {
                let inner = row.pointer(ptr).unwrap_or(&Value::Null);
                let leaves: Vec<Value> = match inner {
                    Value::Array(a) => a.clone(),
                    Value::Object(o) => o.keys().map(|k| Value::String(k.clone())).collect(),
                    Value::Null => vec![],
                    other => vec![other.clone()],
                };
                for leaf in leaves {
                    let v = pick(&leaf, value);
                    let l = pick(&leaf, label);
                    if let Some(v) = v {
                        out.push(Opt {
                            label: l.unwrap_or_else(|| v.clone()),
                            value: Value::String(v),
                            scope: scope_val.clone(),
                        });
                    }
                }
            }
            None => {
                let v = pick(row, value);
                let l = pick(row, label);
                if let Some(v) = v {
                    out.push(Opt {
                        label: l.unwrap_or_else(|| v.clone()),
                        value: Value::String(v),
                        scope: scope_val.clone(),
                    });
                }
            }
        }
    }
    out.dedup_by(|a, b| a.value == b.value && a.scope == b.scope);
    Ok(out)
}

/// `""` means "the item itself"; otherwise a JSON Pointer inside the item.
fn pick(item: &Value, ptr: &str) -> Option<String> {
    if ptr.is_empty() {
        return scalar_string(item);
    }
    item.pointer(ptr).and_then(scalar_string)
}

fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn passes(row: &Value, filters: &Option<Vec<Where>>) -> bool {
    let Some(fs) = filters else { return true };
    for f in fs {
        let actual = row.pointer(&f.path).unwrap_or(&Value::Null);
        let ok = match f.op.as_str() {
            "eq" => actual == &f.value,
            "neq" => actual != &f.value,
            "in" => f.value.as_array().map(|a| a.contains(actual)).unwrap_or(false),
            "truthy" => match actual {
                Value::Bool(b) => *b,
                Value::Null => false,
                Value::String(s) => !s.is_empty(),
                Value::Number(n) => n.as_f64().map(|x| x != 0.0).unwrap_or(false),
                _ => true,
            },
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Fetch a read-view capability's JSON straight from the Python sidecar, with
/// only registry-pinned literal query args.
pub async fn fetch_view(
    st: &SharedState,
    entry: &Entry,
    pinned: &serde_json::Map<String, Value>,
) -> Result<Value, String> {
    let http = entry.http.as_ref().ok_or("source capability has no http block")?;
    let url = format!("{}{}", st.sidecar_base, http.path);
    let mut req = st.http.get(&url);
    let q: Vec<(String, String)> = pinned
        .iter()
        .filter_map(|(k, v)| scalar_string(v).map(|s| (k.clone(), s)))
        .collect();
    if !q.is_empty() {
        req = req.query(&q);
    }
    let resp = req.send().await.map_err(|e| format!("sidecar unreachable: {e}"))?;
    resp.json::<Value>().await.map_err(|e| format!("sidecar returned non-JSON: {e}"))
}
