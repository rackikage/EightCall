//! Bridge to `authz_gate.py`. Fail-closed at every edge.
//!
//! The gate is not callable from Rust: it wants a request signed with a key
//! registered in `authz_policy.yml`. So a tiny Python shim
//! (`toolbox_authz_check.py`) builds and signs the request and asks the gate.
//! The shim adds no authority — the gate decides, the shim carries.
//!
//! DEFAULT-OFF BY DESIGN. If `DETECT_AUTHZ_KEY_TOOLBOX` is unset, every gated
//! capability is denied with a clear reason. That is deliberate: wiring this on
//! means the toolbox process holds an HMAC key that can authorize an action
//! against a real host, so it is an explicit operator decision (mint a caller
//! entry in authz_policy.yml, export the key) and never a silent default.
//!
//! There is no code path in this module where an error becomes an allow.
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::state::SharedState;

const GATE_TIMEOUT: Duration = Duration::from_secs(15);
const KEY_ENV: &str = "DETECT_AUTHZ_KEY_TOOLBOX";

/// Ok(decision_id) on an allow; Err(reason) on anything else.
pub async fn authorize(st: &SharedState, action: &str, target: &str) -> Result<String, String> {
    if std::env::var(KEY_ENV).ok().filter(|v| !v.is_empty()).is_none() {
        return Err(format!(
            "{KEY_ENV} is not set, so this capability cannot obtain a signed allow. \
             Register a caller in authz_policy.yml and export its key to enable it."
        ));
    }

    let request = json!({"action": action, "target": target});

    let mut child = Command::new(&st.python)
        .arg("toolbox_authz_check.py")
        .current_dir(&st.repo_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("gate shim failed to start: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload = serde_json::to_vec(&request).unwrap_or_default();
        if stdin.write_all(&payload).await.is_err() {
            return Err("gate shim closed its input".into());
        }
        drop(stdin);
    }

    let out = match timeout(GATE_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(format!("gate shim failed: {e}")),
        Err(_) => return Err("gate shim timed out".into()),
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim())
        .map_err(|_| format!("gate shim returned unparseable output: {}", String::from_utf8_lossy(&out.stderr).trim()))?;

    match parsed.get("allow").and_then(|v| v.as_bool()) {
        Some(true) => Ok(parsed
            .get("decision_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string()),
        _ => Err(parsed
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("denied")
            .to_string()),
    }
}
