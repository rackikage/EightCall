//! The generic dispatcher: three runners behind one route table.
//!
//! There is no per-capability code anywhere in this file. Adding a command is
//! adding a row to `toolbox_registry.json` and restarting — no Rust rebuild,
//! no TypeScript edit.
use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use crate::bind::{build_argv, coerce, Bindings, Bound};
use crate::options;
use crate::registry::{Arg, Confirm, Entry, Kind, Runner, Source};
use crate::state::{PreviewToken, ServiceRun, SharedState};

const PREVIEW_TTL: Duration = Duration::from_secs(120);

// ------------------------------------------------------------------ //
// envelope
// ------------------------------------------------------------------ //

fn envelope(st: &SharedState, entry: &Entry, output: Value, extra: Value) -> Value {
    let mut env = json!({
        "ok": true,
        "capability": entry.id,
        "output": output,
        "attribution": {
            "registry_sha256": st.registry_sha256,
            "effects": entry.effects,
            "mutating": entry.mutating,
        }
    });
    if let (Some(e), Some(x)) = (env.as_object_mut(), extra.as_object()) {
        for (k, v) in x {
            if k == "attribution" {
                if let (Some(a), Some(b)) = (
                    e.get_mut("attribution").and_then(|a| a.as_object_mut()),
                    v.as_object(),
                ) {
                    for (kk, vv) in b {
                        a.insert(kk.clone(), vv.clone());
                    }
                }
            } else {
                e.insert(k.clone(), v.clone());
            }
        }
    }
    env
}

fn fail(code: StatusCode, capability: &str, msg: impl Into<String>) -> Response {
    (
        code,
        Json(json!({"ok": false, "capability": capability, "error": msg.into()})),
    )
        .into_response()
}

// ------------------------------------------------------------------ //
// GET /api/registry
// ------------------------------------------------------------------ //

pub async fn registry(State(st): State<SharedState>) -> Response {
    // Serve the file verbatim so the UI renders exactly what the lint admitted.
    let path = st.repo_dir.join("toolbox_registry.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(mut v) => {
                if let Some(o) = v.as_object_mut() {
                    o.insert("sha256".into(), Value::String(st.registry_sha256.clone()));
                }
                Json(v).into_response()
            }
            Err(e) => fail(StatusCode::INTERNAL_SERVER_ERROR, "registry", format!("unreadable: {e}")),
        },
        Err(e) => fail(StatusCode::INTERNAL_SERVER_ERROR, "registry", format!("unreadable: {e}")),
    }
}

pub async fn healthz(State(st): State<SharedState>) -> Response {
    let sidecar_ok = st
        .http
        .get(format!("{}/healthz", st.sidecar_base))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    Json(json!({
        "status": "ok",
        "sidecar": if sidecar_ok { "ok" } else { "down" },
        "registry_sha256": st.registry_sha256,
        "capabilities": st.registry.capabilities.len(),
    }))
    .into_response()
}

// ------------------------------------------------------------------ //
// GET /api/options/:cap/:arg
// ------------------------------------------------------------------ //

#[derive(Deserialize)]
pub struct OptionsQuery {
    dep: Option<String>,
}

pub async fn options_for(
    State(st): State<SharedState>,
    Path((cap, arg)): Path<(String, String)>,
    Query(q): Query<OptionsQuery>,
) -> Response {
    match options::resolve(&st, &cap, &arg, q.dep.as_deref()).await {
        Ok(opts) => Json(json!({"capability": cap, "arg": arg, "options": opts
            .iter()
            .map(|o| json!({"value": o.value, "label": o.label, "scope": o.scope}))
            .collect::<Vec<_>>()}))
        .into_response(),
        Err(e) => fail(StatusCode::BAD_REQUEST, &cap, e),
    }
}

// ------------------------------------------------------------------ //
// binding: shape-check, then membership-check against a freshly resolved set
// ------------------------------------------------------------------ //

async fn bind_args(
    st: &SharedState,
    entry: &Entry,
    submitted: &Map<String, Value>,
) -> Result<Bindings, String> {
    let args: Vec<&Arg> = st.registry.args_of(entry).iter().collect();
    let declared: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();

    for k in submitted.keys() {
        if !declared.contains(&k.as_str()) {
            return Err(format!("unknown argument {k:?}"));
        }
    }

    let mut bound: Bindings = BTreeMap::new();
    for arg in &args {
        let got = submitted.get(&arg.name);
        let coerced = coerce(arg, got).map_err(|e| e.message())?;

        let Some(b) = coerced else {
            // server-generated, or absent-and-optional
            if arg.kind == Kind::Server {
                let generated = generate(st, arg)?;
                bound.insert(arg.name.clone(), Bound::Single(generated));
            }
            continue;
        };

        // membership is re-resolved server-side at request time; a stale list
        // cached in a browser can never widen what is accepted
        if matches!(arg.kind, Kind::Enum | Kind::MultiEnum) {
            let dep = arg
                .depends_on
                .as_ref()
                .and_then(|d| bound.get(d.as_str()))
                .and_then(|b| b.as_single().map(|s| s.to_string()));
            let allowed = options::resolve(st, &entry.id, &arg.name, dep.as_deref())
                .await
                .map_err(|e| format!("cannot resolve options for {:?}: {e}", arg.name))?;
            let allowed_vals: Vec<String> = allowed
                .iter()
                .filter_map(|o| o.value.as_str().map(|s| s.to_string()))
                .collect();
            for v in b.as_multi() {
                if !allowed_vals.contains(&v) {
                    return Err(format!(
                        "{v:?} is not a member of the option set for {:?} — a caller picks from \
                         the server's set, it never supplies a free string (allowed: {allowed_vals:?})",
                        arg.name
                    ));
                }
            }
        }
        bound.insert(arg.name.clone(), b);
    }
    Ok(bound)
}

fn generate(st: &SharedState, arg: &Arg) -> Result<String, String> {
    let Some(Source::Server { generator, params }) = arg.source.as_ref() else {
        return Err(format!("arg {:?} has no server source", arg.name));
    };
    match generator.as_str() {
        "timestamp_path" => {
            let dir = params.get("dir").and_then(|v| v.as_str()).unwrap_or(".");
            let prefix = params.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
            let ext = params.get("ext").and_then(|v| v.as_str()).unwrap_or("");
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let rel = format!("{dir}/{prefix}{ts}{ext}");
            // the generated path must land inside the repo
            if rel.contains("..") || rel.starts_with('/') {
                return Err("generated path escaped the repo".into());
            }
            let _ = st;
            Ok(rel)
        }
        other => Err(format!("unknown generator {other:?}")),
    }
}

// ------------------------------------------------------------------ //
// POST /api/run/:cap  — the one dispatch entry point
// ------------------------------------------------------------------ //

#[derive(Deserialize, Default)]
pub struct RunRequest {
    #[serde(default)]
    pub args: Map<String, Value>,
    #[serde(default)]
    pub confirm: Option<String>,
    #[serde(default)]
    pub preview_token: Option<String>,
}

pub async fn run(
    State(st): State<SharedState>,
    Path(cap): Path<String>,
    body: Option<Json<RunRequest>>,
) -> Response {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let Some(entry) = st.registry.get(&cap) else {
        return fail(StatusCode::NOT_FOUND, &cap, "no such capability");
    };
    if !entry.enabled {
        let why = entry
            .docs
            .as_ref()
            .and_then(|d| d.notes.clone())
            .unwrap_or_else(|| "capability is disabled".into());
        return fail(StatusCode::GONE, &cap, why);
    }

    // confirm gate
    match entry.confirm_mode() {
        Confirm::None => {}
        Confirm::Click => {
            if req.confirm.as_deref() != Some("yes") {
                return fail(StatusCode::PRECONDITION_REQUIRED, &cap, "confirmation required");
            }
        }
        Confirm::TypeId => {
            if req.confirm.as_deref() != Some(entry.id.as_str()) {
                return fail(
                    StatusCode::PRECONDITION_REQUIRED,
                    &cap,
                    format!("type the capability id {:?} to confirm", entry.id),
                );
            }
        }
    }

    let (bound, authz_decision) =
        match bind_preview_authz(&st, entry, &req.args, req.preview_token.as_deref()).await {
            Ok(v) => v,
            Err((code, msg)) => return fail(code, &cap, msg),
        };
    dispatch(&st, entry, &bound, authz_decision).await
}

/// bind → preview → gate: the shared spine a direct `run` AND an authorized
/// proposal both take. A proposal cannot reach a runner by any other path.
async fn bind_preview_authz(
    st: &SharedState,
    entry: &Entry,
    submitted: &Map<String, Value>,
    preview_token: Option<&str>,
) -> Result<(Bindings, Option<String>), (StatusCode, String)> {
    let bound = bind_args(st, entry, submitted)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // preview-before-execute
    if let Some(prev_id) = &entry.requires_preview {
        let args_json = canonical(&bound);
        let token = match preview_token {
            Some(t) => t.to_string(),
            None => {
                return Err((
                    StatusCode::PRECONDITION_REQUIRED,
                    format!("run {prev_id} first and pass its preview_token"),
                ))
            }
        };
        let mut store = st.previews.lock().await;
        match store.remove(&token) {
            Some(p) if p.capability == *prev_id && p.args_json == args_json && p.issued.elapsed() < PREVIEW_TTL => {}
            Some(_) => {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    "preview token does not match these arguments".into(),
                ))
            }
            None => {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    "preview token is unknown, used, or expired".into(),
                ))
            }
        }
    }

    // authorization gate — fail closed at every edge
    let mut authz_decision: Option<String> = None;
    if let Some(az) = &entry.authz {
        if az.required {
            let target = bound
                .get(az.target.arg.as_str())
                .and_then(|b| b.as_single())
                .map(|v| format!("{}{}", az.target.prefix, v))
                .unwrap_or_default();
            match crate::authz::authorize(st, &az.action, &target).await {
                Ok(id) => authz_decision = Some(id),
                Err(reason) => return Err((StatusCode::FORBIDDEN, format!("gate denied: {reason}"))),
            }
        }
    }
    Ok((bound, authz_decision))
}

/// The one place a runner is chosen.
async fn dispatch(
    st: &SharedState,
    entry: &Entry,
    bound: &Bindings,
    authz_decision: Option<String>,
) -> Response {
    match entry.runner {
        Runner::ReadView => run_read_view(st, entry, bound).await,
        Runner::Exec => run_exec(st, entry, bound, authz_decision).await,
        Runner::Service => start_service(st, entry, bound).await,
    }
}

// ------------------------------------------------------------------ //
// the approval queue — propose (file) / authorize (fire) / reject
// ------------------------------------------------------------------ //

/// GET /api/proposals — the queue, oldest first.
pub async fn proposals_list(State(st): State<SharedState>) -> Response {
    Json(json!({"proposals": st.proposals.list().await})).into_response()
}

#[derive(Deserialize, Default)]
pub struct CreateProposalRequest {
    #[serde(default)]
    pub capability: String,
    #[serde(default)]
    pub args: Map<String, Value>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
}

/// POST /api/proposals — file a proposal. This runs NOTHING; it validates the
/// capability exists and its args bind (option-set membership re-resolved), so
/// the queue can never hold a malformed request, then records it as pending.
pub async fn proposal_create(
    State(st): State<SharedState>,
    body: Option<Json<CreateProposalRequest>>,
) -> Response {
    let Some(Json(req)) = body else {
        return fail(StatusCode::BAD_REQUEST, "proposals", "missing JSON body");
    };
    let Some(entry) = st.registry.get(&req.capability) else {
        return fail(StatusCode::NOT_FOUND, &req.capability, "no such capability");
    };
    if !entry.enabled {
        return fail(StatusCode::GONE, &req.capability, "capability is disabled");
    }
    // shape + membership check now; the value is discarded, the point is that a
    // malformed proposal never enters the queue.
    if let Err(e) = bind_args(&st, entry, &req.args).await {
        return fail(StatusCode::BAD_REQUEST, &req.capability, e);
    }
    let created_by = req.created_by.as_deref().unwrap_or("operator");
    match st
        .proposals
        .create(&req.capability, req.args, req.note, created_by)
        .await
    {
        Ok(p) => (StatusCode::CREATED, Json(json!({"ok": true, "proposal": p}))).into_response(),
        Err(e) => fail(StatusCode::INTERNAL_SERVER_ERROR, &req.capability, e),
    }
}

#[derive(Deserialize, Default)]
pub struct AuthorizeProposalRequest {
    #[serde(default)]
    pub confirm: Option<String>,
    #[serde(default)]
    pub preview_token: Option<String>,
}

/// POST /api/proposals/:id/authorize — the operator mints the go. Requires the
/// proposal id typed back (`confirm`), then runs the SAME spine as /api/run:
/// bind → preview → gate → runner. On any failure nothing runs and the proposal
/// is left pending. The gate remains the only authority.
pub async fn proposal_authorize(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    body: Option<Json<AuthorizeProposalRequest>>,
) -> Response {
    let req = body.map(|Json(b)| b).unwrap_or_default();

    let Some(prop) = st.proposals.get(&id).await else {
        return fail(StatusCode::NOT_FOUND, &id, "no such proposal");
    };
    if !prop.status.is_open() {
        return fail(
            StatusCode::CONFLICT,
            &id,
            format!("proposal is {:?}, not pending", prop.status),
        );
    }
    // typed-id confirmation: the operator must type the proposal id back
    if req.confirm.as_deref() != Some(id.as_str()) {
        return fail(
            StatusCode::PRECONDITION_REQUIRED,
            &id,
            "type the proposal id to authorize",
        );
    }

    let Some(entry) = st.registry.get(&prop.capability) else {
        return fail(StatusCode::NOT_FOUND, &id, "proposal names no known capability");
    };
    if !entry.enabled {
        return fail(StatusCode::GONE, &id, "capability is disabled");
    }

    let (bound, authz_decision) =
        match bind_preview_authz(&st, entry, &prop.args, req.preview_token.as_deref()).await {
            Ok(v) => v,
            Err((code, msg)) => return fail(code, &id, msg),
        };

    // record the operator's authorization (carrying the gate's decision id)
    let _ = st
        .proposals
        .mark_authorized(&id, authz_decision.clone())
        .await;

    let resp = dispatch(&st, entry, &bound, authz_decision).await;
    if resp.status().is_success() {
        let _ = st.proposals.mark_fired(&id).await;
    } else {
        let _ = st
            .proposals
            .mark_failed(&id, format!("runner returned {}", resp.status()))
            .await;
    }
    resp
}

#[derive(Deserialize, Default)]
pub struct RejectProposalRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /api/proposals/:id/reject — terminal, no action taken.
pub async fn proposal_reject(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    body: Option<Json<RejectProposalRequest>>,
) -> Response {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let Some(prop) = st.proposals.get(&id).await else {
        return fail(StatusCode::NOT_FOUND, &id, "no such proposal");
    };
    if !prop.status.is_open() {
        return fail(
            StatusCode::CONFLICT,
            &id,
            format!("proposal is {:?}, not pending", prop.status),
        );
    }
    let reason = req.reason.unwrap_or_default();
    match st.proposals.mark_rejected(&id, reason).await {
        Ok(()) => Json(json!({"ok": true, "id": id, "status": "rejected"})).into_response(),
        Err(e) => fail(StatusCode::INTERNAL_SERVER_ERROR, &id, e),
    }
}

fn canonical(bound: &Bindings) -> String {
    let map: Map<String, Value> = bound.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
    serde_json::to_string(&Value::Object(map)).unwrap_or_default()
}

// ------------------------------------------------------------------ //
// runner: read_view (proxy to the python sidecar)
// ------------------------------------------------------------------ //

pub async fn read(
    State(st): State<SharedState>,
    Path(cap): Path<String>,
    Query(raw): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(entry) = st.registry.get(&cap) else {
        return fail(StatusCode::NOT_FOUND, &cap, "no such capability");
    };
    if entry.runner != Runner::ReadView {
        return fail(StatusCode::METHOD_NOT_ALLOWED, &cap, "not a read view; POST /api/run/<id>");
    }
    // GET convenience: values arrive as strings, so coerce ints/arrays here
    let mut submitted = Map::new();
    for arg in st.registry.args_of(entry) {
        if let Some(v) = raw.get(&arg.name) {
            let val = match arg.kind {
                Kind::Int => v.parse::<i64>().map(Value::from).unwrap_or(Value::String(v.clone())),
                Kind::MultiEnum => Value::Array(
                    v.split(',').filter(|s| !s.is_empty()).map(|s| Value::String(s.to_string())).collect(),
                ),
                _ => Value::String(v.clone()),
            };
            submitted.insert(arg.name.clone(), val);
        }
    }
    let bound = match bind_args(&st, entry, &submitted).await {
        Ok(b) => b,
        Err(e) => return fail(StatusCode::BAD_REQUEST, &cap, e),
    };
    run_read_view(&st, entry, &bound).await
}

async fn run_read_view(st: &SharedState, entry: &Entry, bound: &Bindings) -> Response {
    let Some(http) = &entry.http else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, &entry.id, "read view has no http block");
    };
    let url = format!("{}{}", st.sidecar_base, http.path);
    let mut pairs: Vec<(String, String)> = Vec::new();
    for q in &http.query {
        let Some(b) = bound.get(q.arg.as_str()) else { continue };
        if q.repeat {
            for v in b.as_multi() {
                pairs.push((q.param.clone(), v));
            }
        } else {
            pairs.push((q.param.clone(), b.to_query_value()));
        }
    }

    let started = Instant::now();
    let mut req = st.http.get(&url);
    if !pairs.is_empty() {
        req = req.query(&pairs);
    }
    match req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("application/json"));
            match resp.bytes().await {
                Ok(bytes) => {
                    let data: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    if !status.is_success() {
                        // preserve the sidecar's own refusal (e.g. 403 label not allowlisted)
                        let mut r = Response::new(axum::body::Body::from(bytes));
                        *r.status_mut() = status;
                        r.headers_mut().insert(header::CONTENT_TYPE, ct);
                        return r;
                    }
                    Json(envelope(
                        st,
                        entry,
                        json!({"kind": entry.output.kind, "data": data}),
                        json!({"duration_ms": started.elapsed().as_millis() as u64}),
                    ))
                    .into_response()
                }
                Err(_) => fail(StatusCode::BAD_GATEWAY, &entry.id, "read-view sidecar unreachable"),
            }
        }
        Err(_) => fail(StatusCode::BAD_GATEWAY, &entry.id, "read-view sidecar unreachable"),
    }
}

// ------------------------------------------------------------------ //
// runner: exec (one-shot subprocess, fixed argv, bounded)
// ------------------------------------------------------------------ //

async fn run_exec(
    st: &SharedState,
    entry: &Entry,
    bound: &Bindings,
    authz_decision: Option<String>,
) -> Response {
    let argv = match build_argv(entry, bound, &st.python_str()) {
        Ok(a) => a,
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, &entry.id, e),
    };

    let started = Instant::now();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&st.repo_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let out = match timeout(entry.timeout(), cmd.output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return fail(StatusCode::INTERNAL_SERVER_ERROR, &entry.id, format!("spawn failed: {e}")),
        Err(_) => {
            return fail(
                StatusCode::GATEWAY_TIMEOUT,
                &entry.id,
                format!("timed out after {}ms", entry.timeout().as_millis()),
            )
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let exit_code = out.status.code();

    let mut output = json!({
        "kind": entry.output.kind,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    });
    // If the command speaks JSON, hand the parsed value to the renderer too.
    if let Ok(parsed) = serde_json::from_str::<Value>(stdout.trim()) {
        output["data"] = parsed;
    }

    // Mint a preview token if something downstream requires this as its preview.
    let mut extra = json!({
        "duration_ms": started.elapsed().as_millis() as u64,
        "attribution": {"argv": argv, "authz_decision_id": authz_decision},
    });
    let is_preview_for = st
        .registry
        .capabilities
        .iter()
        .any(|e| e.requires_preview.as_deref() == Some(entry.id.as_str()));
    if is_preview_for && exit_code == Some(0) {
        let token = new_token();
        st.previews.lock().await.insert(
            token.clone(),
            PreviewToken {
                capability: entry.id.clone(),
                args_json: canonical(bound),
                issued: Instant::now(),
            },
        );
        extra["preview_token"] = Value::String(token);
        extra["preview_expires_in_s"] = json!(PREVIEW_TTL.as_secs());
    }

    Json(envelope(st, entry, output, extra)).into_response()
}

fn new_token() -> String {
    // Not a security boundary (authz_gate is) — just an unguessable-enough,
    // single-use handle tying an execute to the preview the operator saw.
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{ts:x}{:x}", std::process::id())
}

// ------------------------------------------------------------------ //
// runner: service (long-lived child, bounded ring log)
// ------------------------------------------------------------------ //

async fn start_service(st: &SharedState, entry: &Entry, bound: &Bindings) -> Response {
    let cfg = entry.service.as_ref().expect("lint guarantees a service block");
    let mut services = st.services.lock().await;
    let run = services
        .entry(entry.id.clone())
        .or_insert_with(|| ServiceRun::idle(cfg.log_cap));

    if cfg.singleton && run.child.is_some() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "capability": entry.id, "error": "already running", "pid": run.pid})),
        )
            .into_response();
    }

    let argv = match build_argv(entry, bound, &st.python_str()) {
        Ok(a) => a,
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, &entry.id, e),
    };

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&st.repo_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, &entry.id, format!("spawn failed: {e}")),
    };
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    run.child = Some(child);
    run.pid = pid;
    run.log.clear();
    run.exit_code = None;
    run.stopped_by_operator = false;
    let cap_id = entry.id.clone();
    let log_cap = cfg.log_cap;
    let reap_ms = cfg.reap_poll_ms;
    drop(services);

    for (stream, prefix) in [(stdout.map(Ok), ""), (stderr.map(Err), "stderr: ")] {
        let Some(s) = stream else { continue };
        let st2 = st.clone();
        let id2 = cap_id.clone();
        let pfx = prefix.to_string();
        tokio::spawn(async move {
            match s {
                Ok(out) => {
                    let mut lines = BufReader::new(out).lines();
                    while let Ok(Some(l)) = lines.next_line().await {
                        push_log(&st2, &id2, format!("{pfx}{l}"), log_cap).await;
                    }
                }
                Err(err) => {
                    let mut lines = BufReader::new(err).lines();
                    while let Ok(Some(l)) = lines.next_line().await {
                        push_log(&st2, &id2, format!("{pfx}{l}"), log_cap).await;
                    }
                }
            }
        });
    }

    let st3 = st.clone();
    let id3 = cap_id.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(reap_ms)).await;
            let mut services = st3.services.lock().await;
            let Some(run) = services.get_mut(&id3) else { break };
            let done = match run.child.as_mut() {
                Some(c) => match c.try_wait() {
                    Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
                    Ok(None) => None,
                    Err(_) => Some(-1),
                },
                None => break,
            };
            if let Some(code) = done {
                run.exit_code = Some(code);
                run.child = None;
                break;
            }
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(envelope(
            st,
            entry,
            json!({"kind": entry.output.kind, "lines": []}),
            json!({"running": true, "pid": pid, "attribution": {"argv": argv}}),
        )),
    )
        .into_response()
}

async fn push_log(st: &SharedState, cap: &str, line: String, cap_lines: usize) {
    let mut services = st.services.lock().await;
    if let Some(run) = services.get_mut(cap) {
        if run.log.len() >= cap_lines {
            run.log.pop_front();
        }
        run.log.push_back(line);
    }
}

pub async fn service_stop(State(st): State<SharedState>, Path(cap): Path<String>) -> Response {
    let Some(entry) = st.registry.get(&cap) else {
        return fail(StatusCode::NOT_FOUND, &cap, "no such capability");
    };
    let mut services = st.services.lock().await;
    match services.get_mut(&cap).and_then(|r| r.child.take().map(|c| (c, r))) {
        Some((mut child, run)) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            run.stopped_by_operator = true;
            run.exit_code = Some(-15);
            Json(json!({"ok": true, "capability": entry.id, "stopped": true})).into_response()
        }
        None => fail(StatusCode::CONFLICT, &cap, "not running"),
    }
}

pub async fn service_status(State(st): State<SharedState>, Path(cap): Path<String>) -> Response {
    if st.registry.get(&cap).is_none() {
        return fail(StatusCode::NOT_FOUND, &cap, "no such capability");
    }
    let services = st.services.lock().await;
    match services.get(&cap) {
        Some(run) => Json(json!({
            "capability": cap,
            "running": run.child.is_some(),
            "pid": run.pid,
            "exit_code": run.exit_code,
            "stopped_by_operator": run.stopped_by_operator,
            "lines": run.log.iter().collect::<Vec<_>>(),
        }))
        .into_response(),
        None => Json(json!({
            "capability": cap, "running": false, "pid": Value::Null,
            "exit_code": Value::Null, "lines": Vec::<String>::new()
        }))
        .into_response(),
    }
}
