//! detect toolbox — registry-driven front door.
//!
//! One core, three runners, no per-capability code. Everything the panel can
//! do is a row in `toolbox_registry.json`:
//!
//!   read_view → reverse-proxied to the Python view server (`toolbox_http.py`,
//!               run as an internal loopback sidecar). Gate logic, hash-chain
//!               verification and the Sigma evaluator are NOT reimplemented
//!               here — one implementation, in the language it already lives in.
//!   exec      → one-shot subprocess with a fixed argv, bounded by timeout.
//!   service   → long-lived child with a bounded ring log and start/stop/status.
//!
//! Why this stays safe even though argv comes from data:
//!   * `Token`'s deserialize refuses any string that mixes text with a
//!     placeholder, so substring interpolation is unrepresentable.
//!   * The boot lint refuses a placeholder whose arg kind is not `enum` or
//!     `server`, so the only caller-influenced argv elements are members of an
//!     option set the server itself enumerated from an operator-controlled file.
//!   * `Bound::as_single()` exists only for single-valued bindings, so one arg
//!     can never become two argv elements.
//!   * No shell, ever: `Command::new(argv[0]).args(&argv[1..])`.
//!   * The lint runs BEFORE the listener binds. A bad policy file never serves.
//!
//! The registry is a POLICY FILE, not configuration: its literals are argv
//! elements. It ships in git beside authz_policy.yml, and its digest travels in
//! every response envelope.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

mod api;
mod authz;
mod bind;
mod lint;
mod options;
mod proposals;
mod registry;
mod state;

use registry::Registry;
use state::AppState;

#[derive(Parser, Debug)]
#[command(name = "toolbox-rs")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// The Python read-view sidecar. Never exposed directly.
    #[arg(long, default_value = "http://127.0.0.1:9091")]
    sidecar: String,

    /// The detect repo directory. Every spawned argv runs with this as cwd.
    #[arg(long)]
    repo_dir: PathBuf,

    /// Absolute path to the venv's python3.
    #[arg(long)]
    python: PathBuf,

    /// The built frontend (vite build output).
    #[arg(long)]
    static_dir: PathBuf,

    /// The capability registry. Lint-checked before the listener binds.
    #[arg(long)]
    registry: Option<PathBuf>,
}

/// An integrity label for the loaded policy file, surfaced in every envelope
/// so a response can be tied to the exact registry that produced it. This is a
/// change-detection digest, not a security control.
fn digest_hex(bytes: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();

    let registry_path = args
        .registry
        .clone()
        .unwrap_or_else(|| args.repo_dir.join("toolbox_registry.json"));

    let text = std::fs::read_to_string(&registry_path)
        .map_err(|e| anyhow::anyhow!("cannot read registry {}: {e}", registry_path.display()))?;
    let digest = digest_hex(text.as_bytes());

    let mut reg: Registry = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("registry {} is malformed: {e}", registry_path.display()))?;
    reg.index();

    // Lint BEFORE binding. A bad policy file must never serve a single request.
    if let Err(errs) = lint::lint(&reg, &args.repo_dir) {
        eprintln!("registry lint failed ({} problem(s)) — refusing to start:", errs.len());
        for e in &errs {
            eprintln!("  {e}");
        }
        std::process::exit(2);
    }
    tracing::info!("registry ok: {} (digest {})", lint::summarize(&reg), digest);

    // The operator approval queue. Missing file == empty queue.
    let proposals = proposals::ProposalStore::load(args.repo_dir.join(proposals::PROPOSALS_FILE));

    let state = Arc::new(AppState::new(
        args.sidecar.clone(),
        args.repo_dir.clone(),
        args.python.clone(),
        reg,
        digest,
        proposals,
    ));

    let index = args.static_dir.join("index.html");
    let static_service = ServeDir::new(&args.static_dir).not_found_service(ServeFile::new(&index));

    let app = Router::new()
        .route("/api/healthz", get(api::healthz))
        .route("/api/registry", get(api::registry))
        .route("/api/options/:cap/:arg", get(api::options_for))
        // reads are GET-able so refresh/auto-refresh stays a GET; everything
        // that acts is POST-only.
        .route("/api/read/:cap", get(api::read))
        .route("/api/run/:cap", post(api::run))
        // the approval queue: a proposal is filed (POST), then the operator
        // authorizes or rejects it. Authorizing re-runs the same spine as
        // /api/run, through the gate. A proposal alone never acts.
        .route(
            "/api/proposals",
            get(api::proposals_list).post(api::proposal_create),
        )
        .route("/api/proposals/:id/authorize", post(api::proposal_authorize))
        .route("/api/proposals/:id/reject", post(api::proposal_reject))
        .route("/api/service/:cap/stop", post(api::service_stop))
        .route("/api/service/:cap/status", get(api::service_status))
        .fallback_service(static_service)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    if args.host != "127.0.0.1" && args.host != "localhost" && args.host != "::1" {
        tracing::warn!(
            "bound to {} — reachable off-host. This server exposes real action \
             endpoints and discloses host detail; put TLS + auth in front before \
             exposing it beyond loopback.",
            args.host
        );
    }
    tracing::info!("toolbox-rs listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
