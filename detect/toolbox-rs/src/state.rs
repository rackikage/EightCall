//! Shared process state.
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use tokio::process::Child;
use tokio::sync::Mutex;

use crate::proposals::ProposalStore;
use crate::registry::{Opt, Registry};

pub struct ServiceRun {
    pub child: Option<Child>,
    pub pid: Option<u32>,
    pub log: VecDeque<String>,
    pub exit_code: Option<i32>,
    pub log_cap: usize,
    pub stopped_by_operator: bool,
}

impl ServiceRun {
    pub fn idle(log_cap: usize) -> Self {
        Self {
            child: None,
            pid: None,
            log: VecDeque::new(),
            exit_code: None,
            log_cap,
            stopped_by_operator: false,
        }
    }
}

/// A single-use, short-lived token proving a preview was seen before an
/// execute. It is a foot-gun guard and a UI contract — NOT an authorization
/// boundary. `authz_gate` remains the only thing that authorizes anything.
pub struct PreviewToken {
    pub capability: String,
    pub args_json: String,
    pub issued: Instant,
}

pub struct AppState {
    pub sidecar_base: String,
    pub repo_dir: PathBuf,
    pub python: PathBuf,
    pub http: reqwest::Client,

    pub registry: Registry,
    pub registry_sha256: String,

    pub services: Mutex<HashMap<String, ServiceRun>>,
    pub previews: Mutex<HashMap<String, PreviewToken>>,
    pub options_cache: Mutex<HashMap<String, (Instant, Vec<Opt>)>>,
    pub proposals: ProposalStore,
}

impl AppState {
    pub fn new(
        sidecar_base: String,
        repo_dir: PathBuf,
        python: PathBuf,
        registry: Registry,
        registry_sha256: String,
        proposals: ProposalStore,
    ) -> Self {
        Self {
            sidecar_base,
            repo_dir,
            python,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("reqwest client"),
            registry,
            registry_sha256,
            services: Mutex::new(HashMap::new()),
            previews: Mutex::new(HashMap::new()),
            options_cache: Mutex::new(HashMap::new()),
            proposals,
        }
    }

    pub fn python_str(&self) -> String {
        self.python.to_string_lossy().to_string()
    }
}

pub type SharedState = Arc<AppState>;
