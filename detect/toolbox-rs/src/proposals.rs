//! The operator approval queue — the only path a *proposed* action may take.
//!
//! A proposal has **no authority**. It is a request a caller (typically the
//! agent, via `toolbox_propose.py`) files: a capability id plus its args, and a
//! note. Filing one runs nothing. The operator approves it in the panel with a
//! typed confirmation, and only then does the *same* spine `POST /api/run/:cap`
//! takes run — bind (option-set membership re-resolved server-side), preview,
//! `authz_gate` (fail-closed), runner. The gate remains the only authority;
//! this module only records who asked and who said yes.
//!
//! Storage is an append-only JSONL event log; state is the fold of the events.
//! It is tamper-EVIDENT by append-only convention (not hash-chained like the
//! gate audit) — do not treat it as tamper-proof.
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::Mutex;

/// The queue lives beside the registry, in the detect repo dir.
pub const PROPOSALS_FILE: &str = "toolbox_proposals.jsonl";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Authorized,
    Fired,
    Failed,
    Rejected,
}

impl Status {
    /// Only a pending proposal may be decided. Decided is terminal.
    pub fn is_open(self) -> bool {
        matches!(self, Status::Pending)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Proposal {
    pub id: String,
    pub capability: String,
    pub args: Map<String, Value>,
    pub note: Option<String>,
    pub created_by: String,
    pub created_at: u64,
    pub status: Status,
    pub reason: Option<String>,
    pub decision_id: Option<String>,
    pub decided_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // `seq` is carried in the log for ordering; not read back
struct Event {
    seq: u64,
    ts: u64,
    kind: String,
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision_id: Option<String>,
}

pub struct ProposalStore {
    path: PathBuf,
    events: Mutex<Vec<Event>>,
}

impl ProposalStore {
    /// Load the existing log (missing file is an empty queue, not an error).
    pub fn load(path: PathBuf) -> Self {
        let mut events = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(ev) = serde_json::from_str::<Event>(line) {
                    events.push(ev);
                }
            }
        }
        Self {
            path,
            events: Mutex::new(events),
        }
    }

    /// Fold the append-only log into current proposals, oldest first.
    fn fold(events: &[Event]) -> Vec<Proposal> {
        let mut order: Vec<String> = Vec::new();
        let mut map: HashMap<String, Proposal> = HashMap::new();
        for ev in events {
            if ev.kind == "created" {
                if !map.contains_key(&ev.id) {
                    order.push(ev.id.clone());
                }
                map.insert(
                    ev.id.clone(),
                    Proposal {
                        id: ev.id.clone(),
                        capability: ev.capability.clone().unwrap_or_default(),
                        args: ev.args.clone().unwrap_or_default(),
                        note: ev.note.clone(),
                        created_by: ev.created_by.clone().unwrap_or_else(|| "unknown".into()),
                        created_at: ev.ts,
                        status: Status::Pending,
                        reason: None,
                        decision_id: None,
                        decided_at: None,
                    },
                );
                continue;
            }
            if let Some(p) = map.get_mut(&ev.id) {
                p.decided_at = Some(ev.ts);
                match ev.kind.as_str() {
                    "authorized" => {
                        p.status = Status::Authorized;
                        p.decision_id = ev.decision_id.clone();
                    }
                    "fired" => p.status = Status::Fired,
                    "failed" => {
                        p.status = Status::Failed;
                        p.reason = ev.reason.clone();
                    }
                    "rejected" => {
                        p.status = Status::Rejected;
                        p.reason = ev.reason.clone();
                    }
                    _ => {}
                }
            }
        }
        order.into_iter().filter_map(|id| map.remove(&id)).collect()
    }

    pub async fn list(&self) -> Vec<Proposal> {
        let events = self.events.lock().await;
        Self::fold(&events)
    }

    pub async fn get(&self, id: &str) -> Option<Proposal> {
        self.list().await.into_iter().find(|p| p.id == id)
    }

    async fn append(&self, ev: Event) -> Result<(), String> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("cannot open proposals log: {e}"))?;
        let line = serde_json::to_string(&ev).map_err(|e| e.to_string())?;
        writeln!(f, "{line}").map_err(|e| format!("cannot append proposal: {e}"))?;
        self.events.lock().await.push(ev);
        Ok(())
    }

    /// File a proposal. Validation against the registry happens in the caller
    /// (the HTTP handler / CLI) so this stays a pure log append.
    pub async fn create(
        &self,
        capability: &str,
        args: Map<String, Value>,
        note: Option<String>,
        created_by: &str,
    ) -> Result<Proposal, String> {
        let seq = { self.events.lock().await.len() as u64 + 1 };
        let ts = now();
        let id = format!("p{ts:x}{seq:x}");
        let ev = Event {
            seq,
            ts,
            kind: "created".into(),
            id: id.clone(),
            capability: Some(capability.to_string()),
            args: Some(args.clone()),
            note: note.clone(),
            created_by: Some(created_by.to_string()),
            reason: None,
            decision_id: None,
        };
        self.append(ev).await?;
        Ok(Proposal {
            id,
            capability: capability.to_string(),
            args,
            note,
            created_by: created_by.to_string(),
            created_at: ts,
            status: Status::Pending,
            reason: None,
            decision_id: None,
            decided_at: None,
        })
    }

    pub async fn mark_authorized(&self, id: &str, decision_id: Option<String>) -> Result<(), String> {
        self.decide(id, "authorized", None, decision_id).await
    }

    pub async fn mark_fired(&self, id: &str) -> Result<(), String> {
        self.decide(id, "fired", None, None).await
    }

    pub async fn mark_failed(&self, id: &str, reason: String) -> Result<(), String> {
        self.decide(id, "failed", Some(reason), None).await
    }

    pub async fn mark_rejected(&self, id: &str, reason: String) -> Result<(), String> {
        self.decide(id, "rejected", Some(reason), None).await
    }

    async fn decide(
        &self,
        id: &str,
        kind: &str,
        reason: Option<String>,
        decision_id: Option<String>,
    ) -> Result<(), String> {
        let seq = { self.events.lock().await.len() as u64 + 1 };
        let ev = Event {
            seq,
            ts: now(),
            kind: kind.into(),
            id: id.into(),
            capability: None,
            args: None,
            note: None,
            created_by: None,
            reason,
            decision_id,
        };
        self.append(ev).await
    }
}
