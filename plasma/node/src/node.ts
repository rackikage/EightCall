/**
 * fleet node.ts — high-availability handoff, built to the safety scope.
 *
 * Roles (one file, selected by CLI role):
 *   A = Observer          detects + dedupes triggers. Owns NO execution authority.
 *   B = Coordinator       durable state, candidate choice, leases, epoch advance,
 *                         resumable rotation transactions.
 *   C = Ephemeral worker  restores a versioned checkpoint, holds a short lease,
 *                         may act only while its epoch is current.
 *   D = Authority/Store   compare-and-swap ownership + monotonic checkpoints,
 *                         rejects stale epochs, dedupe/idempotency records.
 *   R = ProtectedResource downstream simulator that ENFORCES fencing: it rejects
 *                         any epoch lower than the highest it has accepted.
 *
 * Invariants enforced here:
 *   I1  Only the worker holding the current unexpired epoch may cause side effects.
 *   I2  Downstream (R) rejects stale epochs; safety does not depend on retiring C0.
 *   I3  A newly started worker may be duplicated/delayed/retried; the durable
 *       state + idempotency keys keep effects correct anyway.
 *   I4  One logical trigger => one EXEC_ID (durable admission), regardless of how
 *       many observers or restarts see it.
 *   I5  Checkpoint versions are monotonic; a stale checkpoint is refused.
 *
 * Scope guardrails (venv69): typed capabilities only, NO shell/exec/subprocess.
 * Attribution over camouflage: launcher/unit, node_id, capability, epoch, outcome.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { hostname } from "node:os";
import {
  mkdirSync, readFileSync, writeFileSync, renameSync, openSync, fsyncSync,
  closeSync, existsSync, appendFileSync, unlinkSync, statSync,
} from "node:fs";
import { join } from "node:path";

/* ------------------------------------------------------------------ types */

type Stage = "A" | "B" | "C" | "D" | "R";
type ShipId = string;
type ChainId = string;
type ExecId = string;
type Epoch = number;

type Capability =
  | "PING" | "INFO" | "STATUS" | "DISCONNECT"
  | "SYNC_CONFIG" | "FETCH_LOGS" | "CAPTURE_TELEMETRY"
  | "RESTART_SERVICE" | "UPDATE_RULESET";

const CAPABILITIES: readonly Capability[] = [
  "PING", "INFO", "STATUS", "DISCONNECT",
  "SYNC_CONFIG", "FETCH_LOGS", "CAPTURE_TELEMETRY",
  "RESTART_SERVICE", "UPDATE_RULESET",
];
const MUTATING: ReadonlySet<Capability> = new Set<Capability>(
  ["SYNC_CONFIG", "RESTART_SERVICE", "UPDATE_RULESET"],
);

interface Trigger { source_id: string; source_version: string; observed_at: string; reason: string }

interface ExecRecord {
  exec_id: ExecId;
  chain_id: ChainId;
  trigger_key: string;
  created_at: string;
  status: "OPEN" | "ACTIVE" | "CLOSED";
  attempts: number;
}

interface Ownership {
  exec_id: ExecId;
  chain_id: ChainId;
  owner_ship: ShipId;
  epoch: Epoch;
  checkpoint_version: number;
  lease_id: string;
  lease_expiry: string;
  status: "ACTIVE" | "RETIRED" | "STALE";
}

interface CheckpointPayload {
  cursor: string;
  completed_action_ids: string[];
  retry_budget_remaining: number;
}
interface Checkpoint {
  schema_version: number;
  chain_id: ChainId;
  exec_id: ExecId;
  checkpoint_version: number;
  owner_epoch: Epoch;
  created_at: string;
  payload_hash: string;
  payload: CheckpointPayload;
}

interface ShipCapability {
  ship_id: ShipId;
  os: "linux" | "android" | "ios" | "macos";
  attested: boolean;
  worker_version: string;
  minimum_version: string;
  battery_pct: number;
  charging: boolean;
  heartbeat_age_s: number;
  capabilities: Capability[];
  link: { class: "wifi" | "bluetooth" | "ethernet" | "cellular"; bandwidth_mbps: number; latency_ms: number; trusted: boolean };
  quarantine: boolean;
  recent_success_rate: number;
  thermal_pressure: number;
  locality: number;
}

interface Job { capability: Capability; min_bandwidth_mbps: number; max_latency_ms: number; mobile_eligible: boolean }

interface TxnStep { step: string; status: "PENDING" | "DONE"; at?: string; detail?: string }
interface Txn {
  chain_id: ChainId;
  exec_id: ExecId;
  hop: number;
  from_ship: ShipId;
  to_ship: ShipId;
  epoch: Epoch;
  checkpoint_version: number;
  reason: string;
  steps: TxnStep[];
  status: "OPEN" | "DONE" | "ABORTED";
  started_at: string;
  updated_at: string;
}

interface Action { logical_action_id: string; kind: string; params: Record<string, unknown> }

interface EffectRecord { idem_key: string; applied_at: string; epoch: Epoch; owner: ShipId; result: string }

interface LogRecord {
  ts: string;
  event_id: string;
  stage: Stage;
  event: string;
  chain?: ChainId;
  exec?: ExecId;
  attempt?: number;
  hop?: number;
  epoch?: Epoch;
  from_ship?: ShipId;
  to_ship?: ShipId;
  checkpoint_version?: number;
  lease_id?: string;
  reason?: string;
  result?: string;
  duration_ms?: number;
  [k: string]: unknown;
}

/** Thrown to simulate a coordinator crash between rotation steps. */
class Interrupted extends Error {
  constructor() { super("simulated_interrupt"); this.name = "Interrupted"; }
}

/* -------------------------------------------------------------------- util */

const nowIso = (): string => new Date().toISOString();
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

function sortValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) out[k] = sortValue(o[k]);
    return out;
  }
  return v;
}
const canonical = (o: unknown): string => JSON.stringify(sortValue(o));

const SECRET_RE = /(token|secret|password|passwd|bearer|api[_-]?key|private[_-]?key)/i;
function redact(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(redact);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o)) out[k] = SECRET_RE.test(k) ? "[redacted]" : redact(o[k]);
    return out;
  }
  return v;
}

/* ------------------------------------------------------------- D: store */

interface Versioned<T> { v: number; data: T }

class Store {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }
  private path(name: string): string { return join(this.dir, name.replace(/[/:]/g, "_") + ".json"); }

  read<T>(name: string): Versioned<T> | null {
    const p = this.path(name);
    if (!existsSync(p)) return null;
    return JSON.parse(readFileSync(p, "utf8")) as Versioned<T>;
  }

  private writeAtomic(p: string, text: string): void {
    const tmp = p + "." + randomUUID() + ".tmp";
    const fd = openSync(tmp, "w");
    try { writeFileSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, p);
    const dfd = openSync(this.dir, "r");
    try { fsyncSync(dfd); } finally { closeSync(dfd); }
  }

  /** Compare-and-swap: write only if the caller saw the current version. */
  writeCAS<T>(name: string, expected: number, data: T): { ok: boolean; v: number } {
    return this.lock(name, () => {
      const cur = this.read<T>(name);
      const v = cur ? cur.v : 0;
      if (v !== expected) return { ok: false, v };
      const nv = v + 1;
      this.writeAtomic(this.path(name), JSON.stringify({ v: nv, data } satisfies Versioned<T>));
      return { ok: true, v: nv };
    });
  }

  /** Non-CAS upsert used for monotonic ledgers (callers enforce monotonicity). */
  put<T>(name: string, data: T): number {
    return this.lock(name, () => {
      const cur = this.read<T>(name);
      const nv = (cur ? cur.v : 0) + 1;
      this.writeAtomic(this.path(name), JSON.stringify({ v: nv, data } satisfies Versioned<T>));
      return nv;
    });
  }

  appendEvent(name: string, rec: unknown): void {
    appendFileSync(join(this.dir, name + ".jsonl"), JSON.stringify(rec) + "\n");
  }

  /** Public re-entrant critical section (used by Authority). */
  withLock<T>(name: string, fn: () => T): T { return this.lock(name, fn); }

  private held: Set<string> = new Set<string>();
  private lock<T>(name: string, fn: () => T): T {
    if (this.held.has(name)) return fn(); // re-entrant within this process
    const lp = join(this.dir, name.replace(/[/:]/g, "_") + ".lock");
    const deadline = Date.now() + 3000;
    for (;;) {
      try {
        const fd = openSync(lp, "wx");
        this.held.add(name);
        try {
          return fn();
        } finally {
          this.held.delete(name);
          closeSync(fd);
          try { unlinkSync(lp); } catch { /* ignore */ }
        }
      } catch (e) {
        // break a lock left behind by a crashed process
        try {
          if (Date.now() - statSync(lp).mtimeMs > 5000) { unlinkSync(lp); continue; }
        } catch { /* ignore */ }
        if (Date.now() > deadline) throw e;
      }
    }
  }
}

class Authority {
  readonly store: Store;
  constructor(store: Store) { this.store = store; }

  /* monotonic epoch ledger */
  highestEpoch(chain: ChainId, exec: ExecId): Epoch {
    const r = this.store.read<{ epoch: Epoch }>(`epoch_${chain}_${exec}`);
    return r ? r.data.epoch : 0;
  }
  advanceEpoch(chain: ChainId, exec: ExecId, candidate: Epoch): { ok: boolean; epoch: Epoch } {
    return this.store.withLock(`epoch_${chain}_${exec}`, () => {
      const cur = this.highestEpoch(chain, exec);
      if (candidate <= cur) return { ok: false, epoch: cur };
      this.store.put(`epoch_${chain}_${exec}`, { epoch: candidate });
      return { ok: true, epoch: candidate };
    });
  }

  /* ownership record (CAS) */
  ownership(chain: ChainId, exec: ExecId): Ownership | null {
    const r = this.store.read<Ownership>(`own_${chain}_${exec}`);
    return r ? r.data : null;
  }
  setOwnership(o: Ownership): { ok: boolean; reason?: string } {
    return this.store.withLock(`own_${o.chain_id}_${o.exec_id}`, () => {
      const cur = this.ownership(o.chain_id, o.exec_id);
      if (cur && o.epoch < cur.epoch) return { ok: false, reason: "stale_epoch" };
      if (cur && o.epoch === cur.epoch && o.owner_ship !== cur.owner_ship) {
        return { ok: false, reason: "epoch_owner_conflict" };
      }
      this.store.put(`own_${o.chain_id}_${o.exec_id}`, o);
      return { ok: true };
    });
  }

  /* monotonic checkpoints */
  checkpoint(chain: ChainId, exec: ExecId): Checkpoint | null {
    const r = this.store.read<Checkpoint>(`ckpt_${chain}_${exec}`);
    return r ? r.data : null;
  }
  putCheckpoint(cp: Checkpoint): { ok: boolean; reason?: string } {
    return this.store.withLock(`ckpt_${cp.chain_id}_${cp.exec_id}`, () => {
      const cur = this.checkpoint(cp.chain_id, cp.exec_id);
      if (cur && cp.checkpoint_version <= cur.checkpoint_version) {
        return { ok: false, reason: "stale_checkpoint" };
      }
      if (sha256(canonical(cp.payload)) !== cp.payload_hash) {
        return { ok: false, reason: "payload_hash_mismatch" };
      }
      this.store.put(`ckpt_${cp.chain_id}_${cp.exec_id}`, cp);
      return { ok: true };
    });
  }

  /* durable execution admission: one trigger -> one EXEC_ID */
  admit(trigger: Trigger, chain: ChainId): { rec: ExecRecord; created: boolean } {
    const trigger_key = `${trigger.source_id}:${trigger.source_version}`;
    const name = `admit_${trigger_key}`;
    return this.store.withLock(name, () => {
      const existing = this.store.read<ExecRecord>(name);
      if (existing) return { rec: existing.data, created: false };
      const rec: ExecRecord = {
        exec_id: "E" + sha256(trigger_key).slice(0, 8),
        chain_id: chain, trigger_key, created_at: nowIso(), status: "OPEN", attempts: 0,
      };
      this.store.put(name, rec);
      return { rec, created: true };
    });
  }

  /* idempotency ledger */
  idemKey(chain: ChainId, exec: ExecId, logical_action_id: string): string {
    return `${chain}:${exec}:${logical_action_id}`;
  }
  idemSeen(key: string): EffectRecord | null {
    const r = this.store.read<EffectRecord>(`idem_${key}`);
    return r ? r.data : null;
  }
  idemMark(key: string, rec: EffectRecord): { ok: boolean; existing: EffectRecord | null } {
    return this.store.withLock(`idem_${key}`, () => {
      const cur = this.idemSeen(key);
      if (cur) return { ok: false, existing: cur };
      this.store.put(`idem_${key}`, rec);
      return { ok: true, existing: null };
    });
  }
}

/* ----------------------------------------------- R: protected resource */

class ProtectedResource {
  private highest: Map<string, Epoch> = new Map();
  private ownerAt: Map<string, ShipId> = new Map();
  readonly effects: EffectRecord[] = [];
  private readonly authority: Authority;

  constructor(authority: Authority) { this.authority = authority; }

  private key(chain: ChainId, exec: ExecId): string { return `${chain}:${exec}`; }

  /** Fencing gate. Ordering alone cannot stop a FORGED higher epoch, so the
   *  resource confirms the epoch against the durable authority (D). */
  probe(chain: ChainId, exec: ExecId, epoch: Epoch, owner: ShipId): { ok: boolean; reason?: string } {
    const own = this.authority.ownership(chain, exec);
    if (!own || own.status !== "ACTIVE") return { ok: false, reason: "no_active_ownership" };
    if (epoch < own.epoch) return { ok: false, reason: "stale_epoch" };
    if (epoch !== own.epoch || owner !== own.owner_ship) return { ok: false, reason: "not_authority" };
    return { ok: true };
  }

  /** The fencing point: reject stale epochs here, not by trusting the coordinator. */
  apply(chain: ChainId, exec: ExecId, epoch: Epoch, owner: ShipId, idem_key: string, action: Action): { ok: boolean; result: string; reason?: string } {
    const p = this.probe(chain, exec, epoch, owner);
    if (!p.ok) return { ok: false, result: "rejected", reason: p.reason };
    const k = this.key(chain, exec);
    const dup = this.effects.find((e) => e.idem_key === idem_key);
    if (dup) return { ok: true, result: "deduplicated" };
    this.effects.push({ idem_key, applied_at: nowIso(), epoch, owner, result: action.kind });
    this.highest.set(k, Math.max(this.highest.get(k) ?? 0, epoch));
    this.ownerAt.set(k, owner);
    return { ok: true, result: "applied" };
  }
}

/* ------------------------------------------------------------- logger */

function makeLogger(stage: Stage, store: Store) {
  return (fields: Omit<LogRecord, "ts" | "event_id" | "stage"> & { event: string }): void => {
    const rec = { ts: nowIso(), event_id: randomUUID(), stage, ...(redact(fields) as Record<string, unknown>) } as LogRecord;
    process.stdout.write(JSON.stringify(rec) + "\n");
    store.appendEvent("events", rec);
  };
}
type Logger = ReturnType<typeof makeLogger>;

/* -------------------------------------------------------- C: worker */

class Worker {
  readonly chain: ChainId;
  readonly exec: ExecId;
  readonly ship: ShipId;
  readonly authority: Authority;
  readonly resource: ProtectedResource;
  readonly log: Logger;
  epoch: Epoch = 0;
  leaseId = "";
  leaseExpiryMs = 0;
  checkpointVersion = -1;
  cursor = "";
  completed: Set<string> = new Set<string>();
  retryBudget = 0;

  constructor(chain: ChainId, exec: ExecId, ship: ShipId, authority: Authority, resource: ProtectedResource, log: Logger) {
    this.chain = chain; this.exec = exec; this.ship = ship;
    this.authority = authority; this.resource = resource; this.log = log;
  }

  /** Restores state; refuses a checkpoint older than the expected version. */
  loadCheckpoint(cp: Checkpoint, expectedVersion: number): { ok: boolean; reason?: string } {
    if (cp.schema_version !== 1) return { ok: false, reason: "schema_mismatch" };
    if (cp.chain_id !== this.chain || cp.exec_id !== this.exec) return { ok: false, reason: "identity_mismatch" };
    if (cp.checkpoint_version < expectedVersion) return { ok: false, reason: "stale_checkpoint" };
    if (sha256(canonical(cp.payload)) !== cp.payload_hash) return { ok: false, reason: "payload_hash_mismatch" };
    this.checkpointVersion = cp.checkpoint_version;
    this.cursor = cp.payload.cursor;
    this.completed = new Set(cp.payload.completed_action_ids);
    this.retryBudget = cp.payload.retry_budget_remaining;
    return { ok: true };
  }

  setAuthority(epoch: Epoch, leaseId: string, leaseExpiryMs: number): void {
    this.epoch = epoch; this.leaseId = leaseId; this.leaseExpiryMs = leaseExpiryMs;
  }

  leaseValid(now = Date.now()): boolean { return this.leaseExpiryMs > now && this.epoch > 0; }

  /** Ownership readiness: epoch matches the durable ACTIVE ownership + lease valid. */
  ownerReady(): boolean {
    const own = this.authority.ownership(this.chain, this.exec);
    if (!own || own.status !== "ACTIVE") return false;
    return own.owner_ship === this.ship && own.epoch === this.epoch && this.leaseValid();
  }

  workReady(): boolean { return this.checkpointVersion >= 0; }

  e2eReady(): boolean {
    const p = this.resource.probe(this.chain, this.exec, this.epoch, this.ship);
    return p.ok;
  }

  facts(): Record<string, unknown> {
    return {
      status: this.ownerReady() && this.workReady() ? "ready" : "not_ready",
      chain_id: this.chain,
      exec_id: this.exec,
      ship: this.ship,
      checkpoint_version: this.checkpointVersion,
      owner_epoch: this.epoch,
      lease_id: this.leaseId,
      lease_valid: this.leaseValid(),
      lease_valid_until: this.leaseExpiryMs ? new Date(this.leaseExpiryMs).toISOString() : null,
      dependencies: {
        state_store: "ok",
        work_queue: "ok",
        target_authority: this.e2eReady() ? "accepted" : "rejected",
      },
    };
  }

  /** The only path to side effects. Fenced by epoch at the resource. */
  perform(action: Action): { ok: boolean; result: string; reason?: string } {
    if (!this.leaseValid()) {
      this.log({ event: "action_refused", chain: this.chain, exec: this.exec, epoch: this.epoch, reason: "lease_expired", result: "refused" });
      return { ok: false, result: "refused", reason: "lease_expired" };
    }
    const idem = this.authority.idemKey(this.chain, this.exec, action.logical_action_id);
    if (this.authority.idemSeen(idem) || this.completed.has(action.logical_action_id)) {
      return { ok: true, result: "deduplicated" };
    }
    const r = this.resource.apply(this.chain, this.exec, this.epoch, this.ship, idem, action);
    if (r.ok && r.result === "applied") {
      this.completed.add(action.logical_action_id);
      this.authority.idemMark(idem, { idem_key: idem, applied_at: nowIso(), epoch: this.epoch, owner: this.ship, result: action.kind });
    }
    this.log({
      event: "action", chain: this.chain, exec: this.exec, epoch: this.epoch,
      reason: action.kind, result: r.ok ? r.result : (r.reason ?? "rejected"),
    });
    return r;
  }
}

/* ---------------------------------------------------- B: coordinator */

const POLICY = {
  min_battery_pct: 30,
  max_heartbeat_age_s: 20,
  max_thermal_pressure: 0.8,
  lease_ms: 30_000,
  min_success_rate: 0.5,
};

class Coordinator {
  readonly authority: Authority;
  readonly store: Store;
  readonly resource: ProtectedResource;
  readonly log: Logger;

  constructor(authority: Authority, store: Store, resource: ProtectedResource, log: Logger) {
    this.authority = authority; this.store = store; this.resource = resource; this.log = log;
  }

  /** Admission: durable dedupe, so N observers/restarts produce one EXEC_ID. */
  admit(trigger: Trigger, chain: ChainId): ExecRecord {
    const { rec, created } = this.authority.admit(trigger, chain);
    this.log({ event: created ? "admission_created" : "admission_deduped", chain, exec: rec.exec_id, reason: trigger.reason, result: created ? "created" : "existing" });
    return rec;
  }

  eligibleShip(s: ShipCapability, job: Job): { ok: boolean; reason?: string } {
    if (!s.attested) return { ok: false, reason: "not_attested" };
    if (s.worker_version < s.minimum_version) return { ok: false, reason: "version_too_old" };
    if (!(s.battery_pct >= POLICY.min_battery_pct || s.charging)) return { ok: false, reason: "power" };
    if (s.heartbeat_age_s > POLICY.max_heartbeat_age_s) return { ok: false, reason: "heartbeat_stale" };
    if (!s.capabilities.includes(job.capability)) return { ok: false, reason: "capability_missing" };
    if (!(s.link.bandwidth_mbps >= job.min_bandwidth_mbps && s.link.latency_ms <= job.max_latency_ms)) return { ok: false, reason: "link" };
    if (!s.link.trusted) return { ok: false, reason: "link_untrusted" };
    if (s.quarantine) return { ok: false, reason: "quarantined" };
    if (s.thermal_pressure > POLICY.max_thermal_pressure) return { ok: false, reason: "thermal" };
    if (s.os !== "linux" && !job.mobile_eligible) return { ok: false, reason: "mobile_not_eligible" };
    return { ok: true };
  }

  score(s: ShipCapability): number {
    const power = s.charging ? 1 : s.battery_pct / 100;
    const net = Math.min(1, s.link.bandwidth_mbps / 100) - Math.min(1, s.link.latency_ms / 200);
    return 2 * s.recent_success_rate + 1.5 * power + net + 0.5 * s.locality - s.thermal_pressure;
  }

  selectShip(candidates: ShipCapability[], job: Job, exclude: ShipId[] = []): ShipId {
    const eligible = candidates.filter((c) => !exclude.includes(c.ship_id) && this.eligibleShip(c, job).ok);
    if (eligible.length === 0) throw new Error("no eligible ship");
    eligible.sort((a, b) => this.score(b) - this.score(a));
    return eligible[0].ship_id;
  }

  private pendName(chain: ChainId, exec: ExecId): string { return `pend_${chain}_${exec}`; }
  private txnName(chain: ChainId, exec: ExecId, hop: number): string { return `txn_${chain}_${exec}_${hop}`; }
  private saveTxn(t: Txn): void { this.store.put(this.txnName(t.chain_id, t.exec_id, t.hop), { ...t, updated_at: nowIso() }); }
  private mark(t: Txn, step: string, detail?: string): void {
    const s = t.steps.find((x) => x.step === step);
    if (s) { s.status = "DONE"; s.at = nowIso(); if (detail) s.detail = detail; }
    t.updated_at = nowIso();
    this.saveTxn(t);
  }

  /** Resumable rotation. Safety comes from epoch+fencing, not from killing C0. */
  rotate(chain: ChainId, exec: ExecId, fromShip: ShipId, candidates: ShipCapability[], job: Job, reason: string, stopAfter?: string): { txn: Txn; worker: Worker } {
    const started = Date.now();
    const pend = this.store.read<{ name: string; hop: number }>(this.pendName(chain, exec));
    let t: Txn;
    if (pend && pend.data.name) {
      const stored = this.store.read<Txn>(pend.data.name);
      if (!stored) throw new Error("pending handoff record missing");
      t = stored.data; // resume the interrupted handoff on its existing epoch
    } else {
      const hop = this.authority.highestEpoch(chain, exec) + 1;
      t = {
        chain_id: chain, exec_id: exec, hop, from_ship: fromShip, to_ship: "", epoch: 0,
        checkpoint_version: 0, reason, steps: [
          { step: "intent", status: "PENDING" },
          { step: "allocate_epoch", status: "PENDING" },
          { step: "persist_checkpoint", status: "PENDING" },
          { step: "start_next", status: "PENDING" },
          { step: "verify_next", status: "PENDING" },
          { step: "mark_authoritative", status: "PENDING" },
          { step: "retire_old", status: "PENDING" },
        ], status: "OPEN", started_at: nowIso(), updated_at: nowIso(),
      };
      this.store.put(this.pendName(chain, exec), { name: this.txnName(chain, exec, hop), hop });
    }
    t.reason = reason;
    this.saveTxn(t);

    const done = (s: string): boolean => t.steps.find((x) => x.step === s)?.status === "DONE";
    const marked = (step: string, detail?: string): void => {
      this.mark(t, step, detail);
      if (stopAfter && stopAfter === step) throw new Interrupted();
    };
    if (!done("intent")) { this.log({ event: "handoff_intent", chain, exec, from_ship: fromShip, reason, result: "ok" }); marked("intent"); }

    // 2. allocate a new, strictly greater epoch
    if (!done("allocate_epoch")) {
      const next = this.authority.highestEpoch(chain, exec) + 1;
      const r = this.authority.advanceEpoch(chain, exec, next);
      if (!r.ok) throw new Error("epoch advance rejected: " + r.epoch);
      t.epoch = r.epoch;
      this.log({ event: "epoch_allocated", chain, exec, epoch: t.epoch, result: "ok" });
      marked("allocate_epoch");
    }

    // 3. persist a NEWER checkpoint (version is monotonic at the authority)
    if (!done("persist_checkpoint")) {
      const prev = this.authority.checkpoint(chain, exec);
      const version = (prev ? prev.checkpoint_version : 0) + 1;
      const payload: CheckpointPayload = prev
        ? { ...prev.payload }
        : { cursor: "start", completed_action_ids: [], retry_budget_remaining: 3 };
      const cp: Checkpoint = {
        schema_version: 1, chain_id: chain, exec_id: exec, checkpoint_version: version,
        owner_epoch: t.epoch, created_at: nowIso(), payload_hash: sha256(canonical(payload)), payload,
      };
      const r = this.authority.putCheckpoint(cp);
      if (!r.ok) throw new Error("checkpoint rejected: " + r.reason);
      t.checkpoint_version = version;
      this.log({ event: "checkpoint_persisted", chain, exec, epoch: t.epoch, checkpoint_version: version, result: "ok" });
      marked("persist_checkpoint");
    }

    // 4. choose + start the next worker
    if (!done("start_next")) {
      t.to_ship = this.selectShip(candidates, job, [fromShip]);
      marked("start_next", t.to_ship);
      this.log({ event: "next_selected", chain, exec, from_ship: fromShip, to_ship: t.to_ship, epoch: t.epoch, result: "ok" });
    }

    const worker = new Worker(chain, exec, t.to_ship, this.authority, this.resource, this.log);

    // 5. verify the next worker can actually own work (facts, not a bare 200)
    if (!done("verify_next")) {
      const cp = this.authority.checkpoint(chain, exec);
      if (!cp) throw new Error("no checkpoint to load");
      const lc = worker.loadCheckpoint(cp, cp.checkpoint_version);
      if (!lc.ok) throw new Error("load checkpoint failed: " + lc.reason);
      worker.setAuthority(t.epoch, "lease-" + randomUUID().slice(0, 8), Date.now() + POLICY.lease_ms);
      const epochOk = this.authority.highestEpoch(chain, exec) === t.epoch;
      const ok = worker.checkpointVersion === t.checkpoint_version && worker.leaseValid() && epochOk;
      if (!ok) throw new Error("next worker failed verification (checkpoint/lease/epoch)");
      this.log({ event: "next_verified", chain, exec, to_ship: t.to_ship, epoch: t.epoch, checkpoint_version: t.checkpoint_version, result: "ok" });
      marked("verify_next");
    }

    // 6. make it authoritative (durable)
    if (!done("mark_authoritative")) {
      const own: Ownership = {
        exec_id: exec, chain_id: chain, owner_ship: t.to_ship, epoch: t.epoch,
        checkpoint_version: t.checkpoint_version, lease_id: worker.leaseId,
        lease_expiry: new Date(worker.leaseExpiryMs).toISOString(), status: "ACTIVE",
      };
      const r = this.authority.setOwnership(own);
      if (!r.ok) throw new Error("ownership rejected: " + r.reason);
      this.log({ event: "handoff_commit", chain, exec, from_ship: fromShip, to_ship: t.to_ship, epoch: t.epoch, checkpoint_version: t.checkpoint_version, result: "ok" });
      marked("mark_authoritative");
    }

    // 7. retire old C0 — CLEANUP ONLY. Old C0 is already fenced by epoch.
    if (!done("retire_old")) {
      const own = this.authority.ownership(chain, exec);
      if (own && own.owner_ship === fromShip) {
        // still the owner: retire
        this.authority.setOwnership({ ...own, status: "RETIRED" });
        this.log({ event: "retire_old", chain, exec, from_ship: fromShip, result: "retired" });
      } else {
        this.log({ event: "retire_old", chain, exec, from_ship: fromShip, result: "unreachable_or_already_fenced" });
      }
      marked("retire_old");
    }

    t.status = "DONE"; this.saveTxn(t);
    this.store.put(this.pendName(chain, exec), { name: "", hop: 0 });
    this.log({ event: "handoff_done", chain, exec, to_ship: t.to_ship, epoch: t.epoch, duration_ms: Date.now() - started, result: "ok" });
    return { txn: t, worker };
  }
}

/* ------------------------------------------------------------------ A: observer */

class Observer {
  readonly log: Logger;
  constructor(log: Logger) { this.log = log; }
  observe(source_id: string, source_version: string, reason: string): Trigger {
    this.log({ event: "trigger_observed", reason, result: "ok" });
    return { source_id, source_version, observed_at: nowIso(), reason };
  }
}

/* ------------------------------------------------------------------ http */

function readBody(req: IncomingMessage, max = 64 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0; const parts: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) { reject(new Error("body too large")); req.destroy(); return; }
      parts.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
    req.on("error", reject);
  });
}
function send(res: ServerResponse, code: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(json);
}

interface HttpDeps { ship: ShipId; worker: Worker | null; authority: Authority; log: Logger }

function createHttpServer(deps: HttpDeps) {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://fleet.local");
    const path = url.pathname;
    const w = deps.worker;

    if (path === "/node/healthz") return send(res, 200, { ok: true });
    if (path === "/node/readyz") return send(res, w && w.workReady() ? 200 : 503, { ready: !!(w && w.workReady()) });
    if (path === "/node/live") return send(res, 200, { live: true });
    if (path === "/node/ready") return send(res, w && w.workReady() ? 200 : 503, { ready: !!(w && w.workReady()) });
    if (path === "/node/owner-ready") return send(res, w && w.ownerReady() ? 200 : 409, { owner_ready: !!(w && w.ownerReady()) });
    if (path === "/node/work-ready") return send(res, w && w.workReady() ? 200 : 409, { work_ready: !!(w && w.workReady()) });
    if (path === "/node/e2e") return send(res, w && w.e2eReady() ? 200 : 409, { e2e: !!(w && w.e2eReady()) });
    if (path === "/node/facts") return send(res, 200, { ship: deps.ship, facts: w ? w.facts() : null });

    if (path === "/node/work" && req.method === "POST") {
      const chain = String(req.headers["x-chain-id"] ?? "");
      const exec = String(req.headers["x-exec-id"] ?? "");
      const epoch = Number(req.headers["x-owner-epoch"] ?? "0");
      if (!chain || !exec || !epoch) return send(res, 400, { error: "missing authority headers" });
      if (!w) return send(res, 409, { error: "no worker bound" });
      if (chain !== w.chain || exec !== w.exec || epoch !== w.epoch) {
        deps.log({ event: "work_refused", chain, exec, epoch, reason: "epoch_mismatch", result: "refused" });
        return send(res, 403, { error: "stale or foreign authority" });
      }
      let body: { logical_action_id?: string; kind?: string; capability?: string; params?: Record<string, unknown> } = {};
      try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return send(res, 400, { error: "bad json" }); }
      const action: Action = {
        logical_action_id: String(body.logical_action_id ?? randomUUID()),
        kind: String(body.kind ?? "noop"),
        params: body.params ?? {},
      };
      const r = w.perform(action);
      return send(res, r.ok ? 200 : 403, r);
    }

    return send(res, 404, { error: "not found" });
  });
}

/* ------------------------------------------------------------- ships/demo */

function ship(over: Partial<ShipCapability> & { ship_id: ShipId }): ShipCapability {
  return {
    os: "linux", attested: true, worker_version: "1.4.0", minimum_version: "1.2.0",
    battery_pct: 88, charging: false, heartbeat_age_s: 3,
    capabilities: [...CAPABILITIES], link: { class: "wifi", bandwidth_mbps: 120, latency_ms: 12, trusted: true },
    quarantine: false, recent_success_rate: 0.95, thermal_pressure: 0.2, locality: 0.6,
    ...over,
  };
}

const CHAIN: ChainId = "ACB-7F91";
const JOB: Job = { capability: "FETCH_LOGS", min_bandwidth_mbps: 5, max_latency_ms: 200, mobile_eligible: true };

function assert(cond: boolean, label: string, results: string[]): void {
  results.push((cond ? "PASS " : "FAIL ") + label);
  if (!cond) process.exitCode = 1;
}

function demo(): void {
  const dir = process.env.STATE_DIR ?? join(process.cwd(), "demo_state");
  const store = new Store(dir);
  const authority = new Authority(store);
  const resource = new ProtectedResource(authority);
  const log = makeLogger("B", store);
  const coord = new Coordinator(authority, store, resource, log);
  const obs = new Observer(makeLogger("A", store));
  const results: string[] = [];

  const ships: ShipCapability[] = [
    ship({ ship_id: "nothing-b", os: "android", battery_pct: 90 }),
    ship({ ship_id: "iphone-a", os: "ios", battery_pct: 45, link: { class: "wifi", bandwidth_mbps: 80, latency_ms: 30, trusted: true } }),
    ship({ ship_id: "server-c", os: "linux", battery_pct: 100, charging: true, locality: 0.9 }),
  ];

  // I4: duplicate triggers -> one EXEC_ID
  const t1 = obs.observe("sensor-7", "v42", "manual");
  const t2 = obs.observe("sensor-7", "v42", "retry");
  const e1 = coord.admit(t1, CHAIN);
  const e2 = coord.admit(t2, CHAIN);
  assert(e1.exec_id === e2.exec_id, "I4 duplicate trigger yields one EXEC_ID (" + e1.exec_id + ")", results);

  const exec = e1.exec_id;

  // bearer the first worker (C0) is started by B with epoch 1
  const first = coord.rotate(CHAIN, exec, "", ships, JOB, "initial");
  const c0 = first.worker;
  assert(c0.epoch === 1 && c0.ownerReady(), "C0 holds epoch 1 and is owner-ready", results);

  // C0 does a real logical action
  const a1 = c0.perform({ logical_action_id: "a-001", kind: "fetch", params: {} });
  assert(a1.ok && a1.result === "applied", "C0 action applied under epoch 1", results);

  // handoff to C1
  const second = coord.rotate(CHAIN, exec, c0.ship, ships, JOB, "wifi_degraded");
  const c1 = second.worker;
  assert(c1.epoch === 2, "C1 received a strictly greater epoch (" + c1.epoch + ")", results);
  assert(!c0.ownerReady(), "C0 no longer owner-ready after epoch advance", results);

  // I1/I2: old C0 wakes up and tries to act -> must be fenced
  const stale = c0.perform({ logical_action_id: "a-002", kind: "charge_account", params: {} });
  assert(!stale.ok && stale.reason === "stale_epoch", "I1/I2 stale C0 action rejected at resource (fencing)", results);

  // C1 can act
  const a2 = c1.perform({ logical_action_id: "a-002", kind: "charge_account", params: {} });
  assert(a2.ok && a2.result === "applied", "C1 action applied under epoch 2", results);

  // I3: idempotent replay -> no second effect
  const before = resource.effects.length;
  const replay = c1.perform({ logical_action_id: "a-002", kind: "charge_account", params: {} });
  assert(replay.result === "deduplicated" && resource.effects.length === before, "I3 replay is deduplicated (no double effect)", results);

  // I5: stale checkpoint refused, newer accepted
  const prev = authority.checkpoint(CHAIN, exec);
  if (prev) {
    const staleCp = { ...prev, checkpoint_version: prev.checkpoint_version - 1 };
    const put = authority.putCheckpoint(staleCp);
    assert(!put.ok && put.reason === "stale_checkpoint", "I5 stale checkpoint refused by authority", results);
  } else {
    assert(false, "I5 checkpoint missing", results);
  }

  // C cannot self-promote without the coordinator
  const rogue = new Worker(CHAIN, exec, "rogue-x", authority, resource, makeLogger("C", store));
  rogue.setAuthority(c1.epoch + 5, "forged-lease", Date.now() + 5000);
  const rogueAct = rogue.perform({ logical_action_id: "a-003", kind: "self_promote", params: {} });
  assert(!rogueAct.ok, "C cannot self-promote (no durable ownership)", results);

  // B resume: an INTERRUPTED handoff continues on its existing epoch (no re-allocation)
  let interruptedEpoch = 0;
  try {
    coord.rotate(CHAIN, exec, c1.ship, ships, JOB, "maintenance", "persist_checkpoint");
  } catch (e) {
    if (!(e instanceof Interrupted)) throw e;
    interruptedEpoch = authority.highestEpoch(CHAIN, exec);
  }
  const resumed = coord.rotate(CHAIN, exec, c1.ship, ships, JOB, "maintenance");
  assert(
    resumed.txn.status === "DONE" &&
    resumed.txn.epoch === interruptedEpoch &&
    authority.highestEpoch(CHAIN, exec) === interruptedEpoch,
    "B resumes interrupted handoff without allocating a new epoch",
    results,
  );

  // mobile eligibility: a locked/low phone must not be selected
  const badShips = [ship({ ship_id: "iphone-locked", os: "ios", battery_pct: 10, charging: false, heartbeat_age_s: 90 })];
  let rejected = false;
  try { coord.selectShip(badShips, JOB); } catch { rejected = true; }
  assert(rejected, "ineligible mobile ship refused by policy", results);

  // health tiers should not treat mere liveness as ownership
  assert(c1.facts()["owner_epoch"] === 2, "health facts expose current epoch", results);

  process.stdout.write("\n" + results.join("\n") + "\n");
  process.stdout.write(`state dir: ${dir}\ntotal effects: ${resource.effects.length}\n`);
}

/* ------------------------------------------------------------------ main */

function main(argv: string[]): void {
  const role = argv[0] ?? "demo";
  if (role === "demo") { demo(); return; }
  const dir = process.env.STATE_DIR ?? join(process.cwd(), "state");
  const shipId = process.env.POD_NAME ?? hostname();
  const chain = process.env.CHAIN_ID ?? CHAIN;
  const exec = process.env.EXEC_ID ?? "E0";
  const store = new Store(dir);
  const authority = new Authority(store);
  const resource = new ProtectedResource(authority);
  const log = makeLogger("C", store);
  let worker: Worker | null = null;
  if (role === "worker") {
    const cp = authority.checkpoint(chain, exec);
    worker = new Worker(chain, exec, shipId, authority, resource, log);
    if (cp) worker.loadCheckpoint(cp, cp.checkpoint_version);
  }
  const port = Number(process.env.PORT ?? 8080);
  // Loopback by default. Under k8s the Deployment sets HOST=0.0.0.0 explicitly
  // (a pod must bind the wildcard for kube-proxy/NodePort and kubelet probes to
  // reach it); nothing else should ever bind beyond loopback.
  const host = process.env.HOST ?? "127.0.0.1";
  createHttpServer({ ship: shipId, worker, authority, log }).listen(port, host, () => {
    log({ event: "listening", result: "ok", role, ship: shipId, port });
  });
}

main(process.argv.slice(2));
