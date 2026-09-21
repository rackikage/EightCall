// Generic client. There is no per-capability method here — every call is
// driven by a registry entry, so a new command needs no change to this file.

export type Kind = "enum" | "multi-enum" | "int" | "bool" | "server";
export type Runner = "read_view" | "exec" | "service";
export type ConfirmMode = "none" | "click" | "type-id";

export interface ArgSpec {
  name: string;
  label: string;
  kind: Kind;
  required: boolean;
  default?: unknown;
  min?: number;
  max?: number;
  depends_on?: string;
  source?: { from: "static" | "view" | "server"; values?: Opt[] };
}

export interface Opt {
  value: string;
  label: string;
  scope?: string | null;
}

export interface OutputSpec {
  kind: "table" | "text-lines" | "json" | "json-stream" | "argv-preview" | "pass-fail" | "log-stream";
  facts?: Array<{ label: string; path: string; as?: string }>;
  rows?: string;
  columns?: Array<{ label: string; path: string; as?: string }>;
  empty?: string;
  reverse?: boolean;
  verdict?: string;
  argv?: string;
  lines?: string;
}

export interface Capability {
  id: string;
  label: string;
  group: string;
  summary: string;
  mutating: boolean;
  runner: Runner;
  enabled?: boolean;
  effects?: string[];
  confirm?: ConfirmMode;
  requires_preview?: string;
  writes?: string[];
  args: ArgSpec[] | { from: string };
  output: OutputSpec;
  dashboard?: { panel: string; order: number; refresh_seconds?: number };
  docs?: { notes?: string; hazard?: string };
  service?: { singleton?: boolean };
  authz?: { action: string; required: boolean };
}

export interface RegistryDoc {
  version: number;
  schema: string;
  note?: string;
  sha256?: string;
  capabilities: Capability[];
}

export interface Envelope {
  ok: boolean;
  capability: string;
  error?: string;
  duration_ms?: number;
  preview_token?: string;
  running?: boolean;
  pid?: number;
  output?: {
    kind: string;
    data?: unknown;
    stdout?: string;
    stderr?: string;
    exit_code?: number | null;
    lines?: string[];
  };
  attribution?: {
    registry_sha256?: string;
    effects?: string[];
    mutating?: boolean;
    argv?: string[];
    authz_decision_id?: string | null;
  };
}

export type ProposalStatus = "pending" | "authorized" | "fired" | "failed" | "rejected";

export interface Proposal {
  id: string;
  capability: string;
  args: Record<string, unknown>;
  note?: string | null;
  created_by: string;
  created_at: number;
  status: ProposalStatus;
  reason?: string | null;
  decision_id?: string | null;
  decided_at?: number | null;
}

export interface ServiceStatus {
  capability: string;
  running: boolean;
  pid: number | null;
  exit_code: number | null;
  stopped_by_operator?: boolean;
  lines: string[];
}

async function j<T>(path: string, init?: RequestInit): Promise<{ status: number; body: T }> {
  const resp = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}) },
  });
  const body = (await resp.json().catch(() => ({ error: "response was not JSON" }))) as T;
  return { status: resp.status, body };
}

export const api = {
  registry: () => j<RegistryDoc>("/api/registry"),
  healthz: () => j<{ status: string; sidecar: string; registry_sha256: string }>("/api/healthz"),
  options: (cap: string, arg: string, dep?: string) =>
    j<{ options: Opt[] }>(
      `/api/options/${encodeURIComponent(cap)}/${encodeURIComponent(arg)}` +
        (dep ? `?dep=${encodeURIComponent(dep)}` : ""),
    ),
  read: (cap: string, args: Record<string, unknown>) => {
    const q = Object.entries(args)
      .filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length))
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(Array.isArray(v) ? v.join(",") : String(v))}`)
      .join("&");
    return j<Envelope>(`/api/read/${encodeURIComponent(cap)}${q ? `?${q}` : ""}`);
  },
  run: (cap: string, payload: { args?: Record<string, unknown>; confirm?: string; preview_token?: string }) =>
    j<Envelope>(`/api/run/${encodeURIComponent(cap)}`, { method: "POST", body: JSON.stringify(payload) }),
  serviceStatus: (cap: string) => j<ServiceStatus>(`/api/service/${encodeURIComponent(cap)}/status`),
  serviceStop: (cap: string) => j<{ ok: boolean }>(`/api/service/${encodeURIComponent(cap)}/stop`, { method: "POST" }),

  // the approval queue — file, authorize (fires through the gate), reject
  proposals: () => j<{ proposals: Proposal[] }>("/api/proposals"),
  createProposal: (payload: { capability: string; args?: Record<string, unknown>; note?: string; created_by?: string }) =>
    j<{ ok: boolean; proposal: Proposal }>("/api/proposals", { method: "POST", body: JSON.stringify(payload) }),
  authorizeProposal: (id: string, confirm: string, preview_token?: string) =>
    j<Envelope>(`/api/proposals/${encodeURIComponent(id)}/authorize`, {
      method: "POST",
      body: JSON.stringify({ confirm, preview_token }),
    }),
  rejectProposal: (id: string, reason?: string) =>
    j<{ ok: boolean }>(`/api/proposals/${encodeURIComponent(id)}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason: reason ?? "" }),
    }),
};

/** RFC6901 JSON Pointer. "" means the value itself. */
export function pointer(obj: unknown, ptr: string): unknown {
  if (!ptr) return obj;
  let cur: any = obj;
  for (const raw of ptr.split("/").slice(1)) {
    if (cur == null) return undefined;
    cur = cur[raw.replace(/~1/g, "/").replace(/~0/g, "~")];
  }
  return cur;
}
