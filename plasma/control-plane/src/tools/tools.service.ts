import { Injectable, BadRequestException, ForbiddenException } from "@nestjs/common";
import { spawn } from "node:child_process";
import { appendFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";

type ToolName = "nmap" | "ncat" | "arp-scan" | "tcpdump" | "python";

export interface RunResult {
  tool: string;
  args: string[];
  elevated: boolean;
  code: number | null;
  duration_ms: number;
  stdout: string;
  stderr: string;
}

const ROOT = resolve(__dirname, "..", "..");
const LOG_DIR = join(ROOT, "data", "logs");
const MAX_OUT = 256 * 1024;

/** Python is never a server: only these fixed scripts may be executed. */
const PY_SCRIPTS = new Set(["net_report.py"]);

const TOOLS: Record<ToolName, { bin: string; root: boolean; pythonScript?: boolean }> = {
  nmap: { bin: "nmap", root: false },
  ncat: { bin: "ncat", root: false },
  "arp-scan": { bin: "arp-scan", root: true },
  tcpdump: { bin: "tcpdump", root: true },
  python: { bin: join(ROOT, ".venv", "bin", "python"), root: false, pythonScript: true },
};

/** Only targets on hardware you own. Override deliberately via SCOPE. */
const SCOPE = (process.env.SCOPE ?? "127.0.0.1,192.168.8.0/24")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;
const BAD_ARG = /[;&|`$(){}<>\\'"\s]/;

function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

function inScope(target: string): boolean {
  const [ip, bitsRaw] = target.split("/");
  const v = ipToInt(ip);
  if (v === null) return false;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  return SCOPE.some((s) => {
    const [sip, sbitsRaw] = s.split("/");
    const sv = ipToInt(sip);
    if (sv === null) return false;
    const sBits = sbitsRaw === undefined ? 32 : Number(sbitsRaw);
    if (bits < sBits) return false; // requested range must be inside the scope range
    const mask = (0xffffffff << (32 - sBits)) >>> 0;
    return (v & mask) === (sv & mask);
  });
}

function validateArg(a: string): void {
  if (a.length === 0 || a.length > 256) throw new BadRequestException("bad arg length");
  if (BAD_ARG.test(a)) throw new BadRequestException(`unsafe arg: ${a}`);
  if (a.includes("/") && !IP_RE.test(a)) throw new BadRequestException(`path-like arg rejected: ${a}`);
  if (/^-o[NXAGSJ]$/.test(a)) throw new BadRequestException(`file-writing option rejected: ${a}`);
  if (IP_RE.test(a) && !inScope(a)) throw new ForbiddenException(`target out of scope: ${a}`);
}

@Injectable()
export class ToolsService {
  list(): { tools: string[]; python_scripts: string[]; scope: string[]; root_ops: string[] } {
    return {
      tools: Object.keys(TOOLS),
      python_scripts: [...PY_SCRIPTS],
      scope: SCOPE,
      root_ops: Object.entries(TOOLS).filter(([, d]) => d.root).map(([k]) => k),
    };
  }

  private async audit(rec: RunResult & { at: string }): Promise<void> {
    try {
      await mkdir(LOG_DIR, { recursive: true });
      await appendFile(join(LOG_DIR, "tools.jsonl"), JSON.stringify(rec) + "\n");
    } catch {
      /* logging must never break the operation */
    }
  }

  async run(toolName: string, rawArgs: unknown, elevated: boolean, timeoutMs: number): Promise<RunResult> {
    const def = TOOLS[toolName as ToolName];
    if (!def) throw new BadRequestException(`unknown tool: ${toolName}`);
    if (!Array.isArray(rawArgs)) throw new BadRequestException("args must be an array");
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000) {
      throw new BadRequestException("timeout_ms must be 1..300000");
    }
    if (def.root && !elevated) {
      throw new ForbiddenException(`${toolName} needs elevation: resend with elevated=true (sudo applies to this one call only)`);
    }

    const userArgs = rawArgs.map((a) => String(a));
    let finalArgs: string[];
    if (def.pythonScript) {
      const script = userArgs.shift();
      if (!script || !PY_SCRIPTS.has(script)) throw new ForbiddenException(`python script not allowlisted: ${script ?? "(none)"}`);
      for (const a of userArgs) validateArg(a);
      finalArgs = [join(ROOT, "scripts", script), ...userArgs];
    } else {
      for (const a of userArgs) validateArg(a);
      finalArgs = userArgs;
    }

    const argv = def.root ? ["sudo", "-n", def.bin, ...finalArgs] : [def.bin, ...finalArgs];
    const start = Date.now();
    const child = spawn(argv[0], argv.slice(1), { shell: false, env: process.env });

    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString();
      if (out.length > MAX_OUT) out = out.slice(-MAX_OUT);
    });
    child.stderr.on("data", (d: Buffer) => {
      err += d.toString();
      if (err.length > MAX_OUT) err = err.slice(-MAX_OUT);
    });

    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    const code: number | null = await new Promise((res) => child.on("close", (c) => res(c)));
    clearTimeout(timer);

    const result: RunResult = {
      tool: toolName,
      args: finalArgs,
      elevated: def.root,
      code,
      duration_ms: Date.now() - start,
      stdout: out,
      stderr: err,
    };
    await this.audit({ ...result, at: new Date().toISOString() });
    return result;
  }
}
