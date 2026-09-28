import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { formatRef, parseRef, type ProjectCtx, type Vault, VaultError } from "./store.js";

const MAX_OUTPUT = 200 * 1024;

/** Env vars that must never reach child processes. */
const STRIP_ENV = ["VAULT_MASTER_PASSWORD", "VAULT_MASTER_PASSWORD_CMD"];

/** Replace every secret (and its base64 / URL-encoded forms) with ***. Values shorter than 4 chars are skipped. */
export function scrub(text: string, secrets: Iterable<string>): string {
  const variants = new Set<string>();
  for (const s of secrets) {
    if (!s || s.length < 4) continue;
    variants.add(s);
    variants.add(Buffer.from(s, "utf8").toString("base64").replace(/=+$/, ""));
    variants.add(encodeURIComponent(s));
    // multi-line values (keys, certs): also hide each substantial line
    for (const line of s.split(/\r?\n/)) if (line.trim().length >= 16) variants.add(line.trim());
  }
  let out = text;
  for (const v of [...variants].sort((a, b) => b.length - a.length)) {
    if (v.length >= 4) out = out.split(v).join("***");
  }
  return out;
}

function resolveMap(vault: Vault, map: Record<string, string>, ctx: ProjectCtx | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, ref] of Object.entries(map)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new VaultError(`invalid env var name "${name}"`);
    out[name] = vault.resolveValue(parseRef(ref, ctx));
  }
  return out;
}

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env = { ...process.env, ...extra };
  for (const k of STRIP_ENV) delete env[k];
  return env;
}

// ---------- run_with_secrets ----------

export interface RunResult {
  exit_code: number | null;
  signal: string | null;
  timed_out: boolean;
  stdout: string;
  stderr: string;
}

export function runWithSecrets(
  vault: Vault,
  opts: { command: string; cwd: string; env: Record<string, string>; timeoutMs: number; ctx: ProjectCtx | null },
): Promise<RunResult> {
  const injected = resolveMap(vault, opts.env, opts.ctx);
  const secrets = Object.values(injected);
  return new Promise((done, fail) => {
    const child = spawn(process.env.SHELL || "/bin/sh", ["-c", opts.command], {
      cwd: opts.cwd,
      env: childEnv(injected),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const bufs = { stdout: "", stderr: "" };
    const collect = (k: "stdout" | "stderr") => (chunk: Buffer) => {
      if (bufs[k].length < MAX_OUTPUT) bufs[k] += chunk.toString("utf8");
    };
    child.stdout.on("data", collect("stdout"));
    child.stderr.on("data", collect("stderr"));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 3000).unref();
    }, opts.timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      fail(new VaultError(`failed to start command: ${e.message}`));
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const trunc = (s: string) => (s.length >= MAX_OUTPUT ? s.slice(0, MAX_OUTPUT) + "\n…[truncated]" : s);
      done({
        exit_code: code,
        signal,
        timed_out: timedOut,
        stdout: scrub(trunc(bufs.stdout), secrets),
        stderr: scrub(trunc(bufs.stderr), secrets),
      });
    });
  });
}

// ---------- files on disk ----------

type GitStatus = "ignored" | "tracked-or-not-ignored" | "no-repo";

export function gitStatus(file: string): GitStatus {
  const r = spawnSync("git", ["check-ignore", "-q", "--", basename(file)], { cwd: dirname(file) });
  if (r.status === 0) return "ignored";
  if (r.status === 1) return "tracked-or-not-ignored";
  return "no-repo";
}

function guardTarget(target: string, force: boolean): void {
  if (!existsSync(dirname(target))) throw new VaultError(`directory ${dirname(target)} does not exist`);
  if (!force && gitStatus(target) === "tracked-or-not-ignored") {
    throw new VaultError(`${target} is inside a git repo and NOT gitignored — add it to .gitignore or pass force=true`);
  }
}

function quoteEnv(v: string): string {
  if (/^[A-Za-z0-9_./:@+-]*$/.test(v)) return v;
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "\\$").replace(/\r?\n/g, "\\n")}"`;
}

/** Write/merge KEY=value lines into a .env file (mode 0600). Existing unrelated lines are kept. */
export function writeEnvFile(
  vault: Vault,
  opts: { target: string; mapping: Record<string, string>; force: boolean; ctx: ProjectCtx | null },
): { path: string; written: string[]; git: GitStatus } {
  const target = resolve(opts.target);
  guardTarget(target, opts.force);
  const values = resolveMap(vault, opts.mapping, opts.ctx);
  const lines = existsSync(target) ? readFileSync(target, "utf8").split("\n") : [];
  const pending = new Map(Object.entries(values));
  const merged = lines.map((line) => {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (m && pending.has(m[1])) {
      const v = pending.get(m[1])!;
      pending.delete(m[1]);
      return `${m[1]}=${quoteEnv(v)}`;
    }
    return line;
  });
  if (merged.length && merged[merged.length - 1] === "") merged.pop();
  for (const [k, v] of pending) merged.push(`${k}=${quoteEnv(v)}`);
  writeFileSync(target, merged.join("\n") + "\n", { mode: 0o600 });
  chmodSync(target, 0o600);
  vault.audit("mcp", target, `write-env:${Object.keys(values).join(",")}`);
  return { path: target, written: Object.keys(values), git: gitStatus(target) };
}

export function materializeFile(
  vault: Vault,
  opts: { ref: string; target?: string; mode: number; force: boolean; overwrite: boolean; ctx: ProjectCtx | null; cwd: string },
): { path: string; size: number; mode: string } {
  const ref = parseRef(opts.ref, opts.ctx);
  const { filename, content } = vault.readFile(ref);
  const target = resolve(opts.cwd, opts.target ?? filename);
  if (existsSync(target) && !opts.overwrite) throw new VaultError(`${target} exists — pass overwrite=true`);
  guardTarget(target, opts.force);
  writeFileSync(target, content, { mode: opts.mode });
  chmodSync(target, opts.mode);
  vault.audit("mcp", formatRef(ref), `materialize:${target}`);
  return { path: target, size: statSync(target).size, mode: opts.mode.toString(8) };
}

// ---------- http_request ----------

const PLACEHOLDER = /\{\{\s*secret:([^}\s]+)\s*\}\}/g;

export async function httpRequest(
  vault: Vault,
  opts: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
    timeoutMs: number;
    ctx: ProjectCtx | null;
  },
) {
  const used = new Map<string, string>();
  const fill = (s: string) =>
    s.replace(PLACEHOLDER, (_, ref: string) => {
      if (!used.has(ref)) used.set(ref, vault.resolveValue(parseRef(ref, opts.ctx)));
      return used.get(ref)!;
    });
  const url = fill(opts.url);
  const headers = Object.fromEntries(Object.entries(opts.headers).map(([k, v]) => [k, fill(v)]));
  const body = opts.body === undefined ? undefined : fill(opts.body);
  const secrets = [...used.values()];

  let res: Response;
  try {
    res = await fetch(url, { method: opts.method, headers, body, signal: AbortSignal.timeout(opts.timeoutMs) });
  } catch (e) {
    throw new VaultError(`request failed: ${scrub(String((e as Error).message), secrets)}`);
  }
  let text = await res.text();
  if (text.length > MAX_OUTPUT) text = text.slice(0, MAX_OUTPUT) + "\n…[truncated]";
  return {
    status: res.status,
    status_text: res.statusText,
    headers: JSON.parse(scrub(JSON.stringify(Object.fromEntries(res.headers)), secrets)),
    body: scrub(text, secrets),
    secrets_used: [...used.keys()],
  };
}
