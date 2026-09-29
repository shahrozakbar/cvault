#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { z } from "zod";
import { checkHosts, lockRejected, prepareUse, remapPlaceholders } from "./enforce.js";
import { httpRequest, materializeFile, PLACEHOLDER, runWithSecrets, writeEnvFile } from "./inject.js";
import { extractHosts } from "./policy.js";
import { passwordFromEnv } from "./password.js";
import { askAllow, requestCredential, sealedFetch, sealedSave } from "./sealed.js";
import { formatRef, formatScope, formatServicePath, parseRef, parseScope, parseServicePath, type ProjectCtx, type Ref, Vault, VaultError } from "./store.js";

let vault: Vault | null = null;
let lockReason = "vault locked";

try {
  const pw = passwordFromEnv();
  if (!pw) lockReason = "vault locked: VAULT_MASTER_PASSWORD (or VAULT_MASTER_PASSWORD_CMD) is not set for the MCP server";
  else vault = Vault.open(pw);
} catch (e) {
  lockReason = `vault locked: ${(e as Error).message}`;
}

function v(): Vault {
  if (!vault) throw new VaultError(lockReason);
  return vault;
}

/** Project bound to the given cwd (defaults to the server's cwd, i.e. where Claude Code was started). */
function ctxFor(cwd?: string): ProjectCtx | null {
  return v().resolveContext(cwd ?? process.cwd());
}

const server = new McpServer(
  { name: "cvault", version: "0.2.0" },
  {
    instructions: [
      "Local password manager. Hierarchy: tenant → project → service → item (secret | credential | file).",
      "Refs look like tenant/env/project/service/key (environment such as develop, staging, prod) or tenant/project/service/key (no environment), optionally #field (default field: password) and @N for an old version. Inside a linked project: env/service/key or service/key.",
      "Credentials may carry a role label and one per service may be the default: when the user names a role (\"login as admin\") use the item with that role; if no role is named use the service's default; only ask when several match and none is default.",
      "Nothing is ever deleted: use archive/restore. Every update creates a new version; see list_versions / rollback_secret.",
      "If a project is bound to the working directory, short refs service/key work too — call resolve_context first.",
      "Prefer run_with_secrets / write_env_file / materialize_file / http_request: they use secrets without showing them.",
      "Only call reveal_secret when the user explicitly needs to see a value.",
      "When the user wants to save or fetch a secret without exposing it to Claude, use sealed_save / sealed_fetch (macOS dialog / clipboard).",
      "Enforced by the server (you cannot bypass these): a missing ref makes the server ask the user for it in a dialog before running your tool (just use the ref you need, e.g. staging-admin-panel/systemadmin#password); secrets are only sent to each service's allowed hosts; repeated use of a password asks the user to Allow/Block; an HTTP 401 locks the credential; set_secret/set_credential (values from the chat) need the user's Allow in a dialog unless enabled per project.",
      "If a result says LOCKED or blocked: stop, do not retry and do not try another environment's credential — tell the user.",
      "Never ask the user to paste secrets into chat.",
    ].join(" "),
  },
);

const cwdArg = z.string().optional().describe("Directory used to resolve the bound project for short refs (default: server cwd)");
const roleArg = z.string().optional().describe("role label, e.g. admin, viewer, tester — lets the user say 'login as admin'");
const defaultArg = z.boolean().optional().describe("make this the default credential of its service (used when no role is named)");

function applyTags(r: Ref, role?: string, isDefault?: boolean): void {
  if (role !== undefined || isDefault !== undefined) v().tagItem({ ...r, field: undefined }, { role, isDefault });
}

/**
 * set_secret / set_credential carry values through the chat. Allowed without asking only when the
 * user enabled it for the project; otherwise the user approves each save in a native dialog
 * (which shows the path and field names, never the values).
 */
async function requireChatValues(r: Ref, fieldNames: string[]): Promise<void> {
  if (v().chatValuesAllowed(r.tenant, r.project)) return;
  const target = formatRef({ ...r, field: undefined, version: undefined });
  const exists = v().itemStatus(r) !== "missing";
  const ok = await askAllow({
    title: "cvault - save a value from the chat?",
    message:
      `Claude wants to save ${fieldNames.length > 1 ? `a credential (${fieldNames.join(", ")})` : "a secret"} it received in the chat:\n\n` +
      `${target}${exists ? "\n(exists - a new version will be saved)" : ""}\n\n` +
      `The value is already in the conversation transcript. Allow saving it to the vault?`,
    allow: "Allow",
    deny: "Deny",
  });
  if (!ok) {
    throw new VaultError(
      `the user denied saving ${target} from the chat. Offer request_credential instead (the user types the value in a secure dialog).`,
    );
  }
  v().audit("user", target, "chat-value-approved");
}

function tagNote(role?: string, isDefault?: boolean): string {
  const parts = [role ? `role=${role}` : null, isDefault ? "default" : null].filter(Boolean);
  return parts.length ? ` [${parts.join(", ")}]` : "";
}

/** Tools that consume existing secrets: a "not found" there means the credential must be requested. */
const USE_TOOLS = new Set(["run_with_secrets", "write_env_file", "materialize_file", "http_request", "reveal_secret", "sealed_fetch"]);

function tool<S extends z.ZodRawShape>(
  name: string,
  description: string,
  shape: S,
  handler: (args: z.infer<z.ZodObject<S>>) => unknown,
) {
  server.registerTool(name, { description, inputSchema: shape }, (async (args: z.infer<z.ZodObject<S>>) => {
    try {
      const result = await handler(args);
      return { content: [{ type: "text" as const, text: typeof result === "string" ? result : JSON.stringify(result, null, 2) }] };
    } catch (e) {
      let msg = e instanceof VaultError ? e.message : `internal error: ${(e as Error).message}`;
      if (USE_TOOLS.has(name) && /(item|service|project) ".*" not found/.test(msg)) {
        msg +=
          " → This credential is not in the vault yet. Call request_credential now (suggested_ref = the path you tried, reason = what you are doing) so the user can enter it in a secure dialog. Do not ask for it in chat.";
      }
      return { isError: true, content: [{ type: "text" as const, text: msg }] };
    }
  }) as never);
}

// ---------- browse ----------

tool("vault_status", "Show whether the vault is unlocked and which project is bound to the working directory.", { cwd: cwdArg }, ({ cwd }) => {
  if (!vault) return { unlocked: false, reason: lockReason };
  return { unlocked: true, home: vault.home, context: ctxFor(cwd) };
});

tool("resolve_context", "Return the tenant/project bound to a directory (enables short refs service/key).", { cwd: cwdArg }, ({ cwd }) => {
  return ctxFor(cwd) ?? { bound: false, hint: "bind one with bind_project_path" };
});

const archivedArg = z.boolean().default(false).describe("also show archived entries");

tool("list_tenants", "List tenants (clients/workspaces).", { include_archived: archivedArg }, ({ include_archived }) =>
  v().listTenants(include_archived),
);

tool(
  "list_projects",
  "List projects, optionally within a tenant.",
  { tenant: z.string().optional(), include_archived: archivedArg },
  ({ tenant, include_archived }) => v().listProjects(tenant, include_archived),
);

tool(
  "list_services",
  "List services of a project. `project` is tenant/project; omit to use the project bound to cwd.",
  { project: z.string().optional(), include_archived: archivedArg, cwd: cwdArg },
  ({ project, include_archived, cwd }) => {
    const [t, p] = projectOf(project, cwd);
    return v().listServices(t, p, include_archived);
  },
);

tool(
  "list_items",
  "List item metadata (never values, includes current version and environment). `scope`: tenant | tenant/env | tenant/project | tenant/[env/]project[/service]; omit for the project linked to cwd (all environments).",
  { scope: z.string().optional(), include_archived: archivedArg, cwd: cwdArg },
  ({ scope, include_archived, cwd }) => {
    if (!scope) {
      const [t, p] = projectOf(undefined, cwd);
      return v().listItems(t, p, undefined, include_archived);
    }
    const sc = v().resolveScope(scope);
    const projects = (v().listProjects(sc.tenant) as unknown as Array<{ tenant: string; project: string }>).filter(
      (pr) => !sc.project || pr.project === sc.project,
    );
    return projects.flatMap((pr) => v().listItems(pr.tenant, pr.project, sc.service, include_archived, sc.env));
  },
);

function projectOf(project: string | undefined, cwd?: string): [string, string] {
  if (project) {
    const parts = parseScope(project);
    if (parts.length !== 2) throw new VaultError("project must be tenant/project");
    return [parts[0], parts[1]];
  }
  const ctx = ctxFor(cwd);
  if (!ctx) throw new VaultError("no project bound to this directory; pass project=tenant/project");
  return [ctx.tenant, ctx.project];
}

// ---------- manage ----------

tool("create_tenant", "Create (or rename) a tenant.", { tenant: z.string(), name: z.string().optional() }, ({ tenant, name }) => {
  v().ensureTenant(tenant, name);
  return `tenant ${tenant} ready`;
});

tool(
  "create_project",
  "Create a project under a tenant (tenant is auto-created). Optionally bind a local directory to it.",
  { project: z.string().describe("tenant/project"), name: z.string().optional(), bind_path: z.string().optional() },
  ({ project, name, bind_path }) => {
    const [t, p] = projectOf(project);
    v().ensureProject(t, p, name);
    const bound = bind_path ? v().bindPath(t, p, bind_path) : undefined;
    return { project: `${t}/${p}`, bound_path: bound };
  },
);

tool(
  "create_service",
  "Create or update a service (e.g. postgres, stripe, aws) under a project, optionally in an environment.",
  {
    service: z.string().describe("tenant/project/service or tenant/env/project/service"),
    name: z.string().optional(),
    url: z.string().optional(),
    notes: z.string().optional(),
  },
  ({ service, ...info }) => {
    const [t, p, key] = parseServicePath(service);
    v().ensureService(t, p, key, info);
    return `service ${formatServicePath(t, p, key)} ready`;
  },
);

tool(
  "bind_project_path",
  "Bind (or unbind) a local directory to a project so short refs resolve automatically inside it. Optional env = default environment for 2-part short refs (service/key).",
  {
    project: z.string().describe("tenant/project"),
    path: z.string(),
    env: z.string().optional().describe("default environment for this directory, e.g. staging"),
    unbind: z.boolean().default(false),
  },
  ({ project, path, env, unbind }) => {
    const [t, p] = projectOf(project);
    if (unbind) {
      v().unbindPath(t, p, path);
      return `unbound ${resolve(path)}`;
    }
    return `bound ${v().bindPath(t, p, path, env)} → ${t}/${p}${env ? ` (environment ${env})` : ""}`;
  },
);

tool(
  "set_secret",
  "Store a single-value secret (API key, token) that the user gave in the chat. Unless enabled for the project, the user approves it in an Allow/Deny dialog. Prefer request_credential when the value isn't already in the chat.",
  { ref: z.string(), value: z.string(), description: z.string().optional(), role: roleArg, default: defaultArg, cwd: cwdArg },
  async ({ ref, value, description, role, default: isDefault, cwd }) => {
    const r = parseRef(ref, ctxFor(cwd));
    await requireChatValues(r, ["value"]);
    const ver = v().setSecret(r, value, description);
    applyTags(r, role, isDefault);
    return `stored ${formatRef(r)} (v${ver})${tagNote(role, isDefault)}`;
  },
);

tool(
  "set_credential",
  "Store a multi-field credential (e.g. {username, password, host, port}) that the user gave in the chat. Unless enabled for the project, the user approves it in an Allow/Deny dialog. Prefer request_credential when the values aren't already in the chat.",
  {
    ref: z.string(),
    fields: z.record(z.string(), z.string()),
    description: z.string().optional(),
    role: roleArg,
    default: defaultArg,
    cwd: cwdArg,
  },
  async ({ ref, fields, description, role, default: isDefault, cwd }) => {
    const r = parseRef(ref, ctxFor(cwd));
    await requireChatValues(r, Object.keys(fields));
    const ver = v().setCredential(r, fields, description);
    applyTags(r, role, isDefault);
    return `stored ${formatRef(r)} (v${ver}) with fields [${Object.keys(fields).join(", ")}]${tagNote(role, isDefault)}`;
  },
);

tool(
  "generate_secret",
  "Generate a random secret and store it without ever returning it (e.g. new DB password, JWT secret).",
  {
    ref: z.string(),
    length: z.number().int().min(8).max(256).default(32),
    alphabet: z.enum(["alnum", "hex", "symbols"]).default("alnum"),
    description: z.string().optional(),
    cwd: cwdArg,
  },
  ({ ref, length, alphabet, description, cwd }) => {
    const r = parseRef(ref, ctxFor(cwd));
    const ver = v().generateSecret(r, length, alphabet, description);
    return `generated ${length}-char ${alphabet} secret at ${formatRef(r)} (v${ver})`;
  },
);

tool(
  "put_file",
  "Encrypt a file from disk into the vault (e.g. .pem, service-account.json, kubeconfig). Contents never pass through chat.",
  { ref: z.string(), src_path: z.string(), description: z.string().optional(), cwd: cwdArg },
  ({ ref, src_path, description, cwd }) => {
    const r = parseRef(ref, ctxFor(cwd));
    const info = v().putFile(r, resolve(cwd ?? process.cwd(), src_path), description);
    return { stored: formatRef(r), ...info, hint: "you may now delete the plaintext source file if it is no longer needed" };
  },
);

tool(
  "tag_item",
  "Set an item's role label and/or mark it as the default of its service (non-secret metadata, no new version). role=\"\" clears the role.",
  { ref: z.string(), role: z.string().optional(), default: z.boolean().optional(), cwd: cwdArg },
  ({ ref, role, default: isDefault, cwd }) => {
    const r = parseRef(ref, ctxFor(cwd));
    return { ref: formatRef({ ...r, field: undefined }), ...v().tagItem({ ...r, field: undefined }, { role: role === "" ? null : role, isDefault }) };
  },
);

// ---------- archive / versions (nothing is ever deleted) ----------

tool(
  "archive",
  "Archive (never delete) a tenant, project, service or item: tenant | tenant/project | tenant/project/service | tenant/project/service/key. Archived things are hidden and unusable until restored.",
  { target: z.string() },
  ({ target }) => v().archive(v().resolveTarget(target)),
);

tool(
  "restore",
  "Restore an archived tenant, project, service or item.",
  { target: z.string() },
  ({ target }) => v().restore(v().resolveTarget(target)),
);

tool(
  "list_versions",
  "Version history of an item (metadata only, newest first). Every update creates a new version; old ones are kept. Use ref@N anywhere to use an old version.",
  { ref: z.string(), cwd: cwdArg },
  ({ ref, cwd }) => v().listVersions(parseRef(ref, ctxFor(cwd))),
);

tool(
  "rollback_secret",
  "Make an old version current again. It is copied forward as a NEW version, so history is never rewritten.",
  { ref: z.string(), version: z.number().int().min(1), cwd: cwdArg },
  ({ ref, version, cwd }) => {
    const r = parseRef(ref, ctxFor(cwd));
    const nv = v().rollback(r, version);
    return `${formatRef({ ...r, version: undefined })}: v${version} is now current as v${nv}`;
  },
);

// ---------- use (values hidden) ----------

tool(
  "run_with_secrets",
  "Run a shell command with secrets injected as env vars. Output is scrubbed of the injected values. Example env: {\"DATABASE_URL\": \"acme/api/postgres/url\", \"PGPASSWORD\": \"acme/api/postgres/db#password\"}.",
  {
    command: z.string(),
    env: z.record(z.string(), z.string()).describe("ENV_VAR_NAME → ref"),
    cwd: z.string().optional(),
    timeout_seconds: z.number().int().min(1).max(3600).default(120),
  },
  async ({ command, env, cwd, timeout_seconds }) => {
    const dir = resolve(cwd ?? process.cwd());
    const ctx = ctxFor(dir);
    const p = await prepareUse(v(), Object.values(env), ctx, {
      purpose: `run: ${command.length > 140 ? command.slice(0, 140) + "…" : command}`,
      targetHosts: extractHosts(command),
    });
    const mapped = Object.fromEntries(Object.entries(env).map(([k, r]) => [k, p.remap.get(r) ?? r]));
    const res = await runWithSecrets(v(), { command, env: mapped, cwd: dir, timeoutMs: timeout_seconds * 1000, ctx });
    return p.notes.length ? { ...res, notes: p.notes } : res;
  },
);

tool(
  "write_env_file",
  "Write/merge secrets into a .env file (mode 0600). Refuses if the file is in a git repo and not gitignored unless force=true.",
  {
    path: z.string().describe("target file, e.g. .env or /abs/path/.env.local"),
    mapping: z.record(z.string(), z.string()).describe("ENV_VAR_NAME → ref"),
    force: z.boolean().default(false),
    cwd: cwdArg,
  },
  async ({ path, mapping, force, cwd }) => {
    const dir = resolve(cwd ?? process.cwd());
    const ctx = ctxFor(dir);
    const p = await prepareUse(v(), Object.values(mapping), ctx, { purpose: `write ${path}` });
    const mapped = Object.fromEntries(Object.entries(mapping).map(([k, r]) => [k, p.remap.get(r) ?? r]));
    const res = writeEnvFile(v(), { target: resolve(dir, path), mapping: mapped, force, ctx });
    return p.notes.length ? { ...res, notes: p.notes } : res;
  },
);

tool(
  "materialize_file",
  "Decrypt a file item to disk (default mode 0600, default name = original filename in cwd).",
  {
    ref: z.string(),
    target_path: z.string().optional(),
    mode: z.string().regex(/^[0-7]{3,4}$/).default("600"),
    overwrite: z.boolean().default(false),
    force: z.boolean().default(false).describe("allow writing into a git repo when not gitignored"),
    cwd: cwdArg,
  },
  async ({ ref, target_path, mode, overwrite, force, cwd }) => {
    const dir = resolve(cwd ?? process.cwd());
    const ctx = ctxFor(dir);
    await prepareUse(v(), [ref], ctx, { purpose: `write file ${target_path ?? ""}`.trim(), noPrompt: true });
    return materializeFile(v(), { ref, target: target_path, mode: parseInt(mode, 8), overwrite, force, ctx, cwd: dir });
  },
);

tool(
  "http_request",
  "Make an HTTP request with {{secret:ref}} placeholders in url/headers/body, substituted server-side. Response is scrubbed.",
  {
    method: z.string().default("GET"),
    url: z.string(),
    headers: z.record(z.string(), z.string()).default({}),
    body: z.string().optional(),
    timeout_seconds: z.number().int().min(1).max(300).default(30),
    cwd: cwdArg,
  },
  async ({ method, url, headers, body, timeout_seconds, cwd }) => {
    const ctx = ctxFor(cwd);
    const texts = [url, ...Object.values(headers), body ?? ""];
    const rawRefs = texts.flatMap((t) => [...t.matchAll(PLACEHOLDER)].map((m) => m[1]));
    const shownUrl = url.replace(PLACEHOLDER, "{{secret}}");
    const p = await prepareUse(v(), rawRefs, ctx, { purpose: `${method.toUpperCase()} ${shownUrl}` });
    const rm = (s: string) => remapPlaceholders(s, p.remap, PLACEHOLDER);
    const finalRefs = rawRefs.map((r) => p.remap.get(r) ?? r);
    const parsedRefs = finalRefs.map((r) => parseRef(r, ctx));
    let host = "";
    const res = await httpRequest(v(), {
      method: method.toUpperCase(),
      url: rm(url),
      headers: Object.fromEntries(Object.entries(headers).map(([k, val]) => [k, rm(val)])),
      body: body === undefined ? undefined : rm(body),
      timeoutMs: timeout_seconds * 1000,
      ctx,
      beforeSend: (u) => {
        host = u.hostname;
        checkHosts(v(), parsedRefs, [u.hostname]);
      },
    });
    const notes = [...p.notes];
    if (res.status === 401 && finalRefs.length) {
      const locked = lockRejected(v(), finalRefs, ctx, host);
      if (locked.length) {
        notes.push(
          `HTTP 401 - ${locked.join(", ")} is now LOCKED to prevent account lockout. Do not retry. Tell the user; they can re-enter it (request_credential on the same path) or run: cvault unlock <ref>`,
        );
      }
    }
    return notes.length ? { ...res, notes } : res;
  },
);

// ---------- sealed (user ↔ vault via macOS UI; value never reaches the model) ----------

tool(
  "sealed_save",
  "Ask the USER to type a secret into native macOS dialogs and store it: first the save path (pre-filled with `ref`, editable), then the value (masked). Use this whenever the user wants to save a secret without exposing it to Claude. Use ref#field to set one field of a credential. For a whole missing login (username + password …) prefer request_credential.",
  {
    ref: z.string().optional().describe("suggested save path (the user can change it in the dialog)"),
    description: z.string().optional(),
    confirm: z.boolean().default(false).describe("ask the user to enter it twice"),
    timeout_seconds: z.number().int().min(10).max(600).default(120),
    role: roleArg,
    default: defaultArg,
    cwd: cwdArg,
  },
  async ({ ref, description, confirm, timeout_seconds, role, default: isDefault, cwd }) => {
    const ctx = ctxFor(cwd);
    let suggested: Ref | null = null;
    try {
      suggested = ref ? parseRef(ref, ctx) : null;
    } catch {
      /* invalid suggestion: the user fixes it in the path dialog */
    }
    const res = await sealedSave(v(), suggested, { description, confirm, timeoutSec: timeout_seconds, ctx });
    if (res.ref) {
      applyTags(res.ref, role, isDefault);
      return res.text + tagNote(role, isDefault);
    }
    return res.text;
  },
);

tool(
  "request_credential",
  "Use this AUTOMATICALLY whenever a task needs a credential or secret that is NOT in the vault (e.g. the user asks to log in and no matching item exists, or a tool returned 'not found'). Opens native macOS dialogs: first the save path (pre-filled with suggested_ref, the user can change it), then each field (username visible, password/token hidden). Values never reach Claude; the result tells you the ref to use next. Never ask the user to type secrets into the chat instead.",
  {
    suggested_ref: z
      .string()
      .optional()
      .describe("suggested save path, e.g. admin-panel/superadmin inside a linked project or tenant/project/service/key"),
    type: z.enum(["credential", "secret"]).default("credential").describe("credential = several fields (username/password/…); secret = one value (API key, token)"),
    fields: z.array(z.string()).optional().describe('credential fields to ask for, default ["username","password"]; e.g. ["username","password","url"]'),
    reason: z.string().optional().describe('shown in the dialog, e.g. "log into the draft admin panel"'),
    description: z.string().optional(),
    role: roleArg,
    default: defaultArg,
    timeout_seconds: z.number().int().min(10).max(600).default(180),
    cwd: cwdArg,
  },
  async ({ suggested_ref, type, fields, reason, description, role, default: isDefault, timeout_seconds, cwd }) => {
    const ctx = ctxFor(cwd);
    let suggested: string | undefined;
    try {
      suggested = suggested_ref ? formatRef(parseRef(suggested_ref, ctx)) : undefined;
    } catch {
      suggested = suggested_ref; // shown as-is; the dialog validates it
    }
    const r = await requestCredential(v(), { suggestedRef: suggested, ctx, type, fields, reason, description, timeoutSec: timeout_seconds });
    applyTags(r.ref, role, isDefault);
    const refStr = formatRef(r.ref);
    return (
      `stored ${refStr} as v${r.version} (${r.created ? "new" : "updated"}${r.fields.length ? `; fields: ${r.fields.join(", ")}` : ""})${tagNote(role, isDefault)}. ` +
      (r.adjustedFrom ? `The user typed "${r.adjustedFrom}", which was corrected to this 4-level path. ` : "") +
      `Use ref "${refStr}"${r.fields.length ? ` (e.g. ${refStr}#${r.fields.includes("username") ? "username" : r.fields[0]})` : ""} with run_with_secrets / http_request / write_env_file.`
    );
  },
);

tool(
  "sealed_fetch",
  "Give a secret to the USER without Claude seeing it: copy to the clipboard (auto-cleared) or show it in a macOS dialog. Use this whenever the user wants to get/see a secret themselves.",
  {
    ref: z.string(),
    mode: z.enum(["clipboard", "dialog"]).default("clipboard"),
    clear_after_seconds: z.number().int().min(0).max(600).default(30).describe("0 = never clear the clipboard"),
    timeout_seconds: z.number().int().min(10).max(600).default(120),
    cwd: cwdArg,
  },
  async ({ ref, mode, clear_after_seconds, timeout_seconds, cwd }) => {
    const ctx = ctxFor(cwd);
    const p = await prepareUse(v(), [ref], ctx, { purpose: `hand ${ref} to the user via ${mode}` });
    const text = await sealedFetch(v(), parseRef(p.remap.get(ref) ?? ref, ctx), {
      mode,
      clearAfterSec: clear_after_seconds,
      timeoutSec: timeout_seconds,
    });
    return p.notes.length ? `${text}\n${p.notes.join("\n")}` : text;
  },
);

// ---------- reveal (opt-in per project) ----------

tool(
  "reveal_secret",
  "Return a plaintext value. Only works for projects where the user enabled reveal via `cvault project reveal <tenant/project> on`.",
  { ref: z.string(), reason: z.string().describe("why the plaintext is needed"), cwd: cwdArg },
  ({ ref, reason, cwd }) => {
    const r = parseRef(ref, ctxFor(cwd));
    if (!v().isRevealAllowed(r.tenant, r.project)) {
      throw new VaultError(
        `reveal is disabled for ${r.tenant}/${r.project}. Use run_with_secrets/write_env_file instead, or ask the user to run: cvault project reveal ${r.tenant}/${r.project} on`,
      );
    }
    if (v().itemStatus(r) === "locked") v().resolveValue(r, "mcp"); // throws the LOCKED explanation
    v().audit("mcp", formatRef(r), `reveal-request: ${reason.slice(0, 200)}`);
    return v().getItem(r, "mcp");
  },
);

tool(
  "audit_log",
  "Show recent vault activity (never contains values).",
  { limit: z.number().int().min(1).max(500).default(50), ref_prefix: z.string().optional() },
  ({ limit, ref_prefix }) => v().auditLog(limit, ref_prefix),
);

await server.connect(new StdioServerTransport());
