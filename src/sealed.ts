import { spawn } from "node:child_process";
import { formatRef, parseRef, type ProjectCtx, type Ref, type Vault, VaultError } from "./store.js";

/**
 * "Sealed" operations: the secret travels between the user and the vault through native macOS
 * UI (dialog / clipboard) and never appears in tool input or output, so the model never sees it.
 * Values are handed to osascript via an env var, not argv, so they don't show up in `ps`.
 */

interface OsaResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function osascript(script: string, env: Record<string, string>): Promise<OsaResult> {
  if (process.platform !== "darwin") throw new VaultError("sealed operations need macOS (osascript)");
  return new Promise((done) => {
    const child = spawn("osascript", ["-"], { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", ...env } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
    child.on("close", (code) => done({ code, stdout: stdout.replace(/\n$/, ""), stderr }));
    child.stdin.end(script);
  });
}

/**
 * \`system attribute\` decodes env vars as MacRoman, which garbles UTF-8 (— ⚠ é …). Reading them
 * through the shell's printf builtin returns proper UTF-8 text (and keeps the value off argv).
 */
const ENV_TEXT_HANDLER = `
on envText(varName)
  return do shell script "printf %s \\"$" & varName & "\\"" without altering line endings
end envText
`;

const ASK_SCRIPT = `${ENV_TEXT_HANDLER}
set theTitle to envText("CVAULT_TITLE")
set theMsg to envText("CVAULT_MSG")
set theDefault to envText("CVAULT_DEFAULT")
set okButton to envText("CVAULT_OK")
set secs to (system attribute "CVAULT_SECS") as integer
set isHidden to ((system attribute "CVAULT_HIDDEN") is "1")
tell me to activate
if isHidden then
  set r to display dialog theMsg default answer theDefault with hidden answer with title theTitle buttons {"Cancel", okButton} default button okButton cancel button "Cancel" with icon caution giving up after secs
else
  set r to display dialog theMsg default answer theDefault with title theTitle buttons {"Cancel", okButton} default button okButton cancel button "Cancel" with icon note giving up after secs
end if
if gave up of r then return "GAVE_UP"
return "OK:" & (text returned of r)
`;

/** Thrown when the user cancels a dialog or lets it time out. */
export class DialogCancelled extends Error {
  constructor(readonly reason: "cancelled" | "timed out") {
    super(reason === "cancelled" ? "user cancelled the dialog" : "user did not respond (dialog timed out)");
  }
}

/** One native macOS input dialog. Returns the entered text; throws DialogCancelled. */
async function ask(opts: { title: string; message: string; defaultAnswer?: string; hidden: boolean; ok: string; timeoutSec: number }): Promise<string> {
  const r = await osascript(ASK_SCRIPT, {
    CVAULT_TITLE: opts.title,
    CVAULT_MSG: opts.message,
    CVAULT_DEFAULT: opts.defaultAnswer ?? "",
    CVAULT_OK: opts.ok,
    CVAULT_HIDDEN: opts.hidden ? "1" : "0",
    CVAULT_SECS: String(opts.timeoutSec),
  });
  if (r.code !== 0) {
    if (/-128/.test(r.stderr)) throw new DialogCancelled("cancelled");
    throw new VaultError(`dialog failed: ${r.stderr.trim().slice(0, 200)}`);
  }
  if (r.stdout === "GAVE_UP") throw new DialogCancelled("timed out");
  return r.stdout.slice(3);
}

const NOTICE_SCRIPT = `${ENV_TEXT_HANDLER}
set theMsg to envText("CVAULT_MSG")
set secs to (system attribute "CVAULT_SECS") as integer
tell me to activate
display dialog theMsg with title "cvault" buttons {"OK"} default button "OK" with icon caution giving up after secs
`;

const APPROVE_SCRIPT = `${ENV_TEXT_HANDLER}
set theTitle to envText("CVAULT_TITLE")
set theMsg to envText("CVAULT_MSG")
set allowLabel to envText("CVAULT_ALLOW")
set denyLabel to envText("CVAULT_DENY")
set secs to (system attribute "CVAULT_SECS") as integer
tell me to activate
set r to display dialog theMsg with title theTitle buttons {denyLabel, allowLabel} default button denyLabel cancel button denyLabel with icon caution giving up after secs
if gave up of r then return "GAVE_UP"
return button returned of r
`;

/** Generic Allow/Deny dialog. Deny, Cancel and timeout all mean "no". */
export async function askAllow(opts: { title: string; message: string; allow?: string; deny?: string; timeoutSec?: number }): Promise<boolean> {
  const allow = opts.allow ?? "Allow";
  const r = await osascript(APPROVE_SCRIPT, {
    CVAULT_TITLE: opts.title,
    CVAULT_MSG: opts.message,
    CVAULT_ALLOW: allow,
    CVAULT_DENY: opts.deny ?? "Deny",
    CVAULT_SECS: String(opts.timeoutSec ?? 120),
  });
  return r.code === 0 && r.stdout === allow;
}

/** Ask the user to allow another use of a secret. Block, Cancel and timeout all mean "no". */
export function approveUse(message: string, timeoutSec = 120): Promise<boolean> {
  return askAllow({ title: "cvault - allow again?", message, allow: "Allow", deny: "Block", timeoutSec });
}

/** Informational dialog (e.g. "entries did not match"). */
async function notice(message: string, timeoutSec: number): Promise<void> {
  await osascript(NOTICE_SCRIPT, { CVAULT_MSG: message, CVAULT_SECS: String(Math.min(timeoutSec, 60)) });
}

const isSecretField = (name: string) => /pass|secret|token|key|pin|otp|pwd/i.test(name);

/**
 * Best-effort fix for a path the user typed. Inside a linked project the tenant/project names are
 * recognised wherever they appear and everything else before the key becomes the service
 * (rezilens/develop/digrc-api-service/admin-panel/key -> rezilens/digrc-api-service/develop-admin-panel/key).
 * Without a linked project, levels 3..n-1 are folded into the service. Invalid characters become "-".
 * Returns null when nothing sensible can be derived.
 */
export function suggestPath(answer: string, ctx: ProjectCtx | null): string | null {
  const [path, field] = answer.split("#", 2);
  const parts = path.split("/").map((s) => s.trim()).filter(Boolean);
  const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[-._]+|-+$/g, "");
  const keyOf = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-._]+|-+$/g, "");
  if (parts.length < 2) return null;
  const key = parts[parts.length - 1];
  const rest = parts.slice(0, -1);
  let tenant: string;
  let project: string;
  let env: string | undefined;
  let service: string;
  const fromMiddle = (middle: string[]) => {
    // [service] | [env, service] | [env, service, more…] (extra levels fold into the service)
    if (middle.length === 1) return { env: undefined, service: middle[0] };
    return { env: middle[0], service: middle.slice(1).join("-") };
  };
  if (ctx && (rest.includes(ctx.tenant) || rest.includes(ctx.project) || rest.length <= 2)) {
    // inside a linked project: tenant/project names are recognised wherever they were typed
    tenant = ctx.tenant;
    project = ctx.project;
    const middle = rest.filter((p) => p !== ctx.tenant && p !== ctx.project);
    if (!middle.length) return null;
    ({ env, service } = fromMiddle(middle));
  } else if (rest.length === 3) {
    [tenant, project, service] = rest;
  } else if (rest.length >= 4) {
    [tenant, env, project] = rest;
    service = rest.slice(3).join("-");
  } else {
    return null;
  }
  const fixed = [slug(tenant), env ? slug(env) : null, slug(project), slug(service), keyOf(key)].filter((x) => x !== null) as string[];
  if (fixed.some((p) => !p)) return null;
  const s = fixed.join("/") + (field ? `#${field}` : "");
  return s === answer ? null : s;
}

function pathError(answer: string, e: Error, ctx: ProjectCtx | null): string {
  const levels = answer.split("#")[0].split("/").filter(Boolean).length;
  if (levels > 5) return `A path has at most 5 levels: tenant / env / project / service / key (you entered ${levels}).`;
  if (levels < 4 && !ctx) return "Use tenant/env/project/service/key (this directory is not linked to a project, so a short path is not enough).";
  return e.message.replace(/ \(expected .*\)$/, "");
}

/**
 * Ask the user where to save (pre-filled with Claude's suggestion). If the typed path is invalid
 * but its intent is clear (extra levels, spaces, capitals), the corrected path is accepted right
 * away - no second dialog - and reported back via `adjustedFrom`. Only when nothing sensible can
 * be derived does the dialog re-open with a plain-language error.
 */
async function askPath(opts: {
  intro: string;
  suggested: string;
  ctx: ProjectCtx | null;
  allowField: boolean;
  timeoutSec: number;
  /** extra semantic check (e.g. project/environment swapped); return an error message to reject */
  validate?: (ref: Ref) => string | null;
}): Promise<{ ref: Ref; adjustedFrom?: string }> {
  const format = `tenant/env/project/service/key${opts.allowField ? "[#field]" : ""}  (env is optional)`;
  const shortHint = opts.ctx ? `\n(inside ${opts.ctx.tenant}/${opts.ctx.project} also: env/service/key or service/key)` : "";
  const valid = (ref: Ref) => !ref.version && (!ref.field || opts.allowField) && !opts.validate?.(ref);
  let answer = opts.suggested;
  let error = "";
  for (let attempt = 0; attempt < 5; attempt++) {
    answer = (
      await ask({
        title: "cvault - where should it be saved?",
        message: `${opts.intro}\n\nPath: ${format}${shortHint}${error ? `\n\n! ${error}` : ""}`,
        defaultAnswer: answer,
        hidden: false,
        ok: "Next",
        timeoutSec: opts.timeoutSec,
      })
    ).trim();
    try {
      const ref = parseRef(answer, opts.ctx);
      if (ref.version) throw new VaultError("Don't include @version - saving always creates a new version.");
      if (ref.field && !opts.allowField) throw new VaultError("Don't include #field here - you'll be asked for each field next.");
      const problem = opts.validate?.(ref);
      if (problem) throw new Error(problem);
      return { ref };
    } catch (e) {
      const explicit = e instanceof VaultError && /^Don't/.test(e.message);
      const fix = explicit ? null : suggestPath(answer, opts.ctx);
      if (fix) {
        try {
          const ref = parseRef(fix, opts.ctx);
          if (valid(ref)) return { ref, adjustedFrom: answer };
        } catch {
          /* fall through to re-asking */
        }
      }
      error = explicit ? (e as Error).message : pathError(answer, e as Error, opts.ctx);
    }
  }
  throw new VaultError(`not saved: invalid path "${answer}" (${error.split("\n")[0]})`);
}

const SHOW_SCRIPT = `${ENV_TEXT_HANDLER}
set theTitle to envText("CVAULT_TITLE")
set theMsg to envText("CVAULT_MSG")
set secs to (system attribute "CVAULT_SECS") as integer
tell me to activate
set r to display dialog theMsg with title theTitle buttons {"Copy", "Done"} default button "Done" giving up after secs
if gave up of r then return "GAVE_UP"
return button returned of r
`;

function pbcopy(value: string): Promise<void> {
  return new Promise((done, fail) => {
    const child = spawn("pbcopy");
    child.on("error", fail);
    child.on("close", () => done());
    child.stdin.end(value);
  });
}

function pbpaste(): Promise<string> {
  return new Promise((done) => {
    const child = spawn("pbpaste");
    let out = "";
    child.stdout.on("data", (c: Buffer) => (out += c.toString("utf8")));
    child.on("close", () => done(out));
    child.on("error", () => done(""));
  });
}

/** Copy to clipboard, then clear it after `clearAfterSec` if it still holds the same value. */
async function copyWithAutoClear(value: string, clearAfterSec: number): Promise<void> {
  await pbcopy(value);
  if (clearAfterSec > 0) {
    setTimeout(async () => {
      if ((await pbpaste()) === value) await pbcopy("");
    }, clearAfterSec * 1000);
  }
}

const CLEAR_SCRIPT = `
const { execFileSync } = require("child_process");
setTimeout(() => {
  try {
    if (execFileSync("pbpaste").toString() === process.env.CVAULT_CLIP) execFileSync("pbcopy", { input: "" });
  } catch {}
}, Number(process.env.CVAULT_SECS) * 1000);
`;

/**
 * Copy to clipboard for short-lived processes (the CLI): the auto-clear runs in a detached helper
 * process, so it still happens after the CLI exits. The value is handed over via env (same-user only).
 */
export async function copyToClipboard(value: string, clearAfterSec: number): Promise<void> {
  if (process.platform !== "darwin") throw new VaultError("clipboard needs macOS (pbcopy)");
  await pbcopy(value);
  if (clearAfterSec > 0) {
    spawn(process.execPath, ["-e", CLEAR_SCRIPT], {
      detached: true,
      stdio: "ignore",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", CVAULT_CLIP: value, CVAULT_SECS: String(clearAfterSec) },
    }).unref();
  }
}

// ---------- tools ----------

/** Existing item (if any) at `ref`, for "leave empty to keep" behaviour. */
function existing(vault: Vault, ref: Ref): { type: string; version: number; fields?: Record<string, string> } | null {
  try {
    const item = vault.getItem({ ...ref, field: undefined, version: undefined }, "mcp:request");
    return { type: item.type, version: item.version, fields: typeof item.value === "string" ? undefined : item.value };
  } catch (e) {
    if (e instanceof VaultError && /not found/.test(e.message)) return null;
    if (e instanceof VaultError && /is a file/.test(e.message)) return { type: "file", version: 0 };
    throw e;
  }
}

/** Reject paths whose project doesn't exist but whose environment slot names an existing project (swapped order). */
function swappedProject(vault: Vault) {
  return (ref: Ref): string | null => {
    if (!ref.env) return null;
    const projects = (vault.listProjects(ref.tenant) as unknown as Array<{ project: string }>).map((p) => p.project);
    if (!projects.includes(ref.project) && projects.includes(ref.env)) {
      return `"${ref.env}" is a project and "${ref.project}" looks like an environment - the order is tenant/env/project/service/key.`;
    }
    return null;
  };
}

/**
 * Collect a missing credential/secret from the user through native dialogs: first the path
 * (pre-filled, editable), then each field. Values never reach the model.
 */
export async function requestCredential(
  vault: Vault,
  opts: {
    suggestedRef?: string;
    ctx: ProjectCtx | null;
    type: "credential" | "secret";
    fields?: string[];
    reason?: string;
    description?: string;
    timeoutSec: number;
  },
): Promise<{ ref: Ref; version: number; fields: string[]; created: boolean; adjustedFrom?: string }> {
  try {
    const what = opts.type === "credential" ? "a login / credential" : "a secret";
    const intro = `Claude needs ${what}${opts.reason ? ` to ${opts.reason}` : ""}.\nIt is saved in your encrypted vault - Claude never sees the values.`;
    const suggested =
      opts.suggestedRef ?? (opts.ctx ? `${opts.ctx.tenant}/${opts.ctx.project}/service/key` : "tenant/project/service/key");
    const { ref, adjustedFrom } = await askPath({
      intro,
      suggested,
      ctx: opts.ctx,
      allowField: false,
      timeoutSec: opts.timeoutSec,
      validate: swappedProject(vault),
    });
    const target = formatRef(ref);
    const prev = existing(vault, ref);
    if (prev && prev.type !== (opts.type === "credential" ? "credential" : "secret")) {
      throw new VaultError(`${target} already exists as a ${prev.type}; pick another path`);
    }

    if (opts.type === "secret") {
      let value = "";
      for (;;) {
        value = await ask({
          title: `cvault - ${target}`,
          message: `Value for ${target}${prev ? `\n(exists as v${prev.version} - a new version will be saved)` : ""}`,
          hidden: true,
          ok: "Next",
          timeoutSec: opts.timeoutSec,
        });
        if (!value) continue;
        const again = await ask({ title: `cvault - ${target}`, message: `Re-enter the value for ${target} to confirm`, hidden: true, ok: "Save", timeoutSec: opts.timeoutSec });
        if (again === value) break;
        await notice("The two entries did not match - please enter it again.", opts.timeoutSec);
      }
      const version = vault.setSecret(ref, value, opts.description, "mcp:request");
      return { ref, version, fields: [], created: !prev, adjustedFrom };
    }

    const names = [...new Set(opts.fields?.length ? opts.fields : prev?.fields ? Object.keys(prev.fields) : ["username", "password"])];
    const fields: Record<string, string> = { ...(prev?.fields ?? {}) };
    for (const [i, name] of names.entries()) {
      const hidden = isSecretField(name);
      const current = prev?.fields?.[name];
      const last = i === names.length - 1;
      let value = "";
      for (;;) {
        value = await ask({
          title: `cvault - ${target} (${i + 1}/${names.length})`,
          message: `${name} for ${target}${current !== undefined ? "\n(leave empty to keep the current value)" : hidden ? "" : "\n(optional - leave empty to skip)"}`,
          defaultAnswer: !hidden && current ? current : "",
          hidden,
          ok: last ? "Save" : "Next",
          timeoutSec: opts.timeoutSec,
        });
        if (!value && (current !== undefined || !hidden)) break; // kept / optional
        if (!value) continue; // secret fields are required for new items
        if (!hidden) break;
        // masked input: ask again so a typo can't be saved silently
        const again = await ask({
          title: `cvault - ${target} (${i + 1}/${names.length})`,
          message: `Re-enter ${name} for ${target} to confirm`,
          hidden: true,
          ok: last ? "Save" : "Next",
          timeoutSec: opts.timeoutSec,
        });
        if (again === value) break;
        await notice(`The two ${name} entries did not match - please enter it again.`, opts.timeoutSec);
      }
      if (value) fields[name] = value;
    }
    if (!Object.keys(fields).length) throw new VaultError("nothing entered - not saved");
    const version = vault.setCredential(ref, fields, opts.description, "mcp:request");
    return { ref, version, fields: Object.keys(fields), created: !prev, adjustedFrom };
  } catch (e) {
    if (e instanceof DialogCancelled) throw new VaultError(`not saved: ${e.message}`);
    throw e;
  }
}

export async function sealedSave(
  vault: Vault,
  suggested: Ref | null,
  opts: { description?: string; confirm: boolean; timeoutSec: number; ctx: ProjectCtx | null },
): Promise<{ text: string; ref?: Ref }> {
  let ref: Ref;
  let adjustedFrom: string | undefined;
  let value: string;
  try {
    ({ ref, adjustedFrom } = await askPath({
      intro: "Save a secret into your encrypted vault - Claude never sees the value.\nUse key#field to set one field of a credential.",
      suggested: suggested ? formatRef(suggested) : opts.ctx ? `${opts.ctx.tenant}/${opts.ctx.project}/service/key` : "tenant/project/service/key",
      ctx: opts.ctx,
      allowField: true,
      timeoutSec: opts.timeoutSec,
      validate: swappedProject(vault),
    }));
    const what = ref.field ? `field "${ref.field}" of ${formatRef({ ...ref, field: undefined })}` : formatRef(ref);
    value = await ask({ title: "cvault - save secret", message: `Enter the value for ${what}.`, hidden: true, ok: "Save", timeoutSec: opts.timeoutSec });
    if (!value) return { text: "not saved: empty value" };
    if (opts.confirm) {
      const again = await ask({ title: "cvault - confirm", message: `Re-enter the value for ${what}.`, hidden: true, ok: "Save", timeoutSec: opts.timeoutSec });
      if (again !== value) return { text: "not saved: values did not match" };
    }
  } catch (e) {
    if (e instanceof DialogCancelled) return { text: `not saved: ${e.message}` };
    throw e;
  }
  const target = formatRef(ref);
  const adj = adjustedFrom ? ` (user typed "${adjustedFrom}", saved at the corrected path)` : "";

  if (ref.field) {
    // update a single credential field, keeping the others
    let fields: Record<string, string> = {};
    let exists = true;
    try {
      const item = vault.getItem({ ...ref, field: undefined }, "mcp:sealed");
      if (item.type !== "credential") throw new VaultError(`${formatRef({ ...ref, field: undefined })} is a ${item.type}, not a credential`);
      fields = item.value as Record<string, string>;
    } catch (e) {
      if (!(e instanceof VaultError) || !/not found/.test(e.message)) throw e;
      exists = false;
    }
    fields[ref.field] = value;
    const ver = vault.setCredential({ ...ref, field: undefined }, fields, opts.description, "mcp:sealed");
    return { text: `stored ${target} as v${ver} (${exists ? "updated field" : "new credential"}; fields: ${Object.keys(fields).join(", ")})${adj}`, ref };
  }
  return { text: `stored ${target} as v${vault.setSecret(ref, value, opts.description, "mcp:sealed")}${adj}`, ref };
}

export async function sealedFetch(
  vault: Vault,
  ref: Ref,
  opts: { mode: "clipboard" | "dialog"; clearAfterSec: number; timeoutSec: number },
): Promise<string> {
  const value = vault.resolveValue(ref, "mcp:sealed");
  const target = formatRef(ref);
  if (opts.mode === "clipboard") {
    await copyWithAutoClear(value, opts.clearAfterSec);
    vault.audit("mcp:sealed", target, "copy-to-clipboard");
    return `copied ${target} to the clipboard${opts.clearAfterSec > 0 ? ` (auto-clears in ${opts.clearAfterSec}s)` : ""}`;
  }
  const r = await osascript(SHOW_SCRIPT, {
    CVAULT_TITLE: `cvault - ${target}`,
    CVAULT_MSG: value,
    CVAULT_SECS: String(opts.timeoutSec),
  });
  vault.audit("mcp:sealed", target, "show-dialog");
  if (r.code !== 0) throw new VaultError(`dialog failed: ${r.stderr.trim().slice(0, 200)}`);
  if (r.stdout === "Copy") {
    await copyWithAutoClear(value, opts.clearAfterSec);
    return `shown to the user in a dialog; user copied it to the clipboard (auto-clears in ${opts.clearAfterSec}s)`;
  }
  return r.stdout === "GAVE_UP" ? "dialog shown, closed after timeout" : "shown to the user in a dialog";
}
