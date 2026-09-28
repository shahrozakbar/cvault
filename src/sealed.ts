import { spawn } from "node:child_process";
import { formatRef, type Ref, type Vault, VaultError } from "./store.js";

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

const INPUT_SCRIPT = `
set theTitle to system attribute "CVAULT_TITLE"
set theMsg to system attribute "CVAULT_MSG"
set secs to (system attribute "CVAULT_SECS") as integer
tell me to activate
set r to display dialog theMsg default answer "" with hidden answer with title theTitle buttons {"Cancel", "Save"} default button "Save" cancel button "Cancel" with icon caution giving up after secs
if gave up of r then return "GAVE_UP"
return "OK:" & (text returned of r)
`;

const SHOW_SCRIPT = `
set theTitle to system attribute "CVAULT_TITLE"
set theMsg to system attribute "CVAULT_MSG"
set secs to (system attribute "CVAULT_SECS") as integer
tell me to activate
set r to display dialog theMsg with title theTitle buttons {"Copy", "Done"} default button "Done" giving up after secs
if gave up of r then return "GAVE_UP"
return button returned of r
`;

async function promptSecret(title: string, message: string, timeoutSec: number): Promise<string | "cancelled" | "timed out"> {
  const r = await osascript(INPUT_SCRIPT, { CVAULT_TITLE: title, CVAULT_MSG: message, CVAULT_SECS: String(timeoutSec) });
  if (r.code !== 0) {
    if (/-128/.test(r.stderr)) return "cancelled";
    throw new VaultError(`dialog failed: ${r.stderr.trim().slice(0, 200)}`);
  }
  if (r.stdout === "GAVE_UP") return "timed out";
  return r.stdout.slice(3);
}

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

export async function sealedSave(
  vault: Vault,
  ref: Ref,
  opts: { description?: string; confirm: boolean; timeoutSec: number },
): Promise<string> {
  const target = formatRef(ref);
  const what = ref.field ? `field "${ref.field}" of ${formatRef({ ...ref, field: undefined })}` : target;
  const value = await promptSecret("cvault — save secret", `Enter the value for ${what}.\n\nIt goes straight into the vault; Claude will not see it.`, opts.timeoutSec);
  if (value === "cancelled" || value === "timed out") return `not saved: user ${value === "cancelled" ? "cancelled" : "did not respond (timed out)"}`;
  if (!value) return "not saved: empty value";
  if (opts.confirm) {
    const again = await promptSecret("cvault — confirm", `Re-enter the value for ${what}.`, opts.timeoutSec);
    if (again !== value) return "not saved: values did not match";
  }

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
    return `stored ${target} as v${ver} (${exists ? "updated field" : "new credential"}; fields: ${Object.keys(fields).join(", ")})`;
  }
  return `stored ${target} as v${vault.setSecret(ref, value, opts.description, "mcp:sealed")}`;
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
    CVAULT_TITLE: `cvault — ${target}`,
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
