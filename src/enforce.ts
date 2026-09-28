import { approveUse, requestCredential } from "./sealed.js";
import {
  APPROVAL_GRACE_MIN,
  hostAllowed,
  hostsPolicyError,
  isSecretField,
  USE_BUDGET,
  USE_WINDOW_MIN,
} from "./policy.js";
import { formatRef, parseRef, type ProjectCtx, type Ref, type Vault, VaultError } from "./store.js";

/**
 * Server-side enforcement that runs before any tool uses secrets. Unlike instructions to the model,
 * these cannot be skipped:
 *  1. missing items  → the user is asked via dialogs (path + values); refs are remapped if saved elsewhere
 *  2. allowed hosts  → secrets are never sent outside the service's host list
 *  3. use budget     → after USE_BUDGET uses in USE_WINDOW_MIN the user must Allow (or Block = lock)
 *  4. locks          → locked items are refused by the store itself (see Vault.assertUsable)
 */

const sqlTime = (minutesAgo: number) =>
  new Date(Date.now() - minutesAgo * 60_000).toISOString().replace("T", " ").slice(0, 19);
const baseOf = (r: Ref) => formatRef({ ...r, field: undefined, version: undefined });

export interface Prepared {
  /** raw ref string as given by the model → ref string to use instead */
  remap: Map<string, string>;
  /** human-readable notes to append to the tool result */
  notes: string[];
}

export async function prepareUse(
  vault: Vault,
  rawRefs: string[],
  ctx: ProjectCtx | null,
  opts: {
    purpose: string;
    /** destination hosts (undefined = not applicable / checked later) */
    targetHosts?: string[];
    /** don't open dialogs for missing items (e.g. file items can't be typed in) */
    noPrompt?: boolean;
    timeoutSec?: number;
    /** approval prompt (defaults to the native Allow/Block dialog; injectable for tests) */
    approve?: (message: string) => Promise<boolean>;
  },
): Promise<Prepared> {
  const remap = new Map<string, string>();
  const notes: string[] = [];
  const unique = [...new Set(rawRefs)];

  // 1. missing items → ask the user
  const missing = new Map<string, { raws: string[]; fields: Set<string> }>();
  for (const raw of unique) {
    const ref = parseRef(raw, ctx);
    if (vault.itemStatus(ref) !== "missing") continue;
    const base = baseOf(ref);
    const entry = missing.get(base) ?? { raws: [], fields: new Set<string>() };
    entry.raws.push(raw);
    if (ref.field) entry.fields.add(ref.field);
    missing.set(base, entry);
  }
  if (missing.size && opts.noPrompt) {
    throw new VaultError(`${[...missing.keys()].join(", ")} not found in the vault`);
  }
  for (const [base, { raws, fields }] of missing) {
    const wanted = [...fields];
    if (wanted.includes("password") && !wanted.includes("username")) wanted.unshift("username");
    const r = await requestCredential(vault, {
      suggestedRef: base,
      ctx,
      type: wanted.length ? "credential" : "secret",
      fields: wanted.length ? wanted : undefined,
      reason: opts.purpose,
      timeoutSec: opts.timeoutSec ?? 300,
    });
    const newBase = baseOf(r.ref);
    for (const raw of raws) {
      const old = parseRef(raw, ctx);
      remap.set(raw, newBase + (old.field ? `#${old.field}` : ""));
    }
    notes.push(
      `${base} was not in the vault: the user entered it in a dialog${newBase !== base ? ` and saved it at ${newBase}` : ""} (v${r.version}).`,
    );
  }

  const finalRefs = unique.map((raw) => parseRef(remap.get(raw) ?? raw, ctx));

  // 2. allowed hosts per service
  if (opts.targetHosts) checkHosts(vault, finalRefs, opts.targetHosts);

  // 3. use budget for secret-like values (usernames don't count)
  const budgeted = new Set<string>();
  for (const ref of finalRefs) {
    if (ref.field && !isSecretField(ref.field)) continue;
    const key = formatRef({ ...ref, version: undefined });
    if (budgeted.has(key) || vault.itemStatus(ref) !== "ok") continue;
    budgeted.add(key);
    const approved = vault.lastApproval(ref);
    if (approved && approved >= sqlTime(APPROVAL_GRACE_MIN)) continue;
    const uses = vault.countUses(ref, sqlTime(USE_WINDOW_MIN));
    if (uses < USE_BUDGET) continue;
    const ok = await (opts.approve ?? approveUse)(
      `Claude wants to use ${key} again (${uses} times in the last ${USE_WINDOW_MIN} minutes).\n\n` +
        `Purpose: ${opts.purpose}\n\n` +
        `Repeated use often means failing logins - accounts may get locked.\n` +
        `Allow = ${APPROVAL_GRACE_MIN} more minutes of use.  Block = lock this credential.`,
    );
    if (ok) {
      vault.audit("user", key, "use-approved");
      notes.push(`the user approved further use of ${key} for ${APPROVAL_GRACE_MIN} minutes.`);
    } else {
      vault.lockItem(ref, "blocked by the user after repeated use", "user");
      throw new VaultError(
        `the user blocked further use of ${key} and it is now LOCKED. Stop and ask the user what to do; do not retry.`,
      );
    }
  }

  return { remap, notes };
}

/** Throw if any target host is outside the allowed-hosts list of a service whose secrets are used. */
export function checkHosts(vault: Vault, refs: Ref[], targetHosts: string[]): void {
  const seen = new Set<string>();
  for (const ref of refs) {
    const svc = `${ref.tenant}/${ref.project}/${ref.service}`;
    if (seen.has(svc)) continue;
    seen.add(svc);
    const allowed = vault.allowedHosts(ref.tenant, ref.project, ref.service);
    if (!allowed.length) continue;
    const offending = targetHosts.filter((h) => !hostAllowed(h, allowed));
    if (offending.length) {
      vault.audit("policy", svc, `blocked host ${offending.join(",")}`);
      throw new VaultError(hostsPolicyError(svc, allowed, offending));
    }
  }
}

/** Rewrite {{secret:ref}} placeholders according to `remap`. */
export function remapPlaceholders(text: string, remap: Map<string, string>, placeholder: RegExp): string {
  if (!remap.size) return text;
  return text.replace(placeholder, (m, ref: string) => (remap.has(ref) ? `{{secret:${remap.get(ref)}}}` : m));
}

/** Lock every item used in a request that the target rejected with 401. */
export function lockRejected(vault: Vault, rawRefs: string[], ctx: ProjectCtx | null, host: string): string[] {
  const locked = new Set<string>();
  for (const raw of rawRefs) {
    const ref = parseRef(raw, ctx);
    const base = baseOf(ref);
    if (locked.has(base) || vault.itemStatus(ref) !== "ok") continue;
    vault.lockItem(ref, `rejected by ${host} (HTTP 401)`, "policy");
    locked.add(base);
  }
  return [...locked];
}
