import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { decrypt, DEFAULT_KDF, deriveKey, encrypt, type KdfParams } from "./crypto.js";
import { gitStatus, quoteEnv } from "./inject.js";
import { type ItemType, type Ref, Vault, VaultError } from "./store.js";

/**
 * Export / import.
 *  - bundle: passphrase-encrypted (scrypt + AES-256-GCM) JSON with every item incl. files and labels
 *  - env:    plaintext KEY=value (credentials expand to KEY_FIELD, files are skipped)
 *  - json:   plaintext nested JSON
 */

export type ExportFormat = "bundle" | "env" | "json";

export interface ExportItem {
  tenant: string;
  project: string;
  service: string;
  key: string;
  type: ItemType;
  value?: string;
  fields?: Record<string, string>;
  file?: { filename: string; base64: string };
  role?: string;
  default?: boolean;
  description?: string;
  version: number;
}

const BUNDLE_FORMAT = "cvault-bundle";
const BUNDLE_VERSION = 1;
const BUNDLE_AAD = "cvault-bundle:v1";

/** Scope: [] = whole vault, [tenant], [tenant, project] or [tenant, project, service]. */
export function collectItems(vault: Vault, scope: string[], source = "cli:export"): ExportItem[] {
  const [t, p, s] = scope;
  const projects = (vault.listProjects(t) as unknown as Array<{ tenant: string; project: string }>).filter(
    (pr) => !p || pr.project === p,
  );
  if (scope.length >= 2 && !projects.length) throw new VaultError(`project "${t}/${p}" not found or archived`);
  const out: ExportItem[] = [];
  for (const pr of projects) {
    const items = vault.listItems(pr.tenant, pr.project, s) as unknown as Array<{
      ref: string;
      type: ItemType;
      role?: string;
      default?: boolean;
      description?: string;
      version: number;
    }>;
    for (const i of items) {
      const [tenant, project, service, key] = i.ref.split("/");
      const ref: Ref = { tenant, project, service, key };
      const item: ExportItem = { tenant, project, service, key, type: i.type, version: i.version };
      if (i.role) item.role = i.role;
      if (i.default) item.default = true;
      if (i.description) item.description = i.description;
      if (i.type === "file") {
        const f = vault.readFile(ref, source);
        item.file = { filename: f.filename, base64: f.content.toString("base64") };
      } else {
        const got = vault.getItem(ref, source);
        if (i.type === "secret") item.value = got.value as string;
        else item.fields = got.value as Record<string, string>;
      }
      out.push(item);
    }
  }
  vault.audit(source, scope.join("/") || "*", `export ${out.length} items`);
  return out;
}

// ---------- env ----------

const envName = (parts: string[]) =>
  parts
    .join("_")
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/^(\d)/, "_$1");

/**
 * KEY=value lines. Names are built from the path below the export scope, e.g. exporting a
 * project gives STRIPE_API_KEY and ADMIN_PANEL_SUPERADMIN_PASSWORD; exporting a service gives
 * API_KEY and SUPERADMIN_PASSWORD. Throws on name collisions instead of silently overwriting.
 */
export function toEnv(items: ExportItem[], scopeDepth: number): { text: string; count: number; skipped: string[] } {
  const lines: string[] = [];
  const seen = new Map<string, string>();
  const skipped: string[] = [];
  const add = (name: string, value: string, origin: string) => {
    if (seen.has(name)) throw new VaultError(`env name collision: ${name} (from ${seen.get(name)} and ${origin})`);
    seen.set(name, origin);
    lines.push(`${name}=${quoteEnv(value)}`);
  };
  for (const i of items) {
    const path = [i.tenant, i.project, i.service, i.key];
    const origin = path.join("/");
    const base = path.slice(Math.min(scopeDepth, 3));
    if (i.type === "file") skipped.push(origin);
    else if (i.type === "secret") add(envName(base), i.value!, origin);
    else for (const [f, v] of Object.entries(i.fields!)) add(envName([...base, f]), v, `${origin}#${f}`);
  }
  const header = `# exported by cvault on ${new Date().toISOString()} — plaintext secrets, keep this file private\n`;
  return { text: header + lines.join("\n") + "\n", count: lines.length, skipped };
}

// ---------- json ----------

export function toJson(items: ExportItem[]): string {
  const tree: Record<string, any> = {};
  for (const i of items) {
    const node = (((tree[i.tenant] ??= {})[i.project] ??= {})[i.service] ??= {});
    const { tenant, project, service, key, ...rest } = i;
    node[key] = rest;
  }
  return JSON.stringify({ exported_at: new Date().toISOString(), vault: tree }, null, 2) + "\n";
}

// ---------- encrypted bundle ----------

export function encryptBundle(items: ExportItem[], passphrase: string, kdf: KdfParams = DEFAULT_KDF): string {
  if (passphrase.length < 8) throw new VaultError("bundle passphrase must be at least 8 characters");
  const salt = randomBytes(16);
  const key = deriveKey(passphrase, salt, kdf);
  const payload = Buffer.from(JSON.stringify({ items }), "utf8");
  return (
    JSON.stringify(
      {
        format: BUNDLE_FORMAT,
        version: BUNDLE_VERSION,
        created_at: new Date().toISOString(),
        items: items.length,
        kdf: { name: "scrypt", ...kdf },
        salt: salt.toString("base64"),
        data: encrypt(key, payload, BUNDLE_AAD).toString("base64"),
      },
      null,
      2,
    ) + "\n"
  );
}

export function decryptBundle(text: string, passphrase: string): ExportItem[] {
  let doc: { format?: string; version?: number; kdf?: KdfParams; salt?: string; data?: string };
  try {
    doc = JSON.parse(text);
  } catch {
    throw new VaultError("not a cvault bundle (invalid JSON)");
  }
  if (doc.format !== BUNDLE_FORMAT || !doc.salt || !doc.data || !doc.kdf) throw new VaultError("not a cvault bundle");
  if (doc.version !== BUNDLE_VERSION) throw new VaultError(`unsupported bundle version ${doc.version}`);
  const { N, r, p } = doc.kdf;
  const key = deriveKey(passphrase, Buffer.from(doc.salt, "base64"), { N, r, p });
  try {
    return (JSON.parse(decrypt(key, Buffer.from(doc.data, "base64"), BUNDLE_AAD).toString("utf8")) as { items: ExportItem[] }).items;
  } catch {
    throw new VaultError("wrong passphrase or corrupted bundle");
  }
}

/**
 * Import bundle items. `into` optionally remaps the leading segments: ["acme2"] moves every item to
 * tenant acme2; ["acme2", "api"] moves them into that project. Existing items get a new version.
 */
export function importItems(
  vault: Vault,
  items: ExportItem[],
  opts: { into?: string[]; source?: string } = {},
): { imported: number; created: number; updated: number } {
  const source = opts.source ?? "cli:import-bundle";
  let created = 0;
  let updated = 0;
  for (const i of items) {
    const ref: Ref = {
      tenant: opts.into?.[0] ?? i.tenant,
      project: opts.into?.[1] ?? i.project,
      service: i.service,
      key: i.key,
    };
    let exists = true;
    try {
      vault.listVersions(ref);
    } catch {
      exists = false;
    }
    if (i.type === "secret") vault.setSecret(ref, i.value ?? "", i.description, source);
    else if (i.type === "credential") vault.setCredential(ref, i.fields ?? {}, i.description, source);
    else vault.putFileContent(ref, i.file!.filename, Buffer.from(i.file!.base64, "base64"), i.description, source);
    if (i.role || i.default) vault.tagItem(ref, { role: i.role, isDefault: i.default ? true : undefined }, source);
    if (exists) updated++;
    else created++;
  }
  return { imported: items.length, created, updated };
}

// ---------- writing ----------

/** Write export output with mode 0600, refusing plaintext inside a git repo unless gitignored. */
export function writeExport(
  target: string,
  content: string,
  opts: { plaintext: boolean; overwrite: boolean },
): string {
  const abs = resolve(target);
  if (!existsSync(dirname(abs))) throw new VaultError(`directory ${dirname(abs)} does not exist`);
  if (existsSync(abs) && !opts.overwrite) throw new VaultError(`${abs} exists — use --force to overwrite`);
  if (opts.plaintext && gitStatus(abs) === "tracked-or-not-ignored") {
    throw new VaultError(`${abs} is inside a git repo and not gitignored — refusing to write plaintext secrets there`);
  }
  writeFileSync(abs, content, { mode: 0o600 });
  chmodSync(abs, 0o600);
  return abs;
}
