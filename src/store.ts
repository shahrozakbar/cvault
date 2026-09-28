import type Database from "better-sqlite3";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { decrypt, DEFAULT_KDF, deriveKey, encrypt, type KdfParams, randomKey } from "./crypto.js";
import { openDb, vaultHome } from "./db.js";

export type ItemType = "secret" | "credential" | "file";

/** Fully-qualified pointer to an item: tenant/project/service/key[@version][#field]. */
export interface Ref {
  tenant: string;
  project: string;
  service: string;
  key: string;
  field?: string;
  version?: number;
}

export interface ProjectCtx {
  tenant: string;
  project: string;
}

export class VaultError extends Error {}

const SLUG = /^[a-z0-9][a-z0-9._-]*$/;
const KEY = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DEK_AAD = "vault-mcp:dek:v1";
const MAX_FILE_BYTES = 25 * 1024 * 1024;

/** Absolute path with symlinks resolved when it exists (macOS /tmp → /private/tmp). */
function canonical(dir: string): string {
  const abs = resolve(dir);
  try {
    return realpathSync(abs);
  } catch {
    return abs;
  }
}

function checkSlug(kind: string, s: string): string {
  if (!SLUG.test(s)) throw new VaultError(`invalid ${kind} "${s}" (lowercase letters, digits, . _ - only)`);
  return s;
}

export function formatRef(r: Ref): string {
  return `${r.tenant}/${r.project}/${r.service}/${r.key}${r.version ? `@${r.version}` : ""}${r.field ? `#${r.field}` : ""}`;
}

/**
 * Parse "tenant/project/service/key[@version][#field]". When a project context is known (e.g. from
 * the current directory), the short form "service/key[@version][#field]" is also accepted.
 */
export function parseRef(input: string, ctx?: ProjectCtx | null): Ref {
  const [pathPart, field] = input.trim().split("#", 2);
  let path = pathPart;
  let version: number | undefined;
  const vm = /^(.*)@(\d+)$/.exec(path);
  if (vm) {
    path = vm[1];
    version = parseInt(vm[2], 10);
    if (version < 1) throw new VaultError(`invalid version in "${input}"`);
  }
  const parts = path.split("/").filter(Boolean);
  let ref: Ref;
  if (parts.length === 4) {
    ref = { tenant: parts[0], project: parts[1], service: parts[2], key: parts[3] };
  } else if (parts.length === 2 && ctx) {
    ref = { tenant: ctx.tenant, project: ctx.project, service: parts[0], key: parts[1] };
  } else if (parts.length === 2) {
    throw new VaultError(`"${input}" is a short ref but no project is bound to the current directory; use tenant/project/service/key`);
  } else {
    throw new VaultError(`invalid ref "${input}" (expected tenant/project/service/key[@version][#field])`);
  }
  checkSlug("tenant", ref.tenant);
  checkSlug("project", ref.project);
  checkSlug("service", ref.service);
  if (!KEY.test(ref.key)) throw new VaultError(`invalid key "${ref.key}"`);
  if (field) ref.field = field;
  if (version) ref.version = version;
  return ref;
}

/** Parse "tenant" or "tenant/project" or "tenant/project/service" scope strings. */
export function parseScope(input: string): string[] {
  const parts = input.split("/").filter(Boolean);
  if (parts.length === 0 || parts.length > 3) throw new VaultError(`invalid scope "${input}"`);
  parts.forEach((p) => checkSlug("segment", p));
  return parts;
}

/** Parse an archive/restore target: tenant, tenant/project, tenant/project/service or a full item ref. */
export function parseTarget(input: string): string[] {
  const parts = input.split("/").filter(Boolean);
  if (parts.length === 4) {
    const r = parseRef(input);
    if (r.version || r.field) throw new VaultError("archive/restore targets cannot have @version or #field");
    return [r.tenant, r.project, r.service, r.key];
  }
  return parseScope(input);
}

interface ItemRow {
  id: number;
  uid: string;
  key: string;
  type: ItemType;
  data: Buffer | null;
  meta: string;
  version: number;
  source: string | null;
  updated_at: string;
  archived_at: string | null;
}

interface Loaded {
  type: ItemType;
  meta: Record<string, unknown>;
  plain: Buffer;
  version: number;
}

export class Vault {
  private constructor(
    readonly db: Database.Database,
    private dek: Buffer,
    readonly home: string,
  ) {}

  // ---------- lifecycle ----------

  static isInitialized(home = vaultHome()): boolean {
    if (!existsSync(join(home, "vault.db"))) return false;
    const db = openDb(home);
    try {
      return !!db.prepare("SELECT 1 FROM meta WHERE key = 'wrapped_dek'").get();
    } finally {
      db.close();
    }
  }

  static init(password: string, opts: { home?: string; kdf?: KdfParams } = {}): Vault {
    const home = opts.home ?? vaultHome();
    if (password.length < 8) throw new VaultError("master password must be at least 8 characters");
    const db = openDb(home);
    if (db.prepare("SELECT 1 FROM meta WHERE key = 'wrapped_dek'").get()) {
      db.close();
      throw new VaultError(`vault already initialized at ${home}`);
    }
    const kdf = opts.kdf ?? DEFAULT_KDF;
    const salt = randomBytes(16);
    const dek = randomKey();
    const kek = deriveKey(password, salt, kdf);
    const put = db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)");
    db.transaction(() => {
      put.run("version", Buffer.from("1"));
      put.run("kdf", Buffer.from(JSON.stringify(kdf)));
      put.run("salt", salt);
      put.run("wrapped_dek", encrypt(kek, dek, DEK_AAD));
    })();
    const v = new Vault(db, dek, home);
    v.audit("cli", null, "init");
    return v;
  }

  static open(password: string, opts: { home?: string } = {}): Vault {
    const home = opts.home ?? vaultHome();
    const db = openDb(home);
    const get = (k: string) => (db.prepare("SELECT value FROM meta WHERE key = ?").get(k) as { value: Buffer } | undefined)?.value;
    const wrapped = get("wrapped_dek");
    if (!wrapped) {
      db.close();
      throw new VaultError(`vault not initialized at ${home} — run \`cvault init\``);
    }
    const kdf = JSON.parse(get("kdf")!.toString()) as KdfParams;
    const kek = deriveKey(password, get("salt")!, kdf);
    try {
      return new Vault(db, decrypt(kek, wrapped, DEK_AAD), home);
    } catch {
      db.close();
      throw new VaultError("wrong master password");
    }
  }

  /**
   * Open for metadata only (names, types, bindings — all stored unencrypted) without the master
   * password. Any attempt to decrypt a value fails. Used by the SessionStart hook.
   */
  static openMetadata(opts: { home?: string } = {}): Vault {
    const home = opts.home ?? vaultHome();
    if (!existsSync(join(home, "vault.db"))) throw new VaultError(`no vault at ${home}`);
    const v = new Vault(openDb(home), Buffer.alloc(0), home);
    v.metadataOnly = true;
    return v;
  }

  private metadataOnly = false;

  changePassword(newPassword: string): void {
    if (newPassword.length < 8) throw new VaultError("master password must be at least 8 characters");
    const salt = randomBytes(16);
    const kek = deriveKey(newPassword, salt, DEFAULT_KDF);
    const put = this.db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)");
    this.db.transaction(() => {
      put.run("kdf", Buffer.from(JSON.stringify(DEFAULT_KDF)));
      put.run("salt", salt);
      put.run("wrapped_dek", encrypt(kek, this.dek, DEK_AAD));
    })();
    this.audit("cli", null, "change-password");
  }

  close(): void {
    this.dek.fill(0);
    this.db.close();
  }

  // ---------- hierarchy ----------

  ensureTenant(tenant: string, name?: string): number {
    checkSlug("tenant", tenant);
    this.db.prepare("INSERT INTO tenants (slug, name) VALUES (?, ?) ON CONFLICT(slug) DO NOTHING").run(tenant, name ?? null);
    const row = this.db.prepare("SELECT id, archived_at FROM tenants WHERE slug = ?").get(tenant) as { id: number; archived_at: string | null };
    if (row.archived_at) throw new VaultError(`tenant "${tenant}" is archived — restore it first`);
    if (name) this.db.prepare("UPDATE tenants SET name = ? WHERE id = ?").run(name, row.id);
    return row.id;
  }

  ensureProject(tenant: string, project: string, name?: string): number {
    checkSlug("project", project);
    const tid = this.ensureTenant(tenant);
    this.db
      .prepare("INSERT INTO projects (tenant_id, slug, name) VALUES (?, ?, ?) ON CONFLICT(tenant_id, slug) DO NOTHING")
      .run(tid, project, name ?? null);
    const row = this.db.prepare("SELECT id, archived_at FROM projects WHERE tenant_id = ? AND slug = ?").get(tid, project) as {
      id: number;
      archived_at: string | null;
    };
    if (row.archived_at) throw new VaultError(`project "${tenant}/${project}" is archived — restore it first`);
    if (name) this.db.prepare("UPDATE projects SET name = ? WHERE id = ?").run(name, row.id);
    return row.id;
  }

  ensureService(
    tenant: string,
    project: string,
    service: string,
    info: { name?: string; url?: string; notes?: string } = {},
  ): number {
    checkSlug("service", service);
    const pid = this.ensureProject(tenant, project);
    this.db
      .prepare("INSERT INTO services (project_id, slug) VALUES (?, ?) ON CONFLICT(project_id, slug) DO NOTHING")
      .run(pid, service);
    const row = this.db.prepare("SELECT id, archived_at FROM services WHERE project_id = ? AND slug = ?").get(pid, service) as {
      id: number;
      archived_at: string | null;
    };
    if (row.archived_at) throw new VaultError(`service "${tenant}/${project}/${service}" is archived — restore it first`);
    for (const col of ["name", "url", "notes"] as const) {
      if (info[col] !== undefined) this.db.prepare(`UPDATE services SET ${col} = ? WHERE id = ?`).run(info[col], row.id);
    }
    return row.id;
  }

  private projectRow(tenant: string, project: string) {
    const row = this.db
      .prepare(
        `SELECT p.id, p.allow_reveal, p.bound_paths, t.archived_at AS t_arch, p.archived_at AS p_arch
         FROM projects p JOIN tenants t ON t.id = p.tenant_id WHERE t.slug = ? AND p.slug = ?`,
      )
      .get(tenant, project) as
      | { id: number; allow_reveal: number; bound_paths: string; t_arch: string | null; p_arch: string | null }
      | undefined;
    if (!row) throw new VaultError(`project "${tenant}/${project}" not found`);
    if (row.t_arch) throw new VaultError(`tenant "${tenant}" is archived — restore it first`);
    if (row.p_arch) throw new VaultError(`project "${tenant}/${project}" is archived — restore it first`);
    return row;
  }

  private serviceId(tenant: string, project: string, service: string): number {
    const pid = this.projectRow(tenant, project).id;
    const row = this.db.prepare("SELECT id, archived_at FROM services WHERE project_id = ? AND slug = ?").get(pid, service) as
      | { id: number; archived_at: string | null }
      | undefined;
    if (!row) throw new VaultError(`service "${tenant}/${project}/${service}" not found`);
    if (row.archived_at) throw new VaultError(`service "${tenant}/${project}/${service}" is archived — restore it first`);
    return row.id;
  }

  listTenants(includeArchived = false) {
    return this.db
      .prepare(
        `SELECT t.slug AS tenant, t.name, t.archived_at,
                (SELECT COUNT(*) FROM projects p WHERE p.tenant_id = t.id AND (? OR p.archived_at IS NULL)) AS projects
         FROM tenants t WHERE (? OR t.archived_at IS NULL) ORDER BY t.slug`,
      )
      .all(includeArchived ? 1 : 0, includeArchived ? 1 : 0)
      .map((r) => dropNullArchived(r as Record<string, unknown>));
  }

  listProjects(tenant?: string, includeArchived = false) {
    const rows = this.db
      .prepare(
        `SELECT t.slug AS tenant, p.slug AS project, p.name, p.allow_reveal, p.bound_paths,
                COALESCE(t.archived_at, p.archived_at) AS archived_at,
                (SELECT COUNT(*) FROM services s WHERE s.project_id = p.id AND (? OR s.archived_at IS NULL)) AS services
         FROM projects p JOIN tenants t ON t.id = p.tenant_id
         WHERE (? IS NULL OR t.slug = ?) AND (? OR (t.archived_at IS NULL AND p.archived_at IS NULL))
         ORDER BY t.slug, p.slug`,
      )
      .all(includeArchived ? 1 : 0, tenant ?? null, tenant ?? null, includeArchived ? 1 : 0) as Array<Record<string, unknown>>;
    return rows.map((r) =>
      dropNullArchived({
        ...r,
        allow_reveal: !!r.allow_reveal,
        bound_paths: JSON.parse(r.bound_paths as string),
      }),
    );
  }

  listServices(tenant: string, project: string, includeArchived = false) {
    const pid = this.projectRow(tenant, project).id;
    return this.db
      .prepare(
        `SELECT s.slug AS service, s.name, s.url, s.notes, s.archived_at,
                (SELECT COUNT(*) FROM items i WHERE i.service_id = s.id AND (? OR i.archived_at IS NULL)) AS items
         FROM services s WHERE s.project_id = ? AND (? OR s.archived_at IS NULL) ORDER BY s.slug`,
      )
      .all(includeArchived ? 1 : 0, pid, includeArchived ? 1 : 0)
      .map((r) => dropNullArchived(r as Record<string, unknown>));
  }

  /** Metadata only — never values. */
  listItems(tenant: string, project: string, service?: string, includeArchived = false) {
    const pid = this.projectRow(tenant, project).id;
    const rows = this.db
      .prepare(
        `SELECT s.slug AS service, i.key, i.type, i.meta, i.version, i.updated_at,
                COALESCE(s.archived_at, i.archived_at) AS archived_at
         FROM items i JOIN services s ON s.id = i.service_id
         WHERE s.project_id = ? AND (? IS NULL OR s.slug = ?)
           AND (? OR (s.archived_at IS NULL AND i.archived_at IS NULL))
         ORDER BY s.slug, i.key`,
      )
      .all(pid, service ?? null, service ?? null, includeArchived ? 1 : 0) as Array<{
      service: string;
      key: string;
      type: ItemType;
      meta: string;
      version: number;
      updated_at: string;
      archived_at: string | null;
    }>;
    return rows.map((r) =>
      dropNullArchived({
        ref: `${tenant}/${project}/${r.service}/${r.key}`,
        type: r.type,
        ...JSON.parse(r.meta),
        version: r.version,
        updated_at: r.updated_at,
        archived_at: r.archived_at,
      }),
    );
  }

  // ---------- archive / restore (nothing is ever deleted) ----------

  /** Row id for a target regardless of archive state. */
  private targetRow(target: string[]): { table: "tenants" | "projects" | "services" | "items"; id: number; archived_at: string | null } {
    const [t, p, s, k] = target;
    const q = [
      `SELECT id, archived_at FROM tenants WHERE slug = ?`,
      `SELECT p.id, p.archived_at FROM projects p JOIN tenants t ON t.id = p.tenant_id WHERE t.slug = ? AND p.slug = ?`,
      `SELECT s.id, s.archived_at FROM services s JOIN projects p ON p.id = s.project_id JOIN tenants t ON t.id = p.tenant_id
       WHERE t.slug = ? AND p.slug = ? AND s.slug = ?`,
      `SELECT i.id, i.archived_at FROM items i JOIN services s ON s.id = i.service_id JOIN projects p ON p.id = s.project_id
       JOIN tenants t ON t.id = p.tenant_id WHERE t.slug = ? AND p.slug = ? AND s.slug = ? AND i.key = ?`,
    ][target.length - 1];
    const row = this.db.prepare(q).get(...[t, p, s, k].slice(0, target.length)) as { id: number; archived_at: string | null } | undefined;
    if (!row) throw new VaultError(`"${target.join("/")}" not found`);
    const table = (["tenants", "projects", "services", "items"] as const)[target.length - 1];
    return { table, ...row };
  }

  /** Archive a tenant, project, service or item. Everything below it becomes hidden and unusable. */
  archive(target: string[], source = "mcp"): string {
    const row = this.targetRow(target);
    const name = target.join("/");
    if (row.archived_at) return `${name} was already archived at ${row.archived_at}`;
    this.db.prepare(`UPDATE ${row.table} SET archived_at = datetime('now') WHERE id = ?`).run(row.id);
    this.audit(source, name, `archive-${row.table.slice(0, -1)}`);
    return `archived ${name}`;
  }

  restore(target: string[], source = "mcp"): string {
    const row = this.targetRow(target);
    const name = target.join("/");
    if (!row.archived_at) return `${name} is not archived`;
    this.db.prepare(`UPDATE ${row.table} SET archived_at = NULL WHERE id = ?`).run(row.id);
    this.audit(source, name, `restore-${row.table.slice(0, -1)}`);
    // a restored child is still hidden if a parent is archived — tell the caller
    for (let n = target.length - 1; n >= 1; n--) {
      const parent = this.targetRow(target.slice(0, n));
      if (parent.archived_at) return `restored ${name}, but parent ${target.slice(0, n).join("/")} is still archived`;
    }
    return `restored ${name}`;
  }

  // ---------- project settings ----------

  setAllowReveal(tenant: string, project: string, allow: boolean): void {
    const pid = this.projectRow(tenant, project).id;
    this.db.prepare("UPDATE projects SET allow_reveal = ? WHERE id = ?").run(allow ? 1 : 0, pid);
    this.audit("cli", `${tenant}/${project}`, `allow-reveal=${allow}`);
  }

  isRevealAllowed(tenant: string, project: string): boolean {
    return !!this.projectRow(tenant, project).allow_reveal;
  }

  bindPath(tenant: string, project: string, dir: string): string {
    const abs = canonical(dir);
    const row = this.projectRow(tenant, project);
    const paths = new Set<string>(JSON.parse(row.bound_paths));
    paths.add(abs);
    this.db.prepare("UPDATE projects SET bound_paths = ? WHERE id = ?").run(JSON.stringify([...paths]), row.id);
    return abs;
  }

  unbindPath(tenant: string, project: string, dir: string): void {
    const abs = canonical(dir);
    const row = this.projectRow(tenant, project);
    const paths = (JSON.parse(row.bound_paths) as string[]).filter((p) => p !== abs);
    this.db.prepare("UPDATE projects SET bound_paths = ? WHERE id = ?").run(JSON.stringify(paths), row.id);
  }

  /** Find the (non-archived) project bound to `cwd` or its nearest bound ancestor. */
  resolveContext(cwd: string): (ProjectCtx & { bound_path: string }) | null {
    const abs = canonical(cwd);
    let best: (ProjectCtx & { bound_path: string }) | null = null;
    for (const p of this.listProjects() as unknown as Array<{ tenant: string; project: string; bound_paths: string[] }>) {
      for (const bp of p.bound_paths) {
        if ((abs === bp || abs.startsWith(bp + sep)) && (!best || bp.length > best.bound_path.length)) {
          best = { tenant: p.tenant, project: p.project, bound_path: bp };
        }
      }
    }
    return best;
  }

  // ---------- items (versioned) ----------

  private itemRow(ref: Ref): ItemRow {
    const sid = this.serviceId(ref.tenant, ref.project, ref.service);
    const row = this.db.prepare("SELECT * FROM items WHERE service_id = ? AND key = ?").get(sid, ref.key) as ItemRow | undefined;
    const name = formatRef({ ...ref, field: undefined, version: undefined });
    if (!row) throw new VaultError(`item "${name}" not found`);
    if (row.archived_at) throw new VaultError(`item "${name}" is archived — restore it first`);
    return row;
  }

  /** Existing uid for the ref (so AAD stays stable across versions) or a fresh one. */
  private uidFor(ref: Ref): string {
    let sid: number;
    try {
      sid = this.serviceId(ref.tenant, ref.project, ref.service);
    } catch {
      return randomUUID();
    }
    const row = this.db.prepare("SELECT uid FROM items WHERE service_id = ? AND key = ?").get(sid, ref.key) as { uid: string } | undefined;
    return row?.uid ?? randomUUID();
  }

  /** Current version lives at <uid>.bin; older versions at <uid>.v<N>.bin. */
  private blobPath(uid: string, oldVersion?: number): string {
    return join(this.home, "files", oldVersion ? `${uid}.v${oldVersion}.bin` : `${uid}.bin`);
  }

  /**
   * Write a new version of an item. The previous version (if any) is kept in item_versions
   * (and its file blob renamed to <uid>.v<N>.bin). Writing to an archived item restores it.
   */
  private writeItem(
    ref: Ref,
    type: ItemType,
    data: Buffer | null,
    meta: Record<string, unknown>,
    uid: string,
    source: string,
    blob?: Buffer,
  ): number {
    if (ref.version) throw new VaultError("cannot write to a specific @version; writes always create a new version");
    const sid = this.ensureService(ref.tenant, ref.project, ref.service);
    const existing = this.db.prepare("SELECT * FROM items WHERE service_id = ? AND key = ?").get(sid, ref.key) as ItemRow | undefined;

    if (!existing) {
      if (blob) writeFileSync(this.blobPath(uid), blob, { mode: 0o600 });
      this.db
        .prepare("INSERT INTO items (uid, service_id, key, type, data, meta, version, source) VALUES (?, ?, ?, ?, ?, ?, 1, ?)")
        .run(uid, sid, ref.key, type, data, JSON.stringify(meta), source);
      return 1;
    }

    const oldMeta = JSON.parse(existing.meta);
    for (const k of ["description", "role", "default"]) {
      if (meta[k] === undefined && oldMeta[k] !== undefined) meta[k] = oldMeta[k];
    }
    const cur = this.blobPath(existing.uid);
    const archivedBlob = this.blobPath(existing.uid, existing.version);
    let renamed = false;
    if (existing.type === "file" && existsSync(cur)) {
      renameSync(cur, archivedBlob);
      renamed = true;
    }
    try {
      if (blob) writeFileSync(cur, blob, { mode: 0o600 });
      this.db.transaction(() => {
        this.db
          .prepare("INSERT INTO item_versions (item_id, version, type, data, meta, created_at, source) VALUES (?, ?, ?, ?, ?, ?, ?)")
          .run(existing.id, existing.version, existing.type, existing.data, existing.meta, existing.updated_at, existing.source);
        this.db
          .prepare(
            `UPDATE items SET type = ?, data = ?, meta = ?, version = version + 1, source = ?,
                    archived_at = NULL, updated_at = datetime('now') WHERE id = ?`,
          )
          .run(type, data, JSON.stringify(meta), source, existing.id);
      })();
    } catch (e) {
      if (blob) rmSync(cur, { force: true });
      if (renamed) renameSync(archivedBlob, cur);
      throw e;
    }
    return existing.version + 1;
  }

  setSecret(ref: Ref, value: string, description?: string, source = "mcp"): number {
    const uid = this.uidFor(ref);
    const data = encrypt(this.dek, Buffer.from(value, "utf8"), uid);
    const v = this.writeItem(ref, "secret", data, description ? { description } : {}, uid, source);
    this.audit(source, formatRef(ref), `set-secret v${v}`);
    return v;
  }

  setCredential(ref: Ref, fields: Record<string, string>, description?: string, source = "mcp"): number {
    if (Object.keys(fields).length === 0) throw new VaultError("credential needs at least one field");
    const uid = this.uidFor(ref);
    const data = encrypt(this.dek, Buffer.from(JSON.stringify(fields), "utf8"), uid);
    const meta: Record<string, unknown> = { fields: Object.keys(fields) };
    if (description) meta.description = description;
    const v = this.writeItem(ref, "credential", data, meta, uid, source);
    this.audit(source, formatRef(ref), `set-credential v${v}`);
    return v;
  }

  generateSecret(ref: Ref, length = 32, alphabet: "alnum" | "hex" | "symbols" = "alnum", description?: string): number {
    const sets = {
      alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      hex: "0123456789abcdef",
      symbols: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#%^&*-_=+",
    };
    const chars = sets[alphabet];
    let out = "";
    while (out.length < length) {
      for (const b of randomBytes(length * 2)) {
        if (b < 256 - (256 % chars.length)) out += chars[b % chars.length];
        if (out.length === length) break;
      }
    }
    return this.setSecret(ref, out, description, "mcp:generate");
  }

  putFile(ref: Ref, srcPath: string, description?: string, source = "mcp"): { filename: string; size: number; version: number } {
    const st = statSync(srcPath);
    if (!st.isFile()) throw new VaultError(`${srcPath} is not a file`);
    if (st.size > MAX_FILE_BYTES) throw new VaultError(`file too large (max ${MAX_FILE_BYTES / 1024 / 1024} MB)`);
    return this.putFileContent(ref, basename(srcPath), readFileSync(srcPath), description, source);
  }

  /** Store file content from memory (used by bundle import — no plaintext temp file). */
  putFileContent(
    ref: Ref,
    filename: string,
    content: Buffer,
    description?: string,
    source = "mcp",
  ): { filename: string; size: number; version: number } {
    if (content.length > MAX_FILE_BYTES) throw new VaultError(`file too large (max ${MAX_FILE_BYTES / 1024 / 1024} MB)`);
    const uid = this.uidFor(ref);
    const blob = encrypt(this.dek, content, uid);
    const meta: Record<string, unknown> = { filename, size: content.length };
    if (description) meta.description = description;
    const version = this.writeItem(ref, "file", null, meta, uid, source, blob);
    this.audit(source, formatRef(ref), `put-file v${version}`);
    return { filename, size: content.length, version };
  }

  /** Decrypt the current version, or `ref.version` if given. */
  private load(ref: Ref): Loaded {
    if (this.metadataOnly) throw new VaultError("vault opened for metadata only — values are not available");
    const row = this.itemRow(ref);
    let { type, data, meta } = row;
    let version = row.version;
    let blobFile = this.blobPath(row.uid);
    if (ref.version && ref.version !== row.version) {
      const old = this.db
        .prepare("SELECT type, data, meta FROM item_versions WHERE item_id = ? AND version = ?")
        .get(row.id, ref.version) as { type: ItemType; data: Buffer | null; meta: string } | undefined;
      if (!old) throw new VaultError(`${formatRef({ ...ref, field: undefined })} not found (current version is ${row.version})`);
      ({ type, data, meta } = old);
      version = ref.version;
      blobFile = this.blobPath(row.uid, ref.version);
    }
    const plain = type === "file" ? decrypt(this.dek, readFileSync(blobFile), row.uid) : decrypt(this.dek, data!, row.uid);
    return { type, meta: JSON.parse(meta), plain, version };
  }

  readFile(ref: Ref, source = "mcp"): { filename: string; content: Buffer; version: number } {
    this.assertUsable(ref, source);
    const item = this.load(ref);
    if (item.type !== "file") throw new VaultError(`${formatRef(ref)} is a ${item.type}, not a file`);
    this.audit(source, formatRef(ref), `read-file v${item.version}`);
    return { filename: item.meta.filename as string, content: item.plain, version: item.version };
  }

  /**
   * Resolve a ref to a single string value. Credentials default to the "password" field
   * (or the only field); use `#field` to pick another one.
   */
  resolveValue(ref: Ref, source = "mcp"): string {
    this.assertUsable(ref, source);
    const item = this.load(ref);
    let value: string;
    if (item.type === "file") {
      value = item.plain.toString("utf8");
    } else if (item.type === "secret") {
      if (ref.field) throw new VaultError(`${formatRef(ref)}: secrets have no fields`);
      value = item.plain.toString("utf8");
    } else {
      const fields = JSON.parse(item.plain.toString("utf8")) as Record<string, string>;
      const names = Object.keys(fields);
      const field = ref.field ?? ("password" in fields ? "password" : names.length === 1 ? names[0] : undefined);
      if (!field) throw new VaultError(`${formatRef(ref)} has fields [${names.join(", ")}]; pick one with #field`);
      if (!(field in fields)) throw new VaultError(`${formatRef(ref)} has no field "${field}" (fields: ${names.join(", ")})`);
      value = fields[field];
    }
    this.audit(source, formatRef(ref), `use v${item.version}`);
    return value;
  }

  /** Full item content for humans / reveal. */
  getItem(ref: Ref, source: string): { type: ItemType; version: number; value: string | Record<string, string> } {
    const item = this.load(ref);
    if (item.type === "file") throw new VaultError(`${formatRef(ref)} is a file — materialize it instead`);
    const plain = item.plain.toString("utf8");
    this.audit(source, formatRef(ref), `reveal v${item.version}`);
    if (item.type === "secret") return { type: "secret", version: item.version, value: plain };
    const fields = JSON.parse(plain) as Record<string, string>;
    if (ref.field) return { type: "credential", version: item.version, value: fields[ref.field] ?? "" };
    return { type: "credential", version: item.version, value: fields };
  }

  /**
   * Set non-secret labels on an item without creating a new version: `role` (e.g. admin, viewer;
   * null clears it) and `isDefault` (at most one default per service — setting it clears the others).
   */
  tagItem(
    ref: Ref,
    tags: { role?: string | null; isDefault?: boolean; description?: string | null },
    source = "mcp",
  ): Record<string, unknown> {
    const row = this.itemRow(ref);
    const meta = JSON.parse(row.meta) as Record<string, unknown>;
    if (tags.role !== undefined) {
      if (tags.role === null || tags.role === "") delete meta.role;
      else meta.role = tags.role;
    }
    if (tags.description !== undefined) {
      if (tags.description === null || tags.description === "") delete meta.description;
      else meta.description = tags.description;
    }
    const tx = this.db.transaction(() => {
      if (tags.isDefault === true) {
        const siblings = this.db
          .prepare("SELECT id, meta FROM items WHERE service_id = (SELECT service_id FROM items WHERE id = ?) AND id != ?")
          .all(row.id, row.id) as Array<{ id: number; meta: string }>;
        for (const s of siblings) {
          const m = JSON.parse(s.meta);
          if (m.default) {
            delete m.default;
            this.db.prepare("UPDATE items SET meta = ? WHERE id = ?").run(JSON.stringify(m), s.id);
          }
        }
        meta.default = true;
      } else if (tags.isDefault === false) {
        delete meta.default;
      }
      this.db.prepare("UPDATE items SET meta = ? WHERE id = ?").run(JSON.stringify(meta), row.id);
    });
    tx();
    this.audit(source, formatRef({ ...ref, field: undefined, version: undefined }), `tag role=${meta.role ?? "-"} default=${!!meta.default}`);
    return { role: meta.role ?? null, default: !!meta.default };
  }

  /** Version history (metadata only), newest first. */
  listVersions(ref: Ref) {
    const row = this.itemRow(ref);
    const history = this.db
      .prepare("SELECT version, type, meta, created_at, source FROM item_versions WHERE item_id = ? ORDER BY version DESC")
      .all(row.id) as Array<{ version: number; type: ItemType; meta: string; created_at: string; source: string | null }>;
    return [
      { version: row.version, current: true, type: row.type, ...JSON.parse(row.meta), created_at: row.updated_at, source: row.source },
      ...history.map((h) => ({ version: h.version, current: false, type: h.type, ...JSON.parse(h.meta), created_at: h.created_at, source: h.source })),
    ];
  }

  /** Make an old version current again by copying it forward as a NEW version (history is never rewritten). */
  rollback(ref: Ref, version: number, source = "mcp"): number {
    const row = this.itemRow(ref);
    if (version === row.version) throw new VaultError(`v${version} is already the current version`);
    const old = this.db
      .prepare("SELECT type, data, meta FROM item_versions WHERE item_id = ? AND version = ?")
      .get(row.id, version) as { type: ItemType; data: Buffer | null; meta: string } | undefined;
    if (!old) throw new VaultError(`version ${version} not found`);
    // ciphertext is bound to the item uid (not the version), so it can be copied forward as-is
    const blob = old.type === "file" ? readFileSync(this.blobPath(row.uid, version)) : undefined;
    const base = { ...ref, version: undefined, field: undefined };
    const v = this.writeItem(base, old.type, old.data, JSON.parse(old.meta), row.uid, source, blob);
    this.audit(source, formatRef(base), `rollback to v${version} → v${v}`);
    return v;
  }

  // ---------- enforced policies ----------

  /** "ok" | "missing" (item/service/project absent) | "archived" | "locked", without throwing. */
  itemStatus(ref: Ref): "ok" | "missing" | "archived" | "locked" {
    try {
      const row = this.itemRow(ref);
      return JSON.parse(row.meta).locked ? "locked" : "ok";
    } catch (e) {
      if (e instanceof VaultError && /archived/.test(e.message)) return "archived";
      if (e instanceof VaultError && /not found/.test(e.message)) return "missing";
      throw e;
    }
  }

  /** Lock an item (e.g. after a rejected login). Claude-side use is refused until unlocked or re-entered. */
  lockItem(ref: Ref, reason: string, source = "mcp"): void {
    const row = this.itemRow(ref);
    const meta = JSON.parse(row.meta);
    meta.locked = { at: new Date().toISOString().replace("T", " ").slice(0, 19), reason };
    this.db.prepare("UPDATE items SET meta = ? WHERE id = ?").run(JSON.stringify(meta), row.id);
    this.audit(source, formatRef({ ...ref, field: undefined, version: undefined }), `lock: ${reason}`);
  }

  unlockItem(ref: Ref, source = "cli"): boolean {
    const row = this.itemRow(ref);
    const meta = JSON.parse(row.meta);
    if (!meta.locked) return false;
    delete meta.locked;
    this.db.prepare("UPDATE items SET meta = ? WHERE id = ?").run(JSON.stringify(meta), row.id);
    this.audit(source, formatRef({ ...ref, field: undefined, version: undefined }), "unlock");
    return true;
  }

  /** Throws if the item is locked and the caller is not the user's own CLI/UI. */
  private assertUsable(ref: Ref, source: string): void {
    if (source.startsWith("cli")) return;
    const locked = JSON.parse(this.itemRow(ref).meta).locked as { at: string; reason: string } | undefined;
    if (locked) {
      const base = formatRef({ ...ref, field: undefined, version: undefined });
      throw new VaultError(
        `${base} is LOCKED since ${locked.at} (${locked.reason}). Do not retry. Ask the user to re-enter it (request_credential on the same path saves a new version and unlocks it) or to run: cvault unlock ${base}`,
      );
    }
  }

  /** Model-side uses of `ref#field` since `sinceUtc` (sqlite datetime text). */
  countUses(ref: Ref, sinceUtc: string): number {
    const refStr = formatRef({ ...ref, version: undefined });
    const row = this.db
      .prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE ref = ? AND source LIKE 'mcp%' AND action LIKE 'use%' AND ts >= ?`)
      .get(refStr, sinceUtc) as { n: number };
    return row.n;
  }

  /** Last time the user approved further use of `ref#field` (sqlite datetime text) or null. */
  lastApproval(ref: Ref): string | null {
    const refStr = formatRef({ ...ref, version: undefined });
    const row = this.db
      .prepare(`SELECT MAX(ts) AS ts FROM audit_log WHERE ref = ? AND action = 'use-approved'`)
      .get(refStr) as { ts: string | null };
    return row.ts;
  }

  allowedHosts(tenant: string, project: string, service: string): string[] {
    const pid = this.projectRow(tenant, project).id;
    const row = this.db.prepare("SELECT allowed_hosts FROM services WHERE project_id = ? AND slug = ?").get(pid, service) as
      | { allowed_hosts: string }
      | undefined;
    return row ? (JSON.parse(row.allowed_hosts) as string[]) : [];
  }

  setAllowedHosts(tenant: string, project: string, service: string, hosts: string[], source = "cli"): string[] {
    const sid = this.serviceId(tenant, project, service);
    const clean = [...new Set(hosts.map((h) => h.trim().toLowerCase()).filter(Boolean))];
    this.db.prepare("UPDATE services SET allowed_hosts = ? WHERE id = ?").run(JSON.stringify(clean), sid);
    this.audit(source, `${tenant}/${project}/${service}`, `allowed-hosts=${clean.join(",") || "(any)"}`);
    return clean;
  }

  chatValuesAllowed(tenant: string, project: string): boolean {
    try {
      const row = this.db
        .prepare(`SELECT p.allow_chat_values AS v FROM projects p JOIN tenants t ON t.id = p.tenant_id WHERE t.slug = ? AND p.slug = ?`)
        .get(tenant, project) as { v: number } | undefined;
      return !!row?.v;
    } catch {
      return false;
    }
  }

  setChatValues(tenant: string, project: string, allow: boolean): void {
    const pid = this.projectRow(tenant, project).id;
    this.db.prepare("UPDATE projects SET allow_chat_values = ? WHERE id = ?").run(allow ? 1 : 0, pid);
    this.audit("cli", `${tenant}/${project}`, `chat-values=${allow}`);
  }

  // ---------- audit ----------

  audit(source: string, ref: string | null, action: string): void {
    this.db.prepare("INSERT INTO audit_log (source, ref, action) VALUES (?, ?, ?)").run(source, ref, action);
  }

  auditLog(limit = 50, filter?: string) {
    return this.db
      .prepare(`SELECT ts, source, ref, action FROM audit_log WHERE (? IS NULL OR ref LIKE ?) ORDER BY id DESC LIMIT ?`)
      .all(filter ?? null, filter ? `${filter}%` : null, limit);
  }
}

function dropNullArchived<T extends Record<string, unknown>>(r: T): T {
  if (r.archived_at === null || r.archived_at === undefined) delete r.archived_at;
  return r;
}
