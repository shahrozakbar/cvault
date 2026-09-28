import Database from "better-sqlite3";
import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export function vaultHome(): string {
  return process.env.VAULT_HOME || join(homedir(), ".vault-mcp");
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
  id         INTEGER PRIMARY KEY,
  slug       TEXT NOT NULL UNIQUE,
  name       TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS projects (
  id           INTEGER PRIMARY KEY,
  tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  slug         TEXT NOT NULL,
  name         TEXT,
  allow_reveal INTEGER NOT NULL DEFAULT 0,
  bound_paths  TEXT NOT NULL DEFAULT '[]',
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (tenant_id, slug)
);
CREATE TABLE IF NOT EXISTS services (
  id         INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  slug       TEXT NOT NULL,
  name       TEXT,
  url        TEXT,
  notes      TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (project_id, slug)
);
CREATE TABLE IF NOT EXISTS items (
  id         INTEGER PRIMARY KEY,
  uid        TEXT NOT NULL UNIQUE,
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  key        TEXT NOT NULL,
  type       TEXT NOT NULL CHECK (type IN ('secret', 'credential', 'file')),
  data       BLOB,
  meta       TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (service_id, key)
);
CREATE TABLE IF NOT EXISTS audit_log (
  id     INTEGER PRIMARY KEY,
  ts     TEXT NOT NULL DEFAULT (datetime('now')),
  source TEXT NOT NULL,
  ref    TEXT,
  action TEXT NOT NULL
);
`;

export function openDb(home: string): Database.Database {
  mkdirSync(join(home, "files"), { recursive: true, mode: 0o700 });
  chmodSync(home, 0o700);
  const file = join(home, "vault.db");
  const fresh = !existsSync(file);
  const db = new Database(file);
  if (fresh) chmodSync(file, 0o600);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  migrate(db);
  return db;
}

function addColumn(db: Database.Database, table: string, column: string, ddl: string): void {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!cols.some((c) => c.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}

/** v2: archiving (instead of deleting) and automatic item versioning. */
function migrate(db: Database.Database): void {
  for (const t of ["tenants", "projects", "services", "items"]) addColumn(db, t, "archived_at", "archived_at TEXT");
  addColumn(db, "items", "version", "version INTEGER NOT NULL DEFAULT 1");
  addColumn(db, "items", "source", "source TEXT");
  // v3: enforced policies
  addColumn(db, "services", "allowed_hosts", "allowed_hosts TEXT NOT NULL DEFAULT '[]'");
  addColumn(db, "projects", "allow_chat_values", "allow_chat_values INTEGER NOT NULL DEFAULT 0");
  db.exec(`
    CREATE TABLE IF NOT EXISTS item_versions (
      id         INTEGER PRIMARY KEY,
      item_id    INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      version    INTEGER NOT NULL,
      type       TEXT NOT NULL,
      data       BLOB,
      meta       TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      source     TEXT,
      UNIQUE (item_id, version)
    );
  `);
}
