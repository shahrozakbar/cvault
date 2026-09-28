import { execSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { collectItems, decryptBundle, encryptBundle, importItems, toEnv, toJson, writeExport } from "../src/export.js";
import { parseRef, Vault } from "../src/store.js";

const FAST = { N: 1024, r: 8, p: 1 };
const R = (s: string) => parseRef(s);
let dir: string;
let vault: Vault;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "vault-export-"));
  vault = Vault.init("correct horse battery", { home: join(dir, "v1"), kdf: FAST });
  vault.setCredential(R("acme/api/admin-panel/superadmin"), { username: "root", password: "p@ss w0rd" }, "full access");
  vault.tagItem(R("acme/api/admin-panel/superadmin"), { role: "admin", isDefault: true });
  vault.setSecret(R("acme/api/stripe/api_key"), "sk_old");
  vault.setSecret(R("acme/api/stripe/api_key"), "sk_new");
  const f = join(dir, "deploy.pem");
  writeFileSync(f, "-----KEY-----\n");
  vault.putFile(R("acme/api/ssh/deploy-key"), f);
  vault.setSecret(R("globex/web/cms/token"), "tok");
});
afterEach(() => vault.close());

describe("export", () => {
  it("collects current values of a scope only", () => {
    const items = collectItems(vault, ["acme", "api"]);
    expect(items.map((i) => `${i.service}/${i.key}`).sort()).toEqual(["admin-panel/superadmin", "ssh/deploy-key", "stripe/api_key"]);
    expect(items.find((i) => i.key === "api_key")!.value).toBe("sk_new");
    expect(collectItems(vault, [])).toHaveLength(4);
    expect(collectItems(vault, ["acme", "api", "stripe"])).toHaveLength(1);
  });

  it("builds .env names relative to the scope and skips files", () => {
    const project = toEnv(collectItems(vault, ["acme", "api"]), 2);
    expect(project.text).toContain("STRIPE_API_KEY=sk_new");
    expect(project.text).toContain('ADMIN_PANEL_SUPERADMIN_PASSWORD="p@ss w0rd"');
    expect(project.skipped).toEqual(["acme/api/ssh/deploy-key"]);
    const service = toEnv(collectItems(vault, ["acme", "api", "stripe"]), 3);
    expect(service.text).toContain("API_KEY=sk_new");
  });

  it("refuses .env name collisions", () => {
    vault.setSecret(R("acme/api/stripe/API-KEY"), "dup");
    expect(() => toEnv(collectItems(vault, ["acme", "api", "stripe"]), 3)).toThrow(/collision/);
  });

  it("json keeps structure and labels", () => {
    const doc = JSON.parse(toJson(collectItems(vault, ["acme"])));
    expect(doc.vault.acme.api["admin-panel"].superadmin).toMatchObject({ role: "admin", default: true, fields: { username: "root" } });
  });
});

describe("encrypted bundle", () => {
  it("round-trips into another vault, including files and labels", () => {
    const text = encryptBundle(collectItems(vault, ["acme"]), "bundle-pass-123", FAST);
    expect(text).not.toContain("sk_new");
    expect(text).not.toContain("p@ss");
    const other = Vault.init("another password", { home: join(dir, "v2"), kdf: FAST });
    const r = importItems(other, decryptBundle(text, "bundle-pass-123"));
    expect(r).toEqual({ imported: 3, created: 3, updated: 0 });
    expect(other.resolveValue(R("acme/api/stripe/api_key"))).toBe("sk_new");
    expect(other.resolveValue(R("acme/api/admin-panel/superadmin#username"))).toBe("root");
    expect(other.readFile(R("acme/api/ssh/deploy-key")).content.toString()).toBe("-----KEY-----\n");
    expect(other.listItems("acme", "api", "admin-panel")[0]).toMatchObject({ role: "admin", default: true, description: "full access" });
    other.close();
  });

  it("rejects a wrong passphrase", () => {
    const text = encryptBundle(collectItems(vault, ["globex"]), "bundle-pass-123", FAST);
    expect(() => decryptBundle(text, "nope-nope-nope")).toThrow(/wrong passphrase/);
    expect(() => decryptBundle("{}", "x")).toThrow(/not a cvault bundle/);
  });

  it("import remaps with --into and versions existing items", () => {
    const items = decryptBundle(encryptBundle(collectItems(vault, ["acme", "api", "stripe"]), "bundle-pass-123", FAST), "bundle-pass-123");
    expect(importItems(vault, items, { into: ["acme", "api-copy"] })).toMatchObject({ created: 1 });
    expect(vault.resolveValue(R("acme/api-copy/stripe/api_key"))).toBe("sk_new");
    expect(importItems(vault, items)).toMatchObject({ updated: 1 });
    expect(vault.listVersions(R("acme/api/stripe/api_key"))).toHaveLength(3);
  });
});

describe("writeExport", () => {
  it("writes 0600 and refuses plaintext in a non-ignored git repo", () => {
    const p = writeExport(join(dir, "out.env"), "A=1\n", { plaintext: true, overwrite: false });
    expect(statSync(p).mode & 0o777).toBe(0o600);
    expect(() => writeExport(p, "A=2\n", { plaintext: true, overwrite: false })).toThrow(/exists/);
    const repo = join(dir, "repo");
    mkdirSync(repo);
    execSync("git init -q", { cwd: repo });
    expect(() => writeExport(join(repo, "secrets.env"), "A=1\n", { plaintext: true, overwrite: false })).toThrow(/not gitignored/);
    expect(writeExport(join(repo, "x.cvault"), "{}", { plaintext: false, overwrite: false })).toContain("x.cvault");
    expect(readFileSync(p, "utf8")).toBe("A=1\n");
  });
});
