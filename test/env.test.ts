import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkHosts } from "../src/enforce.js";
import { collectItems, decryptBundle, encryptBundle, importItems, toEnv } from "../src/export.js";
import { formatRef, parseRef, parseServicePath, shortRef, Vault } from "../src/store.js";

const FAST = { N: 1024, r: 8, p: 1 };
let dir: string;
let vault: Vault;
const R = (s: string) => parseRef(s);

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "vault-env-"));
  vault = Vault.init("correct horse battery", { home: join(dir, "v"), kdf: FAST });
  vault.setCredential(R("acme/staging/api/admin-panel/root"), { username: "root", password: "Stag1ng!" });
  vault.setCredential(R("acme/develop/api/admin-panel/root"), { username: "root", password: "Dev3lop!" });
  vault.setSecret(R("acme/api/stripe/key"), "sk_shared");
});
afterEach(() => vault.close());

describe("environment paths", () => {
  it("parses 5-level, 4-level and short forms", () => {
    expect(R("acme/staging/api/admin-panel/root#password")).toEqual({
      tenant: "acme", env: "staging", project: "api", service: "admin-panel", key: "root", field: "password",
    });
    expect(R("acme/api/stripe/key").env).toBeUndefined();
    const ctx = { tenant: "acme", project: "api" };
    expect(parseRef("staging/admin-panel/root", ctx)).toMatchObject({ env: "staging", service: "admin-panel" });
    expect(parseRef("stripe/key", ctx).env).toBeUndefined();
    expect(parseRef("admin-panel/root", { ...ctx, env: "develop" }).env).toBe("develop");
    expect(formatRef(R("acme/staging/api/admin-panel/root"))).toBe("acme/staging/api/admin-panel/root");
    expect(shortRef(R("acme/staging/api/admin-panel/root"))).toBe("staging/admin-panel/root");
    expect(parseServicePath("acme/staging/api/admin-panel")).toEqual(["acme", "api", "staging/admin-panel"]);
  });

  it("keeps the same service name separate per environment", () => {
    expect(vault.resolveValue(R("acme/staging/api/admin-panel/root#password"))).toBe("Stag1ng!");
    expect(vault.resolveValue(R("acme/develop/api/admin-panel/root#password"))).toBe("Dev3lop!");
    expect(() => vault.resolveValue(R("acme/api/admin-panel/root#password"))).toThrow(/not found/);
    expect(vault.listEnvironments("acme")).toEqual(["develop", "staging"]);
    expect(vault.listItems("acme", "api", undefined, false, "staging").map((i) => i.ref)).toEqual(["acme/staging/api/admin-panel/root"]);
    expect(vault.listItems("acme", "api", undefined, false, "").map((i) => i.ref)).toEqual(["acme/api/stripe/key"]);
  });

  it("applies allowed hosts per environment", () => {
    vault.setAllowedHosts("acme", "api", "staging/admin-panel", ["core-staging.acme.io"]);
    vault.setAllowedHosts("acme", "api", "develop/admin-panel", ["core-develop.acme.io"]);
    expect(() => checkHosts(vault, [R("acme/staging/api/admin-panel/root")], ["core-staging.acme.io"])).not.toThrow();
    expect(() => checkHosts(vault, [R("acme/staging/api/admin-panel/root")], ["core-develop.acme.io"])).toThrow(
      /acme\/staging\/api\/admin-panel may only be sent/,
    );
  });

  it("links a directory with a default environment", () => {
    vault.bindPath("acme", "api", dir, "staging");
    const ctx = vault.resolveContext(dir)!;
    expect(ctx).toMatchObject({ tenant: "acme", project: "api", env: "staging" });
    expect(vault.resolveValue(parseRef("admin-panel/root#password", ctx))).toBe("Stag1ng!");
  });
});

describe("moving services into environments", () => {
  it("keeps versions, labels and allowed hosts", () => {
    vault.setCredential(R("acme/api/draft-panel/root"), { username: "root", password: "v1" });
    vault.setCredential(R("acme/api/draft-panel/root"), { username: "root", password: "v2" });
    vault.tagItem(R("acme/api/draft-panel/root"), { role: "admin", isDefault: true });
    vault.setAllowedHosts("acme", "api", "draft-panel", ["core-draft.acme.io"]);
    expect(vault.moveService("acme", "api", "draft-panel", "draft/admin-panel")).toMatch(/→ acme\/draft\/api\/admin-panel/);
    const ref = R("acme/draft/api/admin-panel/root");
    expect(vault.resolveValue({ ...ref, field: "password" })).toBe("v2");
    expect(vault.resolveValue({ ...ref, field: "password", version: 1 })).toBe("v1");
    expect(vault.listItems("acme", "api", "draft/admin-panel")[0]).toMatchObject({ role: "admin", default: true, version: 2 });
    expect(vault.allowedHosts("acme", "api", "draft/admin-panel")).toEqual(["core-draft.acme.io"]);
    expect(() => vault.moveService("acme", "api", "staging/admin-panel", "develop/admin-panel")).toThrow(/already exists/);
  });
});

describe("targets and scopes", () => {
  it("resolves archive targets with and without environments", () => {
    expect(vault.resolveTarget("acme/staging/api/admin-panel/root")).toEqual(["acme", "api", "staging/admin-panel", "root"]);
    expect(vault.resolveTarget("acme/staging/api/admin-panel")).toEqual(["acme", "api", "staging/admin-panel"]);
    expect(vault.resolveTarget("acme/api/stripe/key")).toEqual(["acme", "api", "stripe", "key"]);
    expect(vault.archive(vault.resolveTarget("acme/staging/api/admin-panel"))).toBe("archived acme/staging/api/admin-panel");
    expect(() => vault.resolveValue(R("acme/staging/api/admin-panel/root#password"))).toThrow(/archived/);
    expect(vault.resolveValue(R("acme/develop/api/admin-panel/root#password"))).toBe("Dev3lop!");
  });

  it("resolves listing scopes", () => {
    expect(vault.resolveScope("acme/api")).toEqual({ tenant: "acme", project: "api" });
    expect(vault.resolveScope("acme/staging")).toEqual({ tenant: "acme", env: "staging" });
    expect(vault.resolveScope("acme/staging/api")).toEqual({ tenant: "acme", env: "staging", project: "api" });
    expect(vault.resolveScope("acme/api/stripe")).toEqual({ tenant: "acme", project: "api", service: "stripe" });
    expect(vault.resolveScope("acme/staging/api/admin-panel")).toMatchObject({ service: "staging/admin-panel" });
  });
});

describe("export with environments", () => {
  it("exports one environment and names .env keys without it", () => {
    const scope = vault.resolveScope("acme/staging/api");
    const items = collectItems(vault, scope);
    expect(items.map((i) => `${i.env}/${i.service}/${i.key}`)).toEqual(["staging/admin-panel/root"]);
    expect(toEnv(items, scope).text).toContain('ADMIN_PANEL_ROOT_PASSWORD="Stag1ng!"');
  });

  it("includes the environment in .env names when exporting several", () => {
    const text = toEnv(collectItems(vault, { tenant: "acme", project: "api" }), { tenant: "acme", project: "api" }).text;
    expect(text).toContain('STAGING_ADMIN_PANEL_ROOT_PASSWORD="Stag1ng!"');
    expect(text).toContain('DEVELOP_ADMIN_PANEL_ROOT_PASSWORD="Dev3lop!"');
    expect(text).toContain("STRIPE_KEY=sk_shared");
  });

  it("bundles keep the environment", () => {
    const text = encryptBundle(collectItems(vault, { tenant: "acme" }), "bundle-pass-123", FAST);
    const other = Vault.init("another password", { home: join(dir, "v2"), kdf: FAST });
    importItems(other, decryptBundle(text, "bundle-pass-123"));
    expect(other.resolveValue(R("acme/staging/api/admin-panel/root#password"))).toBe("Stag1ng!");
    expect(other.listEnvironments("acme")).toEqual(["develop", "staging"]);
    other.close();
  });
});
