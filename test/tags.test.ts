import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseRef, Vault } from "../src/store.js";

let vault: Vault;
const R = (s: string) => parseRef(s);

beforeEach(() => {
  vault = Vault.init("correct horse battery", { home: mkdtempSync(join(tmpdir(), "vault-tags-")), kdf: { N: 1024, r: 8, p: 1 } });
});
afterEach(() => vault.close());

describe("roles and defaults", () => {
  it("labels credentials with roles and shows them in listings (no values)", () => {
    vault.setCredential(R("acme/api/panel/admin"), { username: "root", password: "pw-admin" });
    vault.setCredential(R("acme/api/panel/viewer"), { username: "view", password: "pw-viewer" });
    vault.tagItem(R("acme/api/panel/admin"), { role: "admin", isDefault: true });
    vault.tagItem(R("acme/api/panel/viewer"), { role: "viewer" });
    const items = vault.listItems("acme", "api", "panel");
    expect(items.map((i) => [i.role, i.default ?? false])).toEqual([
      ["admin", true],
      ["viewer", false],
    ]);
    expect(JSON.stringify(items)).not.toContain("pw-");
  });

  it("keeps only one default per service", () => {
    vault.setSecret(R("a/p/s/one"), "1");
    vault.setSecret(R("a/p/s/two"), "2");
    vault.setSecret(R("a/p/other/x"), "3");
    vault.tagItem(R("a/p/s/one"), { isDefault: true });
    vault.tagItem(R("a/p/other/x"), { isDefault: true });
    vault.tagItem(R("a/p/s/two"), { isDefault: true });
    const byRef = Object.fromEntries(vault.listItems("a", "p").map((i) => [i.ref, !!i.default]));
    expect(byRef).toEqual({ "a/p/s/one": false, "a/p/s/two": true, "a/p/other/x": true });
  });

  it("tags survive new versions and do not create versions", () => {
    vault.setCredential(R("a/p/s/k"), { password: "v1" });
    vault.tagItem(R("a/p/s/k"), { role: "tester", isDefault: true });
    expect(vault.listVersions(R("a/p/s/k"))).toHaveLength(1);
    vault.setCredential(R("a/p/s/k"), { password: "v2" });
    expect(vault.listItems("a", "p")[0]).toMatchObject({ role: "tester", default: true, version: 2 });
  });

  it("clears role and default", () => {
    vault.setSecret(R("a/p/s/k"), "x");
    vault.tagItem(R("a/p/s/k"), { role: "admin", isDefault: true });
    expect(vault.tagItem(R("a/p/s/k"), { role: null, isDefault: false })).toEqual({ role: null, default: false });
  });
});
