import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseRef, parseTarget, Vault } from "../src/store.js";

const FAST_KDF = { N: 2 ** 10, r: 8, p: 1 };
let home: string;
let vault: Vault;
const R = (s: string) => parseRef(s);

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "vault-ver-"));
  vault = Vault.init("correct horse battery", { home, kdf: FAST_KDF });
});
afterEach(() => vault.close());

describe("versioning", () => {
  it("every update creates a new version and old ones stay readable", () => {
    expect(vault.setSecret(R("a/p/s/k"), "one")).toBe(1);
    expect(vault.setSecret(R("a/p/s/k"), "two")).toBe(2);
    expect(vault.setSecret(R("a/p/s/k"), "three")).toBe(3);
    expect(vault.resolveValue(R("a/p/s/k"))).toBe("three");
    expect(vault.resolveValue(R("a/p/s/k@1"))).toBe("one");
    expect(vault.resolveValue(R("a/p/s/k@2"))).toBe("two");
    expect(vault.resolveValue(R("a/p/s/k@3"))).toBe("three");
    expect(() => vault.resolveValue(R("a/p/s/k@9"))).toThrow(/current version is 3/);
    const versions = vault.listVersions(R("a/p/s/k"));
    expect(versions.map((v) => [v.version, v.current])).toEqual([[3, true], [2, false], [1, false]]);
    expect(JSON.stringify(versions)).not.toMatch(/one|two|three/);
  });

  it("versions credentials with @N#field", () => {
    vault.setCredential(R("a/p/db/admin"), { username: "old-user", password: "old-pass" });
    vault.setCredential(R("a/p/db/admin"), { username: "new-user", password: "new-pass" });
    expect(vault.resolveValue(R("a/p/db/admin#username"))).toBe("new-user");
    expect(vault.resolveValue(R("a/p/db/admin@1#username"))).toBe("old-user");
    expect(vault.resolveValue(R("a/p/db/admin@1"))).toBe("old-pass");
  });

  it("keeps old file blobs untouched and readable", () => {
    const src = join(home, "cert.pem");
    writeFileSync(src, "CERT-V1");
    vault.putFile(R("a/p/tls/cert"), src);
    writeFileSync(src, "CERT-V2");
    expect(vault.putFile(R("a/p/tls/cert"), src).version).toBe(2);
    expect(vault.readFile(R("a/p/tls/cert")).content.toString()).toBe("CERT-V2");
    expect(vault.readFile(R("a/p/tls/cert@1")).content.toString()).toBe("CERT-V1");
    expect(readdirSync(join(home, "files")).sort()).toEqual(expect.arrayContaining([expect.stringMatching(/\.v1\.bin$/)]));
  });

  it("rollback copies an old version forward without rewriting history", () => {
    vault.setSecret(R("a/p/s/k"), "good");
    vault.setSecret(R("a/p/s/k"), "bad");
    expect(vault.rollback(R("a/p/s/k"), 1)).toBe(3);
    expect(vault.resolveValue(R("a/p/s/k"))).toBe("good");
    expect(vault.resolveValue(R("a/p/s/k@2"))).toBe("bad");
    expect(vault.listVersions(R("a/p/s/k"))).toHaveLength(3);
  });

  it("rolls back files too", () => {
    const src = join(home, "f.txt");
    writeFileSync(src, "F1");
    vault.putFile(R("a/p/s/f"), src);
    writeFileSync(src, "F2");
    vault.putFile(R("a/p/s/f"), src);
    vault.rollback(R("a/p/s/f"), 1);
    expect(vault.readFile(R("a/p/s/f")).content.toString()).toBe("F1");
    expect(vault.readFile(R("a/p/s/f@2")).content.toString()).toBe("F2");
  });

  it("keeps the description across versions", () => {
    vault.setSecret(R("a/p/s/k"), "v1", "stripe live key");
    vault.setSecret(R("a/p/s/k"), "v2");
    expect(vault.listItems("a", "p")[0].description).toBe("stripe live key");
  });

  it("refuses writes to @version", () => {
    expect(() => vault.setSecret(R("a/p/s/k@2"), "x")).toThrow(/new version/);
  });
});

describe("archive", () => {
  it("archives and restores items without losing data", () => {
    vault.setSecret(R("a/p/s/k"), "keep-me");
    expect(vault.archive(parseTarget("a/p/s/k"))).toBe("archived a/p/s/k");
    expect(vault.listItems("a", "p")).toHaveLength(0);
    expect(vault.listItems("a", "p", undefined, true)[0]).toHaveProperty("archived_at");
    expect(() => vault.resolveValue(R("a/p/s/k"))).toThrow(/archived/);
    vault.restore(parseTarget("a/p/s/k"));
    expect(vault.resolveValue(R("a/p/s/k"))).toBe("keep-me");
  });

  it("archiving a tenant hides and blocks everything under it", () => {
    vault.setSecret(R("acme/api/s/k"), "v");
    vault.setSecret(R("globex/api/s/k"), "v");
    vault.bindPath("acme", "api", home);
    vault.archive(["acme"]);
    expect(vault.listTenants().map((t) => t.tenant)).toEqual(["globex"]);
    expect(vault.listTenants(true)).toHaveLength(2);
    expect(vault.listProjects().map((p) => p.tenant)).toEqual(["globex"]);
    expect(vault.resolveContext(home)).toBeNull();
    expect(() => vault.resolveValue(R("acme/api/s/k"))).toThrow(/tenant "acme" is archived/);
    expect(() => vault.setSecret(R("acme/api/s/new"), "x")).toThrow(/archived/);
    vault.restore(["acme"]);
    expect(vault.resolveValue(R("acme/api/s/k"))).toBe("v");
  });

  it("archives projects and reports still-archived parents on restore", () => {
    vault.setSecret(R("a/p/s/k"), "v");
    vault.archive(["a", "p"]);
    vault.archive(["a"]);
    expect(vault.restore(["a", "p"])).toMatch(/parent a is still archived/);
    expect(vault.restore(["a"])).toBe("restored a");
    expect(vault.resolveValue(R("a/p/s/k"))).toBe("v");
  });

  it("writing to an archived item restores it as a new version", () => {
    vault.setSecret(R("a/p/s/k"), "v1");
    vault.archive(parseTarget("a/p/s/k"));
    expect(vault.setSecret(R("a/p/s/k"), "v2")).toBe(2);
    expect(vault.resolveValue(R("a/p/s/k@1"))).toBe("v1");
  });

  it("never deletes data from disk", () => {
    const src = join(home, "x.bin");
    writeFileSync(src, "X");
    vault.putFile(R("a/p/s/f"), src);
    vault.archive(["a"]);
    expect(readdirSync(join(home, "files"))).toHaveLength(1);
    expect(existsSync(join(home, "vault.db"))).toBe(true);
  });
});
