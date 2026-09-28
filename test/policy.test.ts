import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkHosts, lockRejected, prepareUse } from "../src/enforce.js";
import { httpRequest } from "../src/inject.js";
import { extractHosts, hostAllowed, USE_BUDGET } from "../src/policy.js";
import { parseRef, Vault } from "../src/store.js";

const R = (s: string) => parseRef(s);
let vault: Vault;

beforeEach(() => {
  vault = Vault.init("correct horse battery", { home: mkdtempSync(join(tmpdir(), "vault-policy-")), kdf: { N: 1024, r: 8, p: 1 } });
  vault.setCredential(R("acme/api/staging-panel/admin"), { username: "root", password: "Stag1ng!" });
  vault.setCredential(R("acme/api/develop-panel/admin"), { username: "root", password: "Dev3lop!" });
});
afterEach(() => vault.close());

describe("host rules", () => {
  it("matches exact hosts and *.wildcards, ignoring case and port", () => {
    expect(hostAllowed("core-staging.digrc.com", ["core-staging.digrc.com"])).toBe(true);
    expect(hostAllowed("CORE-STAGING.digrc.com:443", ["core-staging.digrc.com"])).toBe(true);
    expect(hostAllowed("core-develop.digrc.com", ["core-staging.digrc.com"])).toBe(false);
    expect(hostAllowed("a.staging.digrc.com", ["*.staging.digrc.com"])).toBe(true);
    expect(hostAllowed("staging.digrc.com", ["*.staging.digrc.com"])).toBe(false);
  });

  it("extracts hosts from commands", () => {
    expect(extractHosts(`curl -X POST https://core-develop.digrc.com/user/login -F "a=$P"`)).toEqual(["core-develop.digrc.com"]);
    expect(extractHosts("psql -h db.acme.internal -U app")).toEqual(["db.acme.internal"]);
    expect(extractHosts("ssh deploy@build.acme.io uptime")).toEqual(["build.acme.io"]);
    expect(extractHosts("npm run migrate")).toEqual([]);
  });

  it("blocks secrets from being sent outside the service's allowed hosts", async () => {
    vault.setAllowedHosts("acme", "api", "staging-panel", ["core-staging.digrc.com", "staging-admin.digrc.com"]);
    const ok = prepareUse(vault, ["acme/api/staging-panel/admin#password"], null, { purpose: "t", targetHosts: ["core-staging.digrc.com"] });
    await expect(ok).resolves.toBeDefined();
    const bad = prepareUse(vault, ["acme/api/staging-panel/admin#password"], null, { purpose: "t", targetHosts: ["core-develop.digrc.com"] });
    await expect(bad).rejects.toThrow(/may only be sent to/);
    // services without a list are unrestricted
    await expect(prepareUse(vault, ["acme/api/develop-panel/admin#password"], null, { purpose: "t", targetHosts: ["anything.io"] })).resolves.toBeDefined();
    expect(() => checkHosts(vault, [R("acme/api/staging-panel/admin")], ["evil.example.com"])).toThrow(/blocked/);
  });
});

describe("locks", () => {
  it("a locked credential is refused for Claude but still usable by the user's CLI", () => {
    vault.lockItem(R("acme/api/staging-panel/admin"), "rejected by core-staging.digrc.com (HTTP 401)");
    expect(vault.itemStatus(R("acme/api/staging-panel/admin"))).toBe("locked");
    expect(() => vault.resolveValue(R("acme/api/staging-panel/admin#password"), "mcp")).toThrow(/LOCKED/);
    expect(vault.resolveValue(R("acme/api/staging-panel/admin#password"), "cli:ui")).toBe("Stag1ng!");
    expect(vault.unlockItem(R("acme/api/staging-panel/admin"))).toBe(true);
    expect(vault.resolveValue(R("acme/api/staging-panel/admin#password"), "mcp")).toBe("Stag1ng!");
  });

  it("re-entering the credential (new version) clears the lock", () => {
    vault.lockItem(R("acme/api/staging-panel/admin"), "x");
    vault.setCredential(R("acme/api/staging-panel/admin"), { username: "root", password: "Correct1!" });
    expect(vault.itemStatus(R("acme/api/staging-panel/admin"))).toBe("ok");
  });

  it("an HTTP 401 through http_request locks the credential that was used", async () => {
    const srv = createServer((_, res) => {
      res.statusCode = 401;
      res.end('{"error":"Invalid Username or Password"}');
    });
    await new Promise<void>((r) => srv.listen(0, r));
    const port = (srv.address() as { port: number }).port;
    const refs = ["acme/api/staging-panel/admin#username", "acme/api/staging-panel/admin#password"];
    const res = await httpRequest(vault, {
      method: "POST",
      url: `http://127.0.0.1:${port}/login`,
      headers: {},
      body: "u={{secret:acme/api/staging-panel/admin#username}}&p={{secret:acme/api/staging-panel/admin#password}}",
      timeoutMs: 5000,
      ctx: null,
    });
    srv.close();
    expect(res.status).toBe(401);
    expect(lockRejected(vault, refs, null, "127.0.0.1")).toEqual(["acme/api/staging-panel/admin"]);
    await expect(prepareUse(vault, refs, null, { purpose: "retry" })).resolves.toBeDefined(); // prepare passes…
    expect(() => vault.resolveValue(R(refs[1]), "mcp")).toThrow(/LOCKED/); // …but the value is refused
  });
});

describe("use budget", () => {
  const ref = "acme/api/staging-panel/admin#password";
  const use = (n: number) => {
    for (let i = 0; i < n; i++) vault.resolveValue(R(ref), "mcp");
  };

  it("asks for approval after the budget and locks on Block", async () => {
    use(USE_BUDGET);
    let asked = 0;
    await expect(
      prepareUse(vault, [ref], null, { purpose: "login", approve: async () => (asked++, false) }),
    ).rejects.toThrow(/blocked further use/);
    expect(asked).toBe(1);
    expect(vault.itemStatus(R(ref))).toBe("locked");
  });

  it("Allow grants a grace period without asking again", async () => {
    use(USE_BUDGET);
    let asked = 0;
    const approve = async () => (asked++, true);
    await prepareUse(vault, [ref], null, { purpose: "login", approve });
    use(3);
    await prepareUse(vault, [ref], null, { purpose: "login", approve });
    expect(asked).toBe(1);
  });

  it("usernames don't count against the budget", async () => {
    for (let i = 0; i < USE_BUDGET + 2; i++) vault.resolveValue(R("acme/api/staging-panel/admin#username"), "mcp");
    await expect(
      prepareUse(vault, ["acme/api/staging-panel/admin#username"], null, { purpose: "t", approve: async () => false }),
    ).resolves.toBeDefined();
  });
});

describe("missing items and chat values", () => {
  it("noPrompt refuses missing items instead of opening a dialog", async () => {
    await expect(prepareUse(vault, ["acme/api/ssh/deploy-key"], null, { purpose: "t", noPrompt: true })).rejects.toThrow(/not found/);
  });

  it("values through the chat are off by default", () => {
    expect(vault.chatValuesAllowed("acme", "api")).toBe(false);
    vault.setChatValues("acme", "api", true);
    expect(vault.chatValuesAllowed("acme", "api")).toBe(true);
  });
});
