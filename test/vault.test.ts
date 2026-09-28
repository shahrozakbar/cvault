import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decrypt, encrypt, randomKey } from "../src/crypto.js";
import { httpRequest, materializeFile, runWithSecrets, scrub, writeEnvFile } from "../src/inject.js";
import { parseRef, Vault, VaultError } from "../src/store.js";

const FAST_KDF = { N: 2 ** 10, r: 8, p: 1 };
const PW = "correct horse battery";
let home: string;
let vault: Vault;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "vault-test-"));
  vault = Vault.init(PW, { home, kdf: FAST_KDF });
});
afterEach(() => {
  try {
    vault.close();
  } catch {}
});

describe("crypto", () => {
  it("roundtrips and rejects tampered AAD", () => {
    const k = randomKey();
    const blob = encrypt(k, Buffer.from("hello"), "a");
    expect(decrypt(k, blob, "a").toString()).toBe("hello");
    expect(() => decrypt(k, blob, "b")).toThrow();
  });
});

describe("vault", () => {
  it("rejects wrong password and reopens with the right one", () => {
    vault.setSecret(parseRef("acme/api/stripe/key"), "sk_live_abcdef");
    vault.close();
    expect(() => Vault.open("nope nope nope", { home })).toThrow(/wrong master password/);
    vault = Vault.open(PW, { home });
    expect(vault.resolveValue(parseRef("acme/api/stripe/key"))).toBe("sk_live_abcdef");
  });

  it("stores no plaintext on disk", () => {
    vault.setSecret(parseRef("acme/api/stripe/key"), "PLAINTEXT_MARKER_123");
    const src = join(home, "src.txt");
    writeFileSync(src, "FILE_MARKER_456");
    vault.putFile(parseRef("acme/api/gcp/sa"), src);
    vault.db.pragma("wal_checkpoint(TRUNCATE)");
    const all = [join(home, "vault.db"), ...readdirSync(join(home, "files")).map((f) => join(home, "files", f))]
      .map((f) => readFileSync(f).toString("latin1"))
      .join("");
    expect(all).not.toContain("PLAINTEXT_MARKER_123");
    expect(all).not.toContain("FILE_MARKER_456");
  });

  it("isolates tenants and lists metadata only", () => {
    vault.setSecret(parseRef("acme/api/db/password"), "acme-secret");
    vault.setSecret(parseRef("globex/api/db/password"), "globex-secret");
    expect(vault.resolveValue(parseRef("acme/api/db/password"))).toBe("acme-secret");
    expect(vault.resolveValue(parseRef("globex/api/db/password"))).toBe("globex-secret");
    const items = vault.listItems("acme", "api");
    expect(JSON.stringify(items)).not.toContain("acme-secret");
    expect(items).toHaveLength(1);
  });

  it("credentials default to password and support #field", () => {
    vault.setCredential(parseRef("acme/api/pg/admin"), { username: "root", password: "hunter2hunter2" });
    expect(vault.resolveValue(parseRef("acme/api/pg/admin"))).toBe("hunter2hunter2");
    expect(vault.resolveValue(parseRef("acme/api/pg/admin#username"))).toBe("root");
    expect(() => vault.resolveValue(parseRef("acme/api/pg/admin#nope"))).toThrow(VaultError);
  });

  it("resolves short refs from bound directories (longest match)", () => {
    vault.ensureProject("acme", "api");
    vault.ensureProject("acme", "web");
    vault.bindPath("acme", "api", "/work/acme");
    vault.bindPath("acme", "web", "/work/acme/web");
    expect(vault.resolveContext("/work/acme/src")).toMatchObject({ project: "api" });
    expect(vault.resolveContext("/work/acme/web/src")).toMatchObject({ project: "web" });
    expect(vault.resolveContext("/work/acmex")).toBeNull();
    const ref = parseRef("stripe/key", vault.resolveContext("/work/acme/web"));
    expect(ref).toMatchObject({ tenant: "acme", project: "web", service: "stripe", key: "key" });
    expect(() => parseRef("stripe/key", null)).toThrow(/short ref/);
  });

  it("reveal is off by default", () => {
    vault.ensureProject("acme", "api");
    expect(vault.isRevealAllowed("acme", "api")).toBe(false);
    vault.setAllowReveal("acme", "api", true);
    expect(vault.isRevealAllowed("acme", "api")).toBe(true);
  });

  it("generate_secret stores a value of the right length", () => {
    vault.generateSecret(parseRef("acme/api/jwt/secret"), 48, "hex");
    const v = vault.resolveValue(parseRef("acme/api/jwt/secret"));
    expect(v).toMatch(/^[0-9a-f]{48}$/);
  });

  it("changes password", () => {
    vault.setSecret(parseRef("a/b/c/d"), "value1234");
    vault.changePassword("a brand new password");
    vault.close();
    expect(() => Vault.open(PW, { home })).toThrow();
    vault = Vault.open("a brand new password", { home });
    expect(vault.resolveValue(parseRef("a/b/c/d"))).toBe("value1234");
  });
});

describe("inject", () => {
  it("scrubs raw, base64 and url-encoded forms", () => {
    const s = "p@ss/word!";
    const text = `raw=${s} b64=${Buffer.from(s).toString("base64")} url=${encodeURIComponent(s)}`;
    expect(scrub(text, [s])).toMatch(/^raw=\*\*\* b64=\*\*\*=* url=\*\*\*$/);
  });

  it("runs commands with injected env, scrubbed output, and no master password", async () => {
    vault.setSecret(parseRef("acme/api/stripe/key"), "sk_test_supersecret");
    process.env.VAULT_MASTER_PASSWORD = "leak-me-please";
    const r = await runWithSecrets(vault, {
      command: 'echo "key=$STRIPE_KEY"; echo "mp=${VAULT_MASTER_PASSWORD:-none}"; echo -n "$STRIPE_KEY" | wc -c',
      cwd: home,
      env: { STRIPE_KEY: "acme/api/stripe/key" },
      timeoutMs: 10_000,
      ctx: null,
    });
    delete process.env.VAULT_MASTER_PASSWORD;
    expect(r.exit_code).toBe(0);
    expect(r.stdout).toContain("key=***");
    expect(r.stdout).toContain("mp=none");
    expect(r.stdout).toMatch(/\b19\b/);
    expect(r.stdout).not.toContain("supersecret");
  });

  it("writes and merges .env files with 0600", () => {
    vault.setSecret(parseRef("acme/api/db/url"), "postgres://u:p w@h/db");
    const target = join(home, ".env");
    writeFileSync(target, "KEEP=1\nDATABASE_URL=old\n");
    writeEnvFile(vault, { target, mapping: { DATABASE_URL: "acme/api/db/url" }, force: false, ctx: null });
    expect(readFileSync(target, "utf8")).toBe('KEEP=1\nDATABASE_URL="postgres://u:p w@h/db"\n');
    expect(statSync(target).mode & 0o777).toBe(0o600);
  });

  it("refuses to write secrets into a git repo when not ignored", async () => {
    const { execSync } = await import("node:child_process");
    const repo = join(home, "repo");
    mkdirSync(repo);
    execSync("git init -q", { cwd: repo });
    vault.setSecret(parseRef("acme/api/db/url"), "x-secret-x");
    expect(() =>
      writeEnvFile(vault, { target: join(repo, ".env"), mapping: { A: "acme/api/db/url" }, force: false, ctx: null }),
    ).toThrow(/NOT gitignored/);
    writeFileSync(join(repo, ".gitignore"), ".env\n");
    writeEnvFile(vault, { target: join(repo, ".env"), mapping: { A: "acme/api/db/url" }, force: false, ctx: null });
    expect(existsSync(join(repo, ".env"))).toBe(true);
  });

  it("materializes files", () => {
    const src = join(home, "key.pem");
    writeFileSync(src, "-----BEGIN KEY-----\nabc\n-----END KEY-----\n");
    vault.putFile(parseRef("acme/api/ssh/deploy"), src);
    const outDir = join(home, "out");
    mkdirSync(outDir);
    const r = materializeFile(vault, { ref: "acme/api/ssh/deploy", mode: 0o600, force: false, overwrite: false, ctx: null, cwd: outDir });
    expect(readFileSync(r.path, "utf8")).toContain("BEGIN KEY");
    expect(r.path).toBe(join(outDir, "key.pem"));
  });

  it("substitutes placeholders in http requests and scrubs the echo", async () => {
    const { createServer } = await import("node:http");
    const srv = createServer((req, res) => res.end(`auth=${req.headers.authorization}`));
    await new Promise<void>((r) => srv.listen(0, r));
    const port = (srv.address() as { port: number }).port;
    vault.setSecret(parseRef("acme/api/svc/token"), "tok_1234567890");
    const r = await httpRequest(vault, {
      method: "GET",
      url: `http://127.0.0.1:${port}/`,
      headers: { Authorization: "Bearer {{secret:acme/api/svc/token}}" },
      timeoutMs: 5000,
      ctx: null,
    });
    srv.close();
    expect(r.body).toBe("auth=Bearer ***");
  });
});
