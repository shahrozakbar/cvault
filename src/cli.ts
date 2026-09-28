#!/usr/bin/env node
import { Command } from "commander";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { vaultHome } from "./db.js";
import { auditTable, type ItemRowLike, itemsTable, printTable, versionsTable } from "./table.js";
import { collectItems, decryptBundle, encryptBundle, type ExportFormat, importItems, toEnv, toJson, writeExport } from "./export.js";
import { passwordFromEnv } from "./password.js";
import { formatRef, formatScope, formatServicePath, parseRef, parseScope, parseServicePath, serviceKey, shortRef, splitServiceKey, Vault, VaultError } from "./store.js";

// ---------- prompts ----------

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

function promptHidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) throw new VaultError("no TTY for password prompt; set VAULT_MASTER_PASSWORD or use --stdin");
  return new Promise((done) => {
    const stdin = process.stdin;
    process.stderr.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let value = "";
    const onData = (s: string) => {
      for (const ch of s) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stderr.write("\n");
          return done(value);
        }
        if (ch === "\u0003") {
          process.stderr.write("\n");
          process.exit(130);
        }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

async function masterPassword(): Promise<string> {
  return passwordFromEnv() ?? (await promptHidden("Master password: "));
}

async function openVault(): Promise<Vault> {
  return Vault.open(await masterPassword());
}

function print(obj: unknown) {
  console.log(typeof obj === "string" ? obj : JSON.stringify(obj, null, 2));
}

function projectParts(s: string): [string, string] {
  const p = parseScope(s);
  if (p.length !== 2) throw new VaultError("expected tenant/project");
  return [p[0], p[1]];
}

// ---------- commands ----------

const program = new Command()
  .name("cvault")
  .description(`Local multi-tenant secrets vault for Claude (data: ${vaultHome()})`)
  .showHelpAfterError();

program
  .command("init")
  .description("Create a new vault and set the master password")
  .action(async () => {
    if (Vault.isInitialized()) throw new VaultError(`vault already initialized at ${vaultHome()}`);
    const pw = passwordFromEnv() ?? (await promptHidden("New master password: "));
    if (process.stdin.isTTY && !process.env.VAULT_MASTER_PASSWORD) {
      if ((await promptHidden("Repeat: ")) !== pw) throw new VaultError("passwords do not match");
    }
    Vault.init(pw).close();
    print(`vault initialized at ${vaultHome()}`);
  });

program
  .command("change-password")
  .description("Re-encrypt the vault key with a new master password")
  .action(async () => {
    const vault = await openVault();
    const pw = await promptHidden("New master password: ");
    if ((await promptHidden("Repeat: ")) !== pw) throw new VaultError("passwords do not match");
    vault.changePassword(pw);
    print("master password changed — update VAULT_MASTER_PASSWORD in your MCP config");
  });

program
  .command("ls [scope]")
  .description("List projects and all items. Scope: tenant | tenant/env | tenant/project | tenant/[env/]project[/service]")
  .option("-a, --archived", "include archived entries")
  .option("--json", "print raw JSON instead of tables")
  .action(async (scopeStr: string | undefined, o: { archived?: boolean; json?: boolean }) => {
    const vault = await openVault();
    const a = !!o.archived;
    type P = {
      tenant: string;
      project: string;
      services: number;
      bound_paths: string[];
      bound_envs: Record<string, string>;
      allow_reveal: boolean;
      archived_at?: string;
    };
    const scope = vault.resolveScope(scopeStr);
    const envFilter = scope.env;

    const projects = (vault.listProjects(scope.tenant, a) as unknown as P[]).filter((pr) => !scope.project || pr.project === scope.project);
    const items = projects.flatMap((pr) => {
      try {
        return vault.listItems(pr.tenant, pr.project, scope.service, a, envFilter) as unknown as ItemRowLike[];
      } catch {
        return []; // archived project
      }
    });
    if (o.json) return print({ scope, projects, items });

    if (!scope.project) {
      printTable(
        ["TENANT", "PROJECT", "ENVIRONMENTS", "ITEMS", "LINKED DIRECTORY", "CLAUDE REVEAL"],
        projects.map((pr) => {
          const mine = items.filter((i) => {
            const r = parseRef(i.ref);
            return r.tenant === pr.tenant && r.project === pr.project;
          });
          const envs = [...new Set(mine.map((i) => parseRef(i.ref).env ?? "-"))].join(", ");
          return [
            pr.tenant + (pr.archived_at ? " [archived]" : ""),
            pr.project,
            envs,
            mine.length,
            pr.bound_paths.map((b) => b.replace(homedir(), "~") + (pr.bound_envs?.[b] ? ` (${pr.bound_envs[b]})` : "")).join(", "),
            pr.allow_reveal ? "on" : "off",
          ];
        }),
        { title: `Projects${envFilter ? ` with items in ${envFilter}` : ""} (${projects.length})`, maxCol: 70 },
      );
      console.log();
      return console.log(itemsTable(items, envFilter ? `Items in ${scope.tenant}/${envFilter}` : "All items"));
    }
    if (!scope.service) {
      const services = (
        vault.listServices(scope.tenant!, scope.project, a) as Array<{
          key: string;
          service: string;
          environment: string | null;
          url: string | null;
          items: number;
          archived_at?: string;
        }>
      ).filter((sv) => envFilter === undefined || (sv.environment ?? "") === envFilter);
      printTable(
        ["ENVIRONMENT", "SERVICE", "URL", "ITEMS", "ALLOWED HOSTS"],
        services.map((sv) => [
          sv.environment,
          sv.service + (sv.archived_at ? " [archived]" : ""),
          sv.url,
          sv.items,
          vault.allowedHosts(scope.tenant!, scope.project!, sv.key).join(", "),
        ]),
        { title: `Services of ${formatScope(scope)} (${services.length})`, maxCol: 60 },
      );
      console.log();
      return console.log(itemsTable(items));
    }
    console.log(itemsTable(items, `Items of ${formatScope(scope)}`));
  });

const tenant = program.command("tenant").description("Manage tenants");
tenant
  .command("add <tenant>")
  .option("-n, --name <name>")
  .action(async (t: string, o: { name?: string }) => {
    (await openVault()).ensureTenant(t, o.name);
    print(`tenant ${t} ready`);
  });

const project = program.command("project").description("Manage projects");
project
  .command("add <tenant/project>")
  .option("-n, --name <name>")
  .option("-b, --bind <dir>", "bind a local directory to this project")
  .action(async (s: string, o: { name?: string; bind?: string }) => {
    const vault = await openVault();
    const [t, p] = projectParts(s);
    vault.ensureProject(t, p, o.name);
    if (o.bind) print(`bound ${vault.bindPath(t, p, o.bind)}`);
    print(`project ${t}/${p} ready`);
  });
project
  .command("bind <tenant/project> [dir]")
  .description("Bind a directory (default: cwd) to the project, optionally with a default environment")
  .option("--remove", "unbind instead")
  .option("-e, --env <environment>", "default environment for short refs (service/key) in this directory")
  .action(async (s: string, dir: string | undefined, o: { remove?: boolean; env?: string }) => {
    const vault = await openVault();
    const [t, p] = projectParts(s);
    if (o.remove) {
      vault.unbindPath(t, p, dir ?? process.cwd());
      return print("unbound");
    }
    print(`bound ${vault.bindPath(t, p, dir ?? process.cwd(), o.env)} → ${t}/${p}${o.env ? ` (environment ${o.env})` : ""}`);
  });
project
  .command("chat-values <tenant/project> <on|off>")
  .description("Allow/deny Claude to store values it received through the chat (set_secret / set_credential). Off by default.")
  .action(async (s: string, state: string) => {
    if (state !== "on" && state !== "off") throw new VaultError("state must be on or off");
    const [t, p] = projectParts(s);
    (await openVault()).setChatValues(t, p, state === "on");
    print(`chat values ${state} for ${t}/${p}`);
  });

project
  .command("reveal <tenant/project> <on|off>")
  .description("Allow/deny Claude to read plaintext values (reveal_secret) for this project")
  .action(async (s: string, state: string) => {
    if (state !== "on" && state !== "off") throw new VaultError("state must be on or off");
    const [t, p] = projectParts(s);
    (await openVault()).setAllowReveal(t, p, state === "on");
    print(`reveal ${state} for ${t}/${p}`);
  });

program
  .command("service <tenant/project/service>")
  .description("Create/update a service")
  .option("-n, --name <name>")
  .option("-u, --url <url>")
  .option("--notes <notes>")
  .option("--allow-host <host...>", "only allow this service's secrets to be sent to these hosts (repeatable, *.example.com wildcards)")
  .option("--add-host <host...>", "add hosts to the allowed list")
  .option("--clear-hosts", "remove the host restriction")
  .action(
    async (
      s: string,
      o: { name?: string; url?: string; notes?: string; allowHost?: string[]; addHost?: string[]; clearHosts?: boolean },
    ) => {
      const p = parseServicePath(s);
      const vault = await openVault();
      vault.ensureService(p[0], p[1], p[2], { name: o.name, url: o.url, notes: o.notes });
      let hosts: string[] | undefined;
      if (o.clearHosts) hosts = vault.setAllowedHosts(p[0], p[1], p[2], []);
      if (o.allowHost) hosts = vault.setAllowedHosts(p[0], p[1], p[2], o.allowHost);
      if (o.addHost) hosts = vault.setAllowedHosts(p[0], p[1], p[2], [...vault.allowedHosts(p[0], p[1], p[2]), ...o.addHost]);
      const current = hosts ?? vault.allowedHosts(p[0], p[1], p[2]);
      print(`service ${formatServicePath(p[0], p[1], p[2])} ready — allowed hosts: ${current.length ? current.join(", ") : "any (no restriction)"}`);
    },
  );

program
  .command("service-move <from> <to>")
  .description("Rename a service or move it into/out of an environment (items, versions, hosts move with it). E.g. cvault service-move acme/api/staging-panel acme/staging/api/panel")
  .action(async (from: string, to: string) => {
    const f = parseServicePath(from);
    const t = parseServicePath(to);
    if (f[0] !== t[0] || f[1] !== t[1]) throw new VaultError("a service can only move within the same tenant/project");
    print((await openVault()).moveService(f[0], f[1], f[2], t[2]));
  });

program
  .command("unlock <ref>")
  .description("Unlock a credential that was locked after a rejected login or blocked use")
  .action(async (refStr: string) => {
    const vault = await openVault();
    const ref = parseRef(refStr, vault.resolveContext(process.cwd()));
    print(vault.unlockItem(ref, "cli") ? `unlocked ${formatRef({ ...ref, field: undefined })}` : "not locked");
  });

program
  .command("set <ref>")
  .description("Store a secret (hidden prompt, or --stdin). Refs: tenant/project/service/key")
  .option("-d, --description <text>")
  .option("--stdin", "read the value from stdin")
  .option("-r, --role <role>", "role label, e.g. admin, viewer, tester")
  .option("--default", "make this the default item of its service")
  .action(async (refStr: string, o: { description?: string; stdin?: boolean; role?: string; default?: boolean }) => {
    const vault = await openVault();
    const ref = parseRef(refStr, vault.resolveContext(process.cwd()));
    const value = o.stdin ? await readStdin() : await promptHidden(`Value for ${formatRef(ref)}: `);
    if (!value) throw new VaultError("empty value");
    vault.setSecret(ref, value, o.description, "cli");
    if (o.role || o.default) vault.tagItem(ref, { role: o.role, isDefault: o.default ? true : undefined }, "cli");
    print(`stored ${formatRef(ref)}${o.role ? ` role=${o.role}` : ""}${o.default ? " (default)" : ""}`);
  });

program
  .command("tag <ref>")
  .description("Set the role label and/or default flag of an item (no new version)")
  .option("-r, --role <role>", "role label; pass an empty string to clear")
  .option("--default", "make this the default item of its service")
  .option("--no-default", "remove the default flag")
  .action(async (refStr: string, o: { role?: string; default?: boolean }) => {
    const vault = await openVault();
    const ref = parseRef(refStr, vault.resolveContext(process.cwd()));
    print({ ref: formatRef(ref), ...vault.tagItem(ref, { role: o.role === "" ? null : o.role, isDefault: o.default }, "cli") });
  });

program
  .command("set-cred <ref>")
  .description("Store a credential. Non-secret fields via --field k=v; password prompted (hidden)")
  .option("-u, --username <username>")
  .option("-f, --field <k=v...>", "extra fields (repeatable)")
  .option("--secret-field <name...>", "extra fields to prompt for hidden (repeatable)")
  .option("--no-password", "don't prompt for a password field")
  .option("-d, --description <text>")
  .option("-r, --role <role>", "role label, e.g. admin, viewer, tester")
  .option("--default", "make this the default credential of its service")
  .action(
    async (
      refStr: string,
      o: {
        username?: string;
        field?: string[];
        secretField?: string[];
        password: boolean;
        description?: string;
        role?: string;
        default?: boolean;
      },
    ) => {
      const vault = await openVault();
      const ref = parseRef(refStr, vault.resolveContext(process.cwd()));
      const fields: Record<string, string> = {};
      if (o.username) fields.username = o.username;
      for (const kv of o.field ?? []) {
        const i = kv.indexOf("=");
        if (i < 1) throw new VaultError(`bad --field "${kv}" (use key=value)`);
        fields[kv.slice(0, i)] = kv.slice(i + 1);
      }
      if (o.password) fields.password = await promptHidden("password: ");
      for (const f of o.secretField ?? []) fields[f] = await promptHidden(`${f}: `);
      vault.setCredential(ref, fields, o.description, "cli");
      if (o.role || o.default) vault.tagItem(ref, { role: o.role, isDefault: o.default ? true : undefined }, "cli");
      print(`stored ${formatRef(ref)} [${Object.keys(fields).join(", ")}]${o.role ? ` role=${o.role}` : ""}${o.default ? " (default)" : ""}`);
    },
  );

program
  .command("put-file <ref> <file>")
  .description("Encrypt a file into the vault")
  .option("-d, --description <text>")
  .action(async (refStr: string, file: string, o: { description?: string }) => {
    const vault = await openVault();
    const ref = parseRef(refStr, vault.resolveContext(process.cwd()));
    print({ stored: formatRef(ref), ...vault.putFile(ref, resolve(file), o.description, "cli") });
  });

program
  .command("get <ref>")
  .description("Print a value (secret, credential or credential#field). Files: use --out")
  .option("-o, --out <file>", "write file item to this path")
  .action(async (refStr: string, o: { out?: string }) => {
    const vault = await openVault();
    const ref = parseRef(refStr, vault.resolveContext(process.cwd()));
    if (o.out) {
      const { writeFileSync } = await import("node:fs");
      writeFileSync(resolve(o.out), vault.readFile(ref, "cli").content, { mode: 0o600 });
      return print(`wrote ${resolve(o.out)}`);
    }
    const item = vault.getItem(ref, "cli");
    if (typeof item.value === "string") return print(item.value);
    printTable(["FIELD", "VALUE"], Object.entries(item.value), { title: `${formatRef(ref)} (v${item.version})`, maxCol: 200 });
  });

program
  .command("archive <target>")
  .description("Archive (never delete) a tenant | tenant/project | tenant/project/service | tenant/project/service/key")
  .action(async (target: string) => {
    const vault = await openVault();
    print(vault.archive(vault.resolveTarget(target), "cli"));
  });

program
  .command("restore <target>")
  .description("Restore an archived tenant, project, service or item")
  .action(async (target: string) => {
    const vault = await openVault();
    print(vault.restore(vault.resolveTarget(target), "cli"));
  });

program
  .command("versions <ref>")
  .description("Show the version history of an item (no values)")
  .action(async (refStr: string) => {
    const vault = await openVault();
    console.log(versionsTable(vault.listVersions(parseRef(refStr, vault.resolveContext(process.cwd()))) as never));
  });

program
  .command("rollback <ref> <version>")
  .description("Make an old version current again (copied forward as a new version)")
  .action(async (refStr: string, version: string) => {
    const vault = await openVault();
    const ref = parseRef(refStr, vault.resolveContext(process.cwd()));
    const nv = vault.rollback(ref, parseInt(version, 10), "cli");
    print(`${formatRef(ref)}: v${version} is now current as v${nv}`);
  });

program
  .command("import <envfile>")
  .description("Import KEY=value lines from a .env file as secrets under tenant/[env/]project/service")
  .requiredOption("--into <tenant/[env/]project/service>")
  .action(async (envfile: string, o: { into: string }) => {
    const vault = await openVault();
    const p = parseServicePath(o.into);
    const sk = splitServiceKey(p[2]);
    let n = 0;
    for (const line of readFileSync(envfile, "utf8").split(/\r?\n/)) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
      if (!m) continue;
      let val = m[2];
      if (/^".*"$/.test(val)) val = val.slice(1, -1).replace(/\\n/g, "\n").replace(/\\(["\\$])/g, "$1");
      else if (/^'.*'$/.test(val)) val = val.slice(1, -1);
      else val = val.replace(/\s+#.*$/, "");
      vault.setSecret({ tenant: p[0], env: sk.env, project: p[1], service: sk.service, key: m[1] }, val, undefined, "cli:import");
      n++;
    }
    print(`imported ${n} secrets into ${o.into}`);
  });

// ---------- export / import-bundle ----------

async function promptLine(question: string): Promise<string> {
  const { createInterface } = await import("node:readline/promises");
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/** Bundle passphrase from CVAULT_BUNDLE_PASSPHRASE (scripting) or a hidden prompt. */
async function bundlePassphrase(confirmIt: boolean): Promise<string> {
  const fromEnv = process.env.CVAULT_BUNDLE_PASSPHRASE;
  delete process.env.CVAULT_BUNDLE_PASSPHRASE;
  if (fromEnv) return fromEnv;
  const pw = await promptHidden("Bundle passphrase: ");
  if (confirmIt && (await promptHidden("Repeat passphrase: ")) !== pw) throw new VaultError("passphrases do not match");
  return pw;
}

program
  .command("export [scope]")
  .description("Export secrets as an encrypted bundle (default), .env or JSON. Scope: tenant | tenant/project | tenant/project/service (default: everything)")
  .option("-f, --format <format>", "bundle | env | json", "bundle")
  .option("-o, --out <file>", "output file (default: cvault-<scope>.<cvault|env|json>)")
  .option("--stdout", "print to stdout instead of writing a file (env/json only)")
  .option("--force", "overwrite an existing file")
  .option("-y, --yes", "skip the confirmation for plaintext formats")
  .action(async (scope: string | undefined, o: { format: string; out?: string; stdout?: boolean; force?: boolean; yes?: boolean }) => {
    const format = o.format as ExportFormat;
    if (!["bundle", "env", "json"].includes(format)) throw new VaultError("format must be bundle, env or json");
    if (format === "bundle" && o.stdout) throw new VaultError("bundles are written to a file; use -o");
    const vault = await openVault();
    const sc = vault.resolveScope(scope);
    const label = formatScope(sc);
    const fileTag = scope ? scope.split("/").filter(Boolean).join("-") : "all";
    const plaintext = format !== "bundle";
    if (plaintext && !o.yes) {
      if (!process.stdin.isTTY) throw new VaultError("plaintext export needs confirmation — pass --yes");
      const ans = await promptLine(`Export ${label} as PLAINTEXT ${format}? Anyone with the file can read every secret. Type "yes": `);
      if (ans !== "yes") return print("cancelled — nothing exported");
    }
    const items = collectItems(vault, sc);
    if (!items.length) return print(`nothing to export in ${label}`);
    let content: string;
    let note = "";
    if (format === "bundle") {
      content = encryptBundle(items, await bundlePassphrase(true));
    } else if (format === "env") {
      const r = toEnv(items, sc);
      content = r.text;
      if (r.skipped.length) note = `\nskipped ${r.skipped.length} file item(s) (not representable in .env): ${r.skipped.join(", ")}`;
    } else {
      content = toJson(items);
    }
    if (o.stdout) {
      process.stdout.write(content);
      if (note) console.error(note.trim());
      return;
    }
    const ext = format === "bundle" ? "cvault" : format;
    const path = writeExport(o.out ?? `cvault-${fileTag}.${ext}`, content, { plaintext, overwrite: !!o.force });
    const files = items.filter((i) => i.type === "file").length;
    print(
      `exported ${items.length} item(s) from ${label} → ${path} (${format}${format === "bundle" ? ", encrypted" : ", PLAINTEXT"}, mode 600)` +
        (format === "bundle" && files ? `\nincludes ${files} file(s)` : "") +
        note +
        (format === "bundle" ? `\nrestore with: cvault import-bundle ${path}` : ""),
    );
  });

program
  .command("import-bundle <file>")
  .description("Import an encrypted bundle created by `cvault export`. Existing items get a new version.")
  .option("--into <target>", "remap into another tenant (acme2) or tenant/project (acme2/api)")
  .action(async (file: string, o: { into?: string }) => {
    const vault = await openVault();
    const into = o.into ? parseScope(o.into) : undefined;
    if (into && into.length > 2) throw new VaultError("--into must be tenant or tenant/project");
    const items = decryptBundle(readFileSync(file, "utf8"), await bundlePassphrase(false));
    const r = importItems(vault, items, { into });
    print(`imported ${r.imported} item(s): ${r.created} new, ${r.updated} updated (saved as new versions)`);
  });

program
  .command("backup <dir>")
  .description("Copy the encrypted vault (db + files) to a directory")
  .action(async (dir: string) => {
    const vault = await openVault();
    const dest = resolve(dir, `vault-backup-${new Date().toISOString().replace(/[:.]/g, "-")}`);
    mkdirSync(join(dest, "files"), { recursive: true, mode: 0o700 });
    await vault.db.backup(join(dest, "vault.db"));
    const files = join(vault.home, "files");
    if (existsSync(files)) for (const f of readdirSync(files)) copyFileSync(join(files, f), join(dest, "files", f));
    print(`backup written to ${dest} (still encrypted with your master password)`);
  });

program
  .command("audit")
  .description("Show recent access log")
  .option("-n, --limit <n>", "rows", "50")
  .option("-r, --ref <prefix>", "filter by ref prefix")
  .action(async (o: { limit: string; ref?: string }) => {
    console.log(auditTable((await openVault()).auditLog(parseInt(o.limit, 10), o.ref) as never));
  });

// ---------- session context (metadata only, no master password needed) ----------

const MAX_CONTEXT_ITEMS = 60;

/** Text telling Claude which vault project the directory is bound to and which refs exist. Null if unbound. */
function contextFor(dir: string): string | null {
  if (!Vault.isInitialized()) return null;
  const vault = Vault.openMetadata();
  try {
    const ctx = vault.resolveContext(dir);
    if (!ctx) return null;
    const items = vault.listItems(ctx.tenant, ctx.project) as Array<{
      ref: string;
      type: string;
      fields?: string[];
      filename?: string;
      description?: string;
      role?: string;
      default?: boolean;
      locked?: { at: string; reason: string };
      version: number;
    }>;
    const hostsOf = new Map<string, string[]>();
    const svcKeyOf = (ref: string) => {
      const r = parseRef(ref);
      return serviceKey(r.env, r.service);
    };
    for (const i of items) {
      const k = svcKeyOf(i.ref);
      if (!hostsOf.has(k)) hostsOf.set(k, vault.allowedHosts(ctx.tenant, ctx.project, k));
    }
    const lines = items.slice(0, MAX_CONTEXT_ITEMS).map((i) => {
      const extra = [
        i.role ? `role: ${i.role}` : null,
        i.default ? "DEFAULT" : null,
        i.locked ? `LOCKED since ${i.locked.at}: ${i.locked.reason} - do not use; tell the user` : null,
        hostsOf.get(svcKeyOf(i.ref))?.length ? `only for hosts: ${hostsOf.get(svcKeyOf(i.ref))!.join(", ")}` : null,
        i.type === "credential" && i.fields ? `fields: ${i.fields.join(", ")}` : null,
        i.type === "file" && i.filename ? `file: ${i.filename}` : null,
        i.version > 1 ? `v${i.version}` : null,
        i.description ? `"${i.description}"` : null,
      ].filter(Boolean);
      return `- ${shortRef(parseRef(i.ref))} (${i.type}${extra.length ? `; ${extra.join("; ")}` : ""})`;
    });
    if (items.length > MAX_CONTEXT_ITEMS) lines.push(`- … and ${items.length - MAX_CONTEXT_ITEMS} more (use list_items)`);
    return [
      `CVAULT: this working directory is bound to vault project "${ctx.tenant}/${ctx.project}" (bound path: ${ctx.bound_path}).`,
      `Credentials/secrets/files for this project live in the cvault MCP server (tools mcp__cvault__*). Short refs resolve to this project: "env/service/key[#field]" (e.g. staging/admin-panel/systemadmin#password) or "service/key" for items without an environment${ctx.env ? ` (this directory defaults to environment ${ctx.env})` : ""} — pass cwd="${dir}" to the tools. Environments in use: ${vault.listEnvironments(ctx.tenant).join(", ") || "none"}. Use the environment the user names ("log into staging" → staging/…); never substitute another environment.`,
      items.length ? `Available items (names only, no values):\n${lines.join("\n")}` : "No items stored yet for this project.",
      items.some((i) => i.role || i.default)
        ? "Choosing between credentials: if the user names a role (\"login as admin\"), use the item with that role; if no role is named, use the service's DEFAULT item; only ask the user when several items match and none is DEFAULT."
        : null,
      "When a task needs one of these credentials, fetch it from cvault instead of asking the user or searching .env files:",
      "use run_with_secrets / write_env_file / http_request / materialize_file (values stay hidden), sealed_fetch / sealed_save when the user wants to get/set a value themselves.",
      "If a credential the task needs is NOT listed above, just use the ref it should have (e.g. staging-admin-panel/systemadmin#password): the cvault server itself asks the user for it in a dialog before running your tool. (request_credential does the same explicitly.)",
      "Enforced by the server: secrets only go to each service's allowed hosts, repeated password use needs the user's approval, an HTTP 401 locks the credential. If a result says LOCKED or blocked, stop - never retry and never try another environment's credential.",
      "Never ask the user to paste a secret into chat.",
    ]
      .filter(Boolean)
      .join("\n");
  } finally {
    vault.close();
  }
}

program
  .command("context [dir]")
  .description("Show which vault project a directory (default: cwd) is bound to and its items — what the SessionStart hook injects")
  .action((dir?: string) => {
    print(contextFor(resolve(dir ?? process.cwd())) ?? "no vault project is bound to this directory");
  });

const hook = program.command("hook").description("Claude Code hook entrypoints");
hook
  .command("session-start")
  .description("SessionStart hook: reads the hook JSON on stdin and injects the bound project's vault context")
  .action(async () => {
    try {
      const raw = process.stdin.isTTY ? "{}" : await readStdin();
      const input = raw.trim() ? (JSON.parse(raw) as { cwd?: string }) : {};
      const text = contextFor(resolve(input.cwd ?? process.cwd()));
      if (text) {
        console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: text } }));
      }
    } catch {
      // a hook must never break session start
    }
    process.exit(0);
  });

program
  .command("ui")
  .description("Interactive explorer: browse, search, copy, view and edit items (also: run `cvault` with no arguments)")
  .action(async () => {
    if (!process.stdin.isTTY) throw new VaultError("interactive mode needs a terminal; see `cvault --help`");
    const { runUi } = await import("./ui.js");
    const vault = await openVault();
    try {
      await runUi(vault);
    } finally {
      vault.close();
    }
  });

program.addHelpText("after", "\nRun `cvault` with no arguments to open the interactive explorer.");

// bare `cvault` → interactive explorer (when attached to a terminal); `cvault --help` lists commands
const argv = process.argv.length <= 2 && process.stdin.isTTY ? [...process.argv, "ui"] : process.argv;

program.parseAsync(argv).catch((e: Error) => {
  console.error(`error: ${e.message}`);
  process.exit(1);
});
