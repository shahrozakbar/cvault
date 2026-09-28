#!/usr/bin/env node
import { Command } from "commander";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { vaultHome } from "./db.js";
import { auditTable, type ItemRowLike, itemsTable, printTable, versionsTable } from "./table.js";
import { collectItems, decryptBundle, encryptBundle, type ExportFormat, importItems, toEnv, toJson, writeExport } from "./export.js";
import { passwordFromEnv } from "./password.js";
import { formatRef, parseRef, parseScope, parseTarget, Vault, VaultError } from "./store.js";

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
  .description("List tenants, projects (tenant), services+items (tenant/project), or items (tenant/project/service)")
  .option("-a, --archived", "include archived entries")
  .option("--json", "print raw JSON instead of tables")
  .action(async (scope: string | undefined, o: { archived?: boolean; json?: boolean }) => {
    const vault = await openVault();
    const a = !!o.archived;
    type P = { tenant: string; project: string; name: string | null; services: number; bound_paths: string[]; allow_reveal: boolean; archived_at?: string };
    const p = scope ? parseScope(scope) : [];

    // items across every (non-archived) project in scope
    const itemsFor = (projects: P[]) =>
      projects.flatMap((pr) => {
        try {
          return vault.listItems(pr.tenant, pr.project, undefined, a) as unknown as ItemRowLike[];
        } catch {
          return []; // archived project
        }
      });

    if (p.length <= 1) {
      const projects = vault.listProjects(p[0], a) as unknown as P[];
      const items = itemsFor(projects);
      if (o.json) return print({ tenants: p[0] ? undefined : vault.listTenants(a), projects, items });
      printTable(
        ["TENANT", "PROJECT", "SERVICES", "ITEMS", "BOUND DIRECTORY", "CLAUDE REVEAL"],
        projects.map((pr) => [
          pr.tenant + (pr.archived_at ? " [archived]" : ""),
          pr.project,
          pr.services,
          items.filter((i) => i.ref.startsWith(`${pr.tenant}/${pr.project}/`)).length,
          pr.bound_paths.join(", ").replace(homedir(), "~"),
          pr.allow_reveal ? "on" : "off",
        ]),
        { title: `Projects (${projects.length})`, maxCol: 70 },
      );
      console.log();
      return console.log(itemsTable(items, "All items"));
    }
    if (p.length === 2) {
      const services = vault.listServices(p[0], p[1], a) as Array<{ service: string; name: string | null; url: string | null; notes: string | null; items: number; archived_at?: string }>;
      const items = vault.listItems(p[0], p[1], undefined, a) as unknown as ItemRowLike[];
      if (o.json) return print({ services, items });
      printTable(
        ["SERVICE", "URL", "ITEMS", "NOTES"],
        services.map((s) => [s.service + (s.archived_at ? " [archived]" : ""), s.url, s.items, s.notes]),
        { title: `Services of ${p[0]}/${p[1]} (${services.length})` },
      );
      console.log();
      return console.log(itemsTable(items));
    }
    const items = vault.listItems(p[0], p[1], p[2], a) as unknown as ItemRowLike[];
    if (o.json) return print(items);
    console.log(itemsTable(items, `Items of ${p.join("/")}`));
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
  .description("Bind a directory (default: cwd) to the project")
  .option("--remove", "unbind instead")
  .action(async (s: string, dir: string | undefined, o: { remove?: boolean }) => {
    const vault = await openVault();
    const [t, p] = projectParts(s);
    if (o.remove) {
      vault.unbindPath(t, p, dir ?? process.cwd());
      return print("unbound");
    }
    print(`bound ${vault.bindPath(t, p, dir ?? process.cwd())} → ${t}/${p}`);
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
  .action(async (s: string, o: { name?: string; url?: string; notes?: string }) => {
    const p = parseScope(s);
    if (p.length !== 3) throw new VaultError("expected tenant/project/service");
    (await openVault()).ensureService(p[0], p[1], p[2], o);
    print(`service ${s} ready`);
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
    print((await openVault()).archive(parseTarget(target), "cli"));
  });

program
  .command("restore <target>")
  .description("Restore an archived tenant, project, service or item")
  .action(async (target: string) => {
    print((await openVault()).restore(parseTarget(target), "cli"));
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
  .description("Import KEY=value lines from a .env file as secrets under tenant/project/service")
  .requiredOption("--into <tenant/project/service>")
  .action(async (envfile: string, o: { into: string }) => {
    const vault = await openVault();
    const p = parseScope(o.into);
    if (p.length !== 3) throw new VaultError("--into must be tenant/project/service");
    let n = 0;
    for (const line of readFileSync(envfile, "utf8").split(/\r?\n/)) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
      if (!m) continue;
      let val = m[2];
      if (/^".*"$/.test(val)) val = val.slice(1, -1).replace(/\\n/g, "\n").replace(/\\(["\\$])/g, "$1");
      else if (/^'.*'$/.test(val)) val = val.slice(1, -1);
      else val = val.replace(/\s+#.*$/, "");
      vault.setSecret({ tenant: p[0], project: p[1], service: p[2], key: m[1] }, val, undefined, "cli:import");
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
    const parts = scope ? parseScope(scope) : [];
    const label = parts.join("/") || "the whole vault";
    const plaintext = format !== "bundle";
    if (plaintext && !o.yes) {
      if (!process.stdin.isTTY) throw new VaultError("plaintext export needs confirmation — pass --yes");
      const ans = await promptLine(`Export ${label} as PLAINTEXT ${format}? Anyone with the file can read every secret. Type "yes": `);
      if (ans !== "yes") return print("cancelled — nothing exported");
    }
    const items = collectItems(vault, parts);
    if (!items.length) return print(`nothing to export in ${label}`);
    let content: string;
    let note = "";
    if (format === "bundle") {
      content = encryptBundle(items, await bundlePassphrase(true));
    } else if (format === "env") {
      const r = toEnv(items, parts.length);
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
    const path = writeExport(o.out ?? `cvault-${parts.join("-") || "all"}.${ext}`, content, { plaintext, overwrite: !!o.force });
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
      version: number;
    }>;
    const prefix = `${ctx.tenant}/${ctx.project}/`;
    const lines = items.slice(0, MAX_CONTEXT_ITEMS).map((i) => {
      const extra = [
        i.role ? `role: ${i.role}` : null,
        i.default ? "DEFAULT" : null,
        i.type === "credential" && i.fields ? `fields: ${i.fields.join(", ")}` : null,
        i.type === "file" && i.filename ? `file: ${i.filename}` : null,
        i.version > 1 ? `v${i.version}` : null,
        i.description ? `"${i.description}"` : null,
      ].filter(Boolean);
      return `- ${i.ref.slice(prefix.length)} (${i.type}${extra.length ? `; ${extra.join("; ")}` : ""})`;
    });
    if (items.length > MAX_CONTEXT_ITEMS) lines.push(`- … and ${items.length - MAX_CONTEXT_ITEMS} more (use list_items)`);
    return [
      `CVAULT: this working directory is bound to vault project "${ctx.tenant}/${ctx.project}" (bound path: ${ctx.bound_path}).`,
      `Credentials/secrets/files for this project live in the cvault MCP server (tools mcp__cvault__*). Short refs "service/key[#field]" resolve to this project — pass cwd="${dir}" to the tools.`,
      items.length ? `Available items (names only, no values):\n${lines.join("\n")}` : "No items stored yet for this project.",
      items.some((i) => i.role || i.default)
        ? "Choosing between credentials: if the user names a role (\"login as admin\"), use the item with that role; if no role is named, use the service's DEFAULT item; only ask the user when several items match and none is DEFAULT."
        : null,
      "When a task needs one of these credentials, fetch it from cvault instead of asking the user or searching .env files:",
      "use run_with_secrets / write_env_file / http_request / materialize_file (values stay hidden), sealed_fetch / sealed_save when the user wants to get/set a value themselves.",
      "If a credential the task needs is NOT listed above, immediately call mcp__cvault__request_credential (suggested_ref e.g. \"admin-panel/superadmin\", reason e.g. \"log into the admin panel\", fields if more than username/password are needed): it pops up secure dialogs where the user chooses the save path and enters the values. Then continue with the returned ref.",
      "Never use a credential from another environment/service to log in, and stop after ONE rejected login (accounts lock after a few attempts) - tell the user and offer request_credential on the same path to re-enter it.",
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
