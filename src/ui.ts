import { confirm as confirmP, input as inputP, password as passwordP, search, select, Separator } from "@inquirer/prompts";
import { emitKeypressEvents } from "node:readline";
import { existsSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { collectItems, encryptBundle, type ExportFormat, toEnv, toJson, writeExport } from "./export.js";
import { copyToClipboard } from "./sealed.js";
import { alignedRows, auditTable, type Cell, humanSize, itemsTable, renderTable } from "./table.js";
import { type ItemType, parseRef, type Ref, Vault, VaultError } from "./store.js";

/**
 * Interactive explorer. Every menu is a "page": the screen is cleared and redrawn with a header,
 * a breadcrumb and the result of the previous action (flash messages), then the menu itself.
 */

const SOURCE = "cli:ui";
const CLIP_SECONDS = 30;
const PAGE_SIZE = 20;
const BACK = "__back";
const SLUG = /^[a-z0-9][a-z0-9._-]*$/;
const KEY = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** prompts erase themselves when answered, so pages don't accumulate "✔ …" lines */
const CTX = { clearPromptOnDone: true };

// ---------- cancel handling: Esc cancels the running action (or goes back on a menu) ----------

/** set while an action runs: aborting it cancels every prompt of that action */
let actionSignal: AbortSignal | undefined;
const promptCtx = () => (actionSignal ? { ...CTX, signal: actionSignal } : CTX);

/** Abort `controller` when Esc is pressed; returns an unsubscribe function. */
function onEscape(controller: AbortController): () => void {
  emitKeypressEvents(process.stdin);
  const handler = (_: string, key?: { name?: string }) => {
    if (key?.name === "escape") controller.abort();
  };
  process.stdin.on("keypress", handler);
  return () => process.stdin.off("keypress", handler);
}

const isCancel = (e: unknown) => ["AbortPromptError", "ExitPromptError"].includes((e as Error)?.name);

const input = (cfg: Parameters<typeof inputP>[0]) => inputP(cfg, promptCtx());
const confirm = (cfg: Parameters<typeof confirmP>[0]) => confirmP(cfg, promptCtx());
const password = (cfg: Parameters<typeof passwordP>[0]) => passwordP(cfg, promptCtx());

const dim = (s: string) => `\x1b[2m${s}\x1b[22m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[22m`;
const green = (s: string) => `\x1b[32m${s}\x1b[39m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[39m`;
const red = (s: string) => `\x1b[31m${s}\x1b[39m`;
const cyan = (s: string) => `\x1b[36m${s}\x1b[39m`;
const inverse = (s: string) => `\x1b[7m${s}\x1b[27m`;

interface ItemInfo {
  ref: string;
  type: ItemType;
  fields?: string[];
  filename?: string;
  size?: number;
  description?: string;
  role?: string;
  default?: boolean;
  version: number;
  updated_at: string;
  archived_at?: string;
  locked?: { at: string; reason: string };
}

// ---------- page / flash ----------

let flash: string[] = [];
const ok = (msg: string) => flash.push(green(`✔ ${msg}`));
const fail = (msg: string) => flash.push(red(`✖ ${msg}`));
const note = (text: string) => flash.push(text);

const tilde = (p: string) => (p.startsWith(homedir()) ? "~" + p.slice(homedir().length) : p);
const termWidth = () => Math.min(process.stdout.columns || 100, 160);

function stats(vault: Vault): { projects: number; items: number } {
  const projects = vault.listProjects() as unknown as Array<{ tenant: string; project: string }>;
  let items = 0;
  for (const p of projects) items += vault.listItems(p.tenant, p.project).length;
  return { projects: projects.length, items };
}

/** Fit a line to the terminal width (ANSI-aware), ending with … when cut. */
function fit(line: string, w = termWidth()): string {
  const plain = line.replace(/\x1b\[[0-9;]*m/g, "");
  if ([...plain].length <= w) return line;
  return [...plain].slice(0, w - 1).join("") + "…";
}

/** Clear the screen and draw header, breadcrumb, optional info line and pending flash messages. */
function page(vault: Vault, crumbs: string[], info?: string): void {
  process.stdout.write("\x1b[H\x1b[2J");
  const s = stats(vault);
  const w = termWidth();
  console.log(
    fit(`${inverse(bold(" cvault "))} ${dim(`${s.items} item${s.items === 1 ? "" : "s"} in ${s.projects} project${s.projects === 1 ? "" : "s"} · ${tilde(vault.home)}`)}`, w),
  );
  console.log(fit(` ${crumbs.map((c, i) => (i === crumbs.length - 1 ? bold(cyan(c)) : c)).join(dim(" › "))}`, w));
  if (info) console.log(fit(` ${dim(info)}`, w));
  const hints = " Esc back/cancel · Ctrl+C quit ";
  console.log(dim("─".repeat(Math.max(2, w - hints.length - 2)) + hints + "──"));
  if (flash.length) {
    console.log(flash.join("\n"));
    console.log();
    flash = [];
  }
}

// ---------- menu helpers ----------

const backChoice = { name: dim("← back"), value: BACK };
const SECTION_WIDTH = 34;
/** Non-selectable section heading inside a menu (all the same width). */
const section = (title: string) =>
  new Separator(cyan(`── ${title} ${"─".repeat(Math.max(2, SECTION_WIDTH - title.length - 4))}`));

type Choice<T> = { name: string; value: T } | Separator;

/**
 * Arrow-key menu. Inside an action, Esc cancels the whole action; on a plain page, Esc returns BACK.
 */
async function menu<T>(message: string, choices: Choice<T>[], defaultValue?: T): Promise<T> {
  const cfg = { message, choices, pageSize: PAGE_SIZE, loop: false, default: defaultValue };
  if (actionSignal) return select<T>(cfg, promptCtx());
  const ac = new AbortController();
  const off = onEscape(ac);
  try {
    return await select<T>(cfg, { ...CTX, signal: ac.signal });
  } catch (e) {
    if ((e as Error).name === "AbortPromptError") return BACK as unknown as T;
    throw e;
  } finally {
    off();
  }
}

/**
 * A menu section rendered as an aligned table: header + rule (non-selectable) + one selectable row
 * each. If the table is wider than the terminal, columns named in `dropOrder` are removed one by
 * one (least important first) until it fits.
 */
function tableSection<T extends string | number>(
  headers: string[],
  rows: Array<{ cells: Cell[]; value: T }>,
  maxCols: Record<number, number> = {},
  empty = "(nothing here yet)",
  dropOrder: string[] = [],
): Choice<T>[] {
  if (!rows.length) return [new Separator(dim(` ${empty}`))];
  let keep = headers.map((_, i) => i);
  const build = () => {
    const limits: Record<number, number> = {};
    keep.forEach((orig, j) => {
      if (maxCols[orig] !== undefined) limits[j] = maxCols[orig];
    });
    // separators render with 1 leading char, choices with 2 (cursor + space) → indent the header by 1
    return alignedRows(
      keep.map((i) => headers[i]),
      rows.map((r) => keep.map((i) => r.cells[i])),
      { indent: 1, maxCol: 40, maxCols: limits },
    );
  };
  const visible = (line: string) => [...line.replace(/\x1b\[[0-9;]*m/g, "")].length;
  let t = build();
  for (const name of dropOrder) {
    if (visible(t.header) + 2 <= termWidth()) break;
    keep = keep.filter((i) => headers[i] !== name);
    t = build();
  }
  return [new Separator(t.header), new Separator(t.rule), ...rows.map((r, i) => ({ name: t.lines[i], value: r.value }))];
}

const status = (archived?: string) => (archived ? yellow("archived") : green("active"));
const keyOf = (ref: string) => ref.split("/").slice(3).join("/");
const fieldsOrFile = (i: ItemInfo) =>
  i.type === "credential" ? i.fields?.join(", ") : i.type === "file" ? `${i.filename} (${humanSize(i.size)})` : "";

/**
 * Run an action. Esc or Ctrl+C inside it cancels just the action; vault errors become flash
 * messages instead of crashing the UI.
 */
async function act(fn: () => unknown | Promise<unknown>): Promise<void> {
  const ac = new AbortController();
  const off = onEscape(ac);
  actionSignal = ac.signal;
  try {
    await fn();
  } catch (e) {
    if (isCancel(e)) note(dim("↩ cancelled — nothing changed"));
    else fail((e as Error).message);
  } finally {
    actionSignal = undefined;
    off();
  }
}

const slugPrompt = (message: string) =>
  input({ message, validate: (v) => SLUG.test(v) || "lowercase letters, digits, . _ - only" });
const keyPrompt = (message: string) =>
  input({ message, validate: (v) => KEY.test(v) || "letters, digits, . _ - only" });
const secretPrompt = (message: string) => password({ message, mask: "•", validate: (v) => v.length > 0 || "empty value" });
const isSecretField = (name: string) => /pass|secret|token|key|pin|otp/i.test(name);

function itemInfo(vault: Vault, ref: Ref): ItemInfo {
  const base = `${ref.tenant}/${ref.project}/${ref.service}/${ref.key}`;
  const info = (vault.listItems(ref.tenant, ref.project, ref.service) as unknown as ItemInfo[]).find((i) => i.ref === base);
  if (!info) throw new VaultError(`item ${base} not found`);
  return info;
}

function allItems(vault: Vault): ItemInfo[] {
  const all: ItemInfo[] = [];
  for (const p of vault.listProjects() as unknown as Array<{ tenant: string; project: string }>) {
    all.push(...(vault.listItems(p.tenant, p.project) as unknown as ItemInfo[]));
  }
  return all;
}

async function copy(vault: Vault, ref: Ref, label: string): Promise<void> {
  await copyToClipboard(vault.resolveValue(ref, SOURCE), CLIP_SECONDS);
  vault.audit(SOURCE, `${ref.tenant}/${ref.project}/${ref.service}/${ref.key}`, `copy${ref.field ? `#${ref.field}` : ""}`);
  ok(`${label} copied to clipboard — clears in ${CLIP_SECONDS}s`);
}

// ---------- entry ----------

export async function runUi(vault: Vault): Promise<void> {
  try {
    await mainMenu(vault);
  } catch (e) {
    if ((e as Error).name !== "ExitPromptError") throw e;
  }
  process.stdout.write("\x1b[H\x1b[2J");
  console.log(dim("cvault closed"));
}

async function mainMenu(vault: Vault): Promise<void> {
  for (;;) {
    const ctx = vault.resolveContext(process.cwd());
    page(vault, ["home"]);
    const a = await menu<string>("What do you want to do?", [
      ...(ctx ? [section("This directory"), { name: `${bold(`${ctx.tenant}/${ctx.project}`)}  ${dim(tilde(ctx.bound_path))}`, value: "ctx" }] : []),
      section("Find"),
      { name: "Search all items…", value: "search" },
      { name: "Browse tenants & projects", value: "browse" },
      section("Overview"),
      { name: "All items (table)", value: "table" },
      { name: "Audit log (last 30)", value: "audit" },
      { name: "Export the whole vault…", value: "export" },
      new Separator(" "),
      { name: dim("Quit"), value: "quit" },
    ]);
    if (a === "quit") return;
    if (a === "ctx" && ctx) await projectMenu(vault, ctx.tenant, ctx.project);
    if (a === "search") await searchAll(vault);
    if (a === "browse") await tenantsMenu(vault);
    if (a === "table") note(itemsTable(allItems(vault), "All items"));
    if (a === "audit") note(auditTable(vault.auditLog(30) as never));
    if (a === "export") await act(() => exportFlow(vault, []));
  }
}

async function searchAll(vault: Vault): Promise<void> {
  const all = allItems(vault);
  page(vault, ["home", "search"], "type to filter by ref, role, description or type");
  if (!all.length) return void note(dim("vault is empty"));
  const picked = await search<string>(
    {
      message: "Search",
      pageSize: PAGE_SIZE,
      source: (term) => {
        const t = (term ?? "").toLowerCase();
        const hits = all.filter((i) => !t || [i.ref, i.role, i.description, i.type].some((x) => x?.toLowerCase().includes(t)));
        return [
          ...tableSection(
            ["REF", "TYPE", "ROLE", "DEFAULT", "FIELDS / FILE", "VER", "DESCRIPTION"],
            hits.map((i) => ({
              cells: [i.ref, i.type, i.role, i.default ? yellow("yes") : "", fieldsOrFile(i), `v${i.version}`, i.description],
              value: i.ref,
            })),
            { 0: 0, 4: 0, 6: 30 },
            "no matches",
            ["DESCRIPTION", "VER", "DEFAULT", "ROLE", "TYPE"],
          ),
          { name: dim("← back"), value: BACK },
        ];
      },
    },
    CTX,
  );
  if (picked !== BACK) await itemMenu(vault, parseRef(picked));
}

// ---------- hierarchy ----------

async function tenantsMenu(vault: Vault): Promise<void> {
  for (;;) {
    const ts = vault.listTenants(true) as Array<{ tenant: string; name: string | null; projects: number; archived_at?: string }>;
    page(vault, ["home", "tenants"]);
    const a = await menu<string>("Pick a tenant", [
      ...tableSection(
        ["TENANT", "NAME", "PROJECTS", "STATUS"],
        ts.map((t) => ({ cells: [t.tenant, t.name, t.projects, status(t.archived_at)], value: t.tenant })),
      ),
      section("Actions"),
      { name: "+ New tenant…", value: "__new" },
      backChoice,
    ]);
    if (a === BACK) return;
    if (a === "__new") {
      await act(async () => {
        const slug = await slugPrompt("Tenant slug (e.g. acme)");
        const name = await input({ message: "Display name (optional)" });
        vault.ensureTenant(slug, name || undefined);
        ok(`tenant ${slug} created`);
      });
      continue;
    }
    const t = ts.find((x) => x.tenant === a)!;
    if (t.archived_at) {
      if (await confirm({ message: `Tenant ${t.tenant} is archived. Restore it?`, default: false })) {
        await act(() => ok(vault.restore([t.tenant], SOURCE)));
      }
      continue;
    }
    await projectsMenu(vault, t.tenant);
  }
}

async function projectsMenu(vault: Vault, tenant: string): Promise<void> {
  for (;;) {
    const ps = vault.listProjects(tenant, true) as unknown as Array<{
      project: string;
      name: string | null;
      services: number;
      bound_paths: string[];
      archived_at?: string;
    }>;
    page(vault, ["home", "tenants", tenant]);
    const a = await menu<string>("Pick a project", [
      ...tableSection(
        ["PROJECT", "NAME", "SERVICES", "LINKED DIRECTORY", "STATUS"],
        ps.map((p) => ({
          cells: [p.project, p.name, p.services, p.bound_paths.map(tilde).join(", "), status(p.archived_at)],
          value: p.project,
        })),
        { 3: 0 },
        undefined,
        ["NAME", "LINKED DIRECTORY"],
      ),
      section("Actions"),
      { name: "+ New project…", value: "__new" },
      { name: yellow("Archive this tenant"), value: "__archive" },
      backChoice,
    ]);
    if (a === BACK) return;
    if (a === "__new") {
      await act(async () => {
        const slug = await slugPrompt("Project slug (e.g. api-service)");
        vault.ensureProject(tenant, slug);
        ok(`project ${tenant}/${slug} created`);
        if (await confirm({ message: `Link the current directory (${tilde(process.cwd())}) to it?`, default: false })) {
          ok(`linked ${tilde(vault.bindPath(tenant, slug, process.cwd()))}`);
        }
      });
      continue;
    }
    if (a === "__archive") {
      if (await confirm({ message: `Archive tenant ${tenant} and hide everything under it?`, default: false })) {
        await act(() => ok(vault.archive([tenant], SOURCE)));
        return;
      }
      continue;
    }
    const p = ps.find((x) => x.project === a)!;
    if (p.archived_at) {
      if (await confirm({ message: `Project ${tenant}/${p.project} is archived. Restore it?`, default: false })) {
        await act(() => ok(vault.restore([tenant, p.project], SOURCE)));
      }
      continue;
    }
    await projectMenu(vault, tenant, p.project);
  }
}

function cwdCanonical(): string {
  try {
    return realpathSync(process.cwd());
  } catch {
    return process.cwd();
  }
}

/** Project page: every item of the project in one table (with its service), plus project actions. */
async function projectMenu(vault: Vault, tenant: string, project: string): Promise<void> {
  for (;;) {
    let info: { allow_reveal: boolean; bound_paths: string[] } | undefined;
    try {
      info = (vault.listProjects(tenant) as unknown as Array<{ project: string; allow_reveal: boolean; bound_paths: string[] }>).find(
        (p) => p.project === project,
      );
    } catch {
      /* archived */
    }
    if (!info) return;
    const items = vault.listItems(tenant, project) as unknown as ItemInfo[];
    const linkedHere = info.bound_paths.includes(cwdCanonical());
    page(
      vault,
      ["home", tenant, project],
      `linked: ${info.bound_paths.map(tilde).join(", ") || "none"} · Claude reveal: ${info.allow_reveal ? "ON" : "off"}`,
    );
    const a = await menu<string>("Pick an item", [
      ...tableSection(
        ["SERVICE", "KEY", "TYPE", "ROLE", "DEFAULT", "FIELDS / FILE", "VER", "DESCRIPTION"],
        items.map((i) => {
          const [, , service] = i.ref.split("/");
          return {
            cells: [service, keyOf(i.ref), i.type, i.role, i.default ? yellow("yes") : "", fieldsOrFile(i), `v${i.version}`, i.description],
            value: i.ref,
          };
        }),
        { 1: 0, 5: 0, 7: 30 },
        "no items yet — add one below",
        ["DESCRIPTION", "VER", "DEFAULT", "ROLE", "SERVICE"],
      ),
      section("Actions"),
      { name: "+ New item…", value: "__new" },
      { name: "Services…", value: "__services" },
      { name: "Export this project…", value: "__export" },
      ...(linkedHere ? [] : [{ name: `Link this directory ${dim(tilde(process.cwd()))}`, value: "__bind" }]),
      { name: `Turn Claude reveal ${info.allow_reveal ? "OFF" : "ON"}`, value: "__reveal" },
      { name: yellow("Archive this project"), value: "__archive" },
      backChoice,
    ]);
    if (a === BACK) return;
    if (a === "__new") await act(() => newItemFlow(vault, tenant, project));
    else if (a === "__services") await servicesMenu(vault, tenant, project);
    else if (a === "__export") await act(() => exportFlow(vault, [tenant, project]));
    else if (a === "__bind") await act(() => ok(`linked ${tilde(vault.bindPath(tenant, project, process.cwd()))}`));
    else if (a === "__reveal") {
      await act(() => {
        vault.setAllowReveal(tenant, project, !info!.allow_reveal);
        ok(`Claude reveal ${!info!.allow_reveal ? "ON" : "OFF"} for ${tenant}/${project}`);
      });
    } else if (a === "__archive") {
      if (await confirm({ message: `Archive project ${tenant}/${project}?`, default: false })) {
        await act(() => ok(vault.archive([tenant, project], SOURCE)));
        return;
      }
    } else await itemMenu(vault, parseRef(a));
  }
}

async function servicesMenu(vault: Vault, tenant: string, project: string): Promise<void> {
  for (;;) {
    const svcs = vault.listServices(tenant, project, true) as Array<{ service: string; url: string | null; items: number; archived_at?: string }>;
    page(vault, ["home", tenant, project, "services"]);
    const a = await menu<string>("Pick a service", [
      ...tableSection(
        ["SERVICE", "URL", "ITEMS", "STATUS"],
        svcs.map((s) => ({ cells: [s.service, s.url, s.items, status(s.archived_at)], value: s.service })),
        { 1: 50 },
      ),
      section("Actions"),
      { name: "+ New service…", value: "__new" },
      backChoice,
    ]);
    if (a === BACK) return;
    if (a === "__new") {
      await act(async () => ok(`service ${await createService(vault, tenant, project)} created`));
      continue;
    }
    const s = svcs.find((x) => x.service === a)!;
    if (s.archived_at) {
      if (await confirm({ message: `Service ${s.service} is archived. Restore it?`, default: false })) {
        await act(() => ok(vault.restore([tenant, project, s.service], SOURCE)));
      }
      continue;
    }
    await serviceMenu(vault, tenant, project, s.service);
  }
}

async function serviceMenu(vault: Vault, tenant: string, project: string, service: string): Promise<void> {
  for (;;) {
    let items: ItemInfo[];
    try {
      items = vault.listItems(tenant, project, service, true) as unknown as ItemInfo[];
    } catch {
      return;
    }
    page(vault, ["home", tenant, project, service]);
    const a = await menu<string>("Pick an item", [
      ...tableSection(
        ["KEY", "TYPE", "ROLE", "DEFAULT", "FIELDS / FILE", "VER", "DESCRIPTION"],
        items.map((i) => ({
          cells: [
            keyOf(i.ref) + (i.archived_at ? yellow(" [archived]") : ""),
            i.type,
            i.role,
            i.default ? yellow("yes") : "",
            fieldsOrFile(i),
            `v${i.version}`,
            i.description,
          ],
          value: i.ref,
        })),
        { 0: 0, 4: 0, 6: 30 },
        undefined,
        ["DESCRIPTION", "VER", "DEFAULT", "ROLE"],
      ),
      section("Actions"),
      { name: "+ New credential…", value: "__cred" },
      { name: "+ New secret…", value: "__secret" },
      { name: "+ Upload file…", value: "__file" },
      { name: `Allowed hosts… ${dim(`(${vault.allowedHosts(tenant, project, service).join(", ") || "any"})`)}`, value: "__hosts" },
      { name: yellow("Archive this service"), value: "__archive" },
      backChoice,
    ]);
    if (a === BACK) return;
    if (a === "__cred") await act(() => newCredential(vault, tenant, project, service));
    else if (a === "__secret") await act(() => newSecret(vault, tenant, project, service));
    else if (a === "__file") await act(() => newFile(vault, tenant, project, service));
    else if (a === "__hosts") {
      await act(async () => {
        const current = vault.allowedHosts(tenant, project, service).join(", ");
        const answer = await input({
          message: "Hosts this service's secrets may be sent to (comma-separated, *.example.com allowed; empty = any)",
          default: current,
        });
        const hosts = vault.setAllowedHosts(tenant, project, service, answer.split(/[,\s]+/), SOURCE);
        ok(`allowed hosts for ${service}: ${hosts.join(", ") || "any (no restriction)"}`);
      });
    }
    else if (a === "__archive") {
      if (await confirm({ message: `Archive service ${service}?`, default: false })) {
        await act(() => ok(vault.archive([tenant, project, service], SOURCE)));
        return;
      }
    } else {
      const i = items.find((x) => x.ref === a)!;
      if (i.archived_at) {
        if (await confirm({ message: `${i.ref} is archived. Restore it?`, default: false })) {
          await act(() => ok(vault.restore(i.ref.split("/"), SOURCE)));
        }
        continue;
      }
      await itemMenu(vault, parseRef(i.ref));
    }
  }
}

// ---------- create ----------

async function createService(vault: Vault, tenant: string, project: string): Promise<string> {
  const slug = await slugPrompt("Service slug (e.g. postgres, stripe, admin-panel)");
  const url = await input({ message: "URL (optional)" });
  vault.ensureService(tenant, project, slug, url ? { url } : {});
  return slug;
}

async function newItemFlow(vault: Vault, tenant: string, project: string): Promise<void> {
  const svcs = vault.listServices(tenant, project) as Array<{ service: string; url: string | null }>;
  let service = await menu<string>("Which service?", [
    ...svcs.map((s) => ({ name: `${s.service}${s.url ? dim(`  ${s.url}`) : ""}`, value: s.service })),
    { name: "+ New service…", value: "__new" },
  ]);
  if (service === "__new") service = await createService(vault, tenant, project);
  const type = await menu<string>("What kind of item?", [
    { name: `Credential ${dim("username + password (+ more fields)")}`, value: "cred" },
    { name: `Secret ${dim("a single value: API key, token, connection string")}`, value: "secret" },
    { name: `File ${dim("key, certificate, service-account JSON, kubeconfig")}`, value: "file" },
  ]);
  if (type === "cred") await newCredential(vault, tenant, project, service);
  if (type === "secret") await newSecret(vault, tenant, project, service);
  if (type === "file") await newFile(vault, tenant, project, service);
}

async function askTags(vault: Vault, ref: Ref): Promise<void> {
  const role = await input({ message: "Role (optional, e.g. admin, viewer)" });
  const isDefault = await confirm({ message: "Default item of this service?", default: false });
  if (role || isDefault) vault.tagItem(ref, { role: role || undefined, isDefault: isDefault || undefined }, SOURCE);
}

async function newCredential(vault: Vault, t: string, p: string, s: string): Promise<void> {
  const key = await keyPrompt("Name (e.g. superadmin, readonly-user)");
  const ref: Ref = { tenant: t, project: p, service: s, key };
  const fields: Record<string, string> = {};
  const username = await input({ message: "username (optional)" });
  if (username) fields.username = username;
  fields.password = await secretPrompt("password");
  while (await confirm({ message: "Add another field (host, url, token, …)?", default: false })) {
    const name = await keyPrompt("Field name");
    fields[name] = isSecretField(name) ? await secretPrompt(`${name} (hidden)`) : await input({ message: name });
  }
  const description = await input({ message: "Description (optional)" });
  vault.setCredential(ref, fields, description || undefined, SOURCE);
  await askTags(vault, ref);
  ok(`stored ${t}/${p}/${s}/${key} [${Object.keys(fields).join(", ")}]`);
}

async function newSecret(vault: Vault, t: string, p: string, s: string): Promise<void> {
  const key = await keyPrompt("Name (e.g. api_key, DATABASE_URL)");
  const ref: Ref = { tenant: t, project: p, service: s, key };
  const value = await secretPrompt("Value (hidden)");
  const description = await input({ message: "Description (optional)" });
  vault.setSecret(ref, value, description || undefined, SOURCE);
  await askTags(vault, ref);
  ok(`stored ${t}/${p}/${s}/${key}`);
}

async function newFile(vault: Vault, t: string, p: string, s: string): Promise<void> {
  const key = await keyPrompt("Name (e.g. service-account, deploy-key)");
  const src = await input({ message: "Path of the file to upload", validate: (v) => existsSync(resolve(v)) || "file not found" });
  const description = await input({ message: "Description (optional)" });
  const r = vault.putFile({ tenant: t, project: p, service: s, key }, resolve(src), description || undefined, SOURCE);
  ok(`stored ${r.filename} (${humanSize(r.size)}) as ${t}/${p}/${s}/${key}`);
}

// ---------- export ----------

async function exportFlow(vault: Vault, scope: string[]): Promise<void> {
  const label = scope.join("/") || "the whole vault";
  const format = await menu<ExportFormat>(`Export ${label} as…`, [
    { name: `Encrypted bundle ${dim("(recommended) passphrase-protected, includes files · restore with cvault import-bundle")}`, value: "bundle" },
    { name: `.env file ${dim("PLAINTEXT KEY=value — credentials become KEY_FIELD, files skipped")}`, value: "env" },
    { name: `JSON ${dim("PLAINTEXT, nested by tenant/project/service")}`, value: "json" },
  ]);
  const plaintext = format !== "bundle";
  const ext = format === "bundle" ? "cvault" : format;
  const target = resolve(await input({ message: "Save to", default: `./cvault-${scope.join("-") || "all"}.${ext}` }));
  if (plaintext && !(await confirm({ message: yellow(`Write ${label} as PLAINTEXT? Anyone with the file can read every secret.`), default: false }))) {
    note(dim("↩ cancelled — nothing exported"));
    return;
  }
  let overwrite = false;
  if (existsSync(target)) {
    overwrite = await confirm({ message: `${tilde(target)} exists — overwrite?`, default: false });
    if (!overwrite) return void note(dim("↩ cancelled — nothing exported"));
  }
  let passphrase = "";
  if (format === "bundle") {
    passphrase = await password({ message: "Bundle passphrase (min 8 chars)", mask: "•", validate: (v) => v.length >= 8 || "at least 8 characters" });
    if ((await password({ message: "Repeat passphrase", mask: "•" })) !== passphrase) throw new VaultError("passphrases do not match — nothing exported");
  }
  const items = collectItems(vault, scope, SOURCE);
  if (!items.length) return void note(dim(`nothing to export in ${label}`));
  let content: string;
  let extra = "";
  if (format === "bundle") content = encryptBundle(items, passphrase);
  else if (format === "env") {
    const r = toEnv(items, scope.length);
    content = r.text;
    if (r.skipped.length) extra = ` · skipped ${r.skipped.length} file item(s)`;
  } else content = toJson(items);
  const path = writeExport(target, content, { plaintext, overwrite });
  ok(`exported ${items.length} item(s) from ${label} → ${tilde(path)} (${plaintext ? "PLAINTEXT" : "encrypted"}, mode 600)${extra}`);
}

// ---------- item ----------

function detailsTable(info: ItemInfo): string {
  return renderTable(
    ["PROPERTY", "VALUE"],
    [
      ["ref", info.ref],
      ["type", info.type],
      ...(info.type === "credential" ? [["fields", info.fields?.join(", ")] as Cell[]] : []),
      ...(info.type === "file" ? [["file", `${info.filename} (${humanSize(info.size)})`] as Cell[]] : []),
      ["role", info.role ? `${info.role}${info.default ? " (default)" : ""}` : info.default ? "(default)" : ""],
      ["version", `v${info.version} · updated ${info.updated_at} UTC`],
      ["description", info.description],
      ...(info.locked ? [["LOCKED", `${info.locked.at} UTC - ${info.locked.reason}`] as Cell[]] : []),
    ],
    { maxCol: 0 },
  );
}

async function itemMenu(vault: Vault, ref: Ref): Promise<void> {
  let last: string | undefined;
  for (;;) {
    let info: ItemInfo;
    try {
      info = itemInfo(vault, ref);
    } catch {
      return; // archived or gone
    }
    const key = keyOf(info.ref);
    page(vault, ["home", ref.tenant, ref.project, ref.service, key]);
    console.log(detailsTable(info));

    const copyOpts =
      info.type === "credential"
        ? (info.fields ?? []).map((f) => ({ name: `Copy ${bold(f)}`, value: `copy:${f}` }))
        : [{ name: info.type === "file" ? "Copy file contents" : "Copy value", value: "copy" }];
    const viewOpts = [
      info.type === "file"
        ? { name: "Save file to disk…", value: "save" }
        : { name: info.type === "credential" ? "Show all fields" : "Show value", value: "show" },
      { name: `Version history… ${dim(`(${info.version} version${info.version > 1 ? "s" : ""})`)}`, value: "versions" },
    ];
    const editOpts = [
      ...(info.type === "secret" ? [{ name: "Change value…", value: "edit" }] : []),
      ...(info.type === "credential"
        ? [
            { name: "Edit a field…", value: "editfield" },
            { name: "Add a field…", value: "addfield" },
            { name: "Remove a field…", value: "rmfield" },
          ]
        : []),
      ...(info.type === "file" ? [{ name: "Replace with another file…", value: "replace" }] : []),
    ];

    const a = await menu<string>(`${bold(key)} — choose an action`, [
      section("Copy to clipboard"),
      ...copyOpts,
      section("View"),
      ...viewOpts,
      section("Edit (saves a new version)"),
      ...editOpts,
      section("Labels & lifecycle"),
      { name: "Role / default / description…", value: "tags" },
      ...(info.locked ? [{ name: yellow("Unlock (allow Claude to use it again)"), value: "unlock" }] : []),
      { name: yellow("Archive this item"), value: "archive" },
      backChoice,
    ], last);
    if (a === BACK) return;
    last = a;
    await act(async () => {
      if (a === "copy") await copy(vault, ref, info.type === "file" ? "file contents" : "value");
      else if (a.startsWith("copy:")) await copy(vault, { ...ref, field: a.slice(5) }, a.slice(5));
      else if (a === "show") showItem(vault, ref);
      else if (a === "edit") {
        const value = await secretPrompt("New value (hidden)");
        const again = await secretPrompt("Repeat");
        if (value !== again) throw new VaultError("values did not match — nothing saved");
        ok(`saved as v${vault.setSecret(ref, value, undefined, SOURCE)}`);
      } else if (a === "editfield") await editField(vault, ref, info);
      else if (a === "addfield") await addField(vault, ref);
      else if (a === "rmfield") await removeField(vault, ref, info);
      else if (a === "save") await saveFile(vault, ref);
      else if (a === "replace") {
        const src = await input({ message: "Path of the new file", validate: (v) => existsSync(resolve(v)) || "file not found" });
        ok(`saved as v${vault.putFile(ref, resolve(src), undefined, SOURCE).version}`);
      } else if (a === "tags") await editTags(vault, ref, info);
      else if (a === "unlock") {
        vault.unlockItem(ref, SOURCE);
        ok(`unlocked ${info.ref}`);
      }
      else if (a === "versions") await versionsMenu(vault, ref, info);
      else if (a === "archive") {
        if (await confirm({ message: `Archive ${info.ref}?`, default: false })) ok(vault.archive(info.ref.split("/"), SOURCE));
      }
    });
  }
}

function showItem(vault: Vault, ref: Ref): void {
  const item = vault.getItem(ref, SOURCE);
  const title = `${keyOf(`${ref.tenant}/${ref.project}/${ref.service}/${ref.key}`)} (v${item.version}) ${dim("— visible until your next action")}`;
  const rows = typeof item.value === "string" ? [["value", item.value]] : Object.entries(item.value);
  note(renderTable(["FIELD", "VALUE"], rows, { title, maxCol: 0 }));
}

async function credentialFields(vault: Vault, ref: Ref): Promise<Record<string, string>> {
  return vault.getItem({ ...ref, field: undefined }, SOURCE).value as Record<string, string>;
}

async function editField(vault: Vault, ref: Ref, info: ItemInfo): Promise<void> {
  const field = await menu<string>("Field to edit", (info.fields ?? []).map((f) => ({ name: f, value: f })));
  const fields = await credentialFields(vault, ref);
  fields[field] = isSecretField(field)
    ? await secretPrompt(`New ${field} (hidden)`)
    : await input({ message: `New ${field}`, default: fields[field] });
  ok(`${field} updated — saved as v${vault.setCredential(ref, fields, undefined, SOURCE)}`);
}

async function addField(vault: Vault, ref: Ref): Promise<void> {
  const name = await keyPrompt("Field name (e.g. host, url, otp_secret)");
  const fields = await credentialFields(vault, ref);
  if (name in fields && !(await confirm({ message: `${name} exists — overwrite?`, default: false }))) return;
  const hidden = isSecretField(name) || (await confirm({ message: "Hide input?", default: false }));
  fields[name] = hidden ? await secretPrompt(`${name} (hidden)`) : await input({ message: name });
  ok(`${name} added — saved as v${vault.setCredential(ref, fields, undefined, SOURCE)}`);
}

async function removeField(vault: Vault, ref: Ref, info: ItemInfo): Promise<void> {
  if ((info.fields ?? []).length <= 1) throw new VaultError("a credential needs at least one field");
  const field = await menu<string>("Field to remove", (info.fields ?? []).map((f) => ({ name: f, value: f })));
  if (!(await confirm({ message: `Remove ${field}? (older versions keep it)`, default: false }))) return;
  const fields = await credentialFields(vault, ref);
  delete fields[field];
  ok(`${field} removed — saved as v${vault.setCredential(ref, fields, undefined, SOURCE)}`);
}

async function saveFile(vault: Vault, ref: Ref): Promise<void> {
  const { filename, content, version } = vault.readFile(ref, SOURCE);
  const target = resolve(await input({ message: "Save to", default: `./${filename}` }));
  if (existsSync(target) && !(await confirm({ message: `${tilde(target)} exists — overwrite?`, default: false }))) return;
  writeFileSync(target, content, { mode: 0o600 });
  ok(`wrote ${tilde(target)} (v${version}, mode 600)`);
}

async function editTags(vault: Vault, ref: Ref, info: ItemInfo): Promise<void> {
  const role = await input({ message: "Role (empty = none)", default: info.role ?? "" });
  const isDefault = await confirm({ message: "Default item of this service?", default: !!info.default });
  const description = await input({ message: "Description (empty = none)", default: info.description ?? "" });
  const r = vault.tagItem(ref, { role: role || null, isDefault, description: description || null }, SOURCE);
  ok(`labels saved — role: ${r.role ?? "none"}, default: ${r.default ? "yes" : "no"}`);
}

async function versionsMenu(vault: Vault, ref: Ref, info: ItemInfo): Promise<void> {
  const key = keyOf(info.ref);
  for (;;) {
    const versions = vault.listVersions(ref) as Array<{
      version: number;
      current: boolean;
      created_at: string;
      source: string | null;
      fields?: string[];
      filename?: string;
    }>;
    page(vault, ["home", ref.tenant, ref.project, ref.service, key, "versions"]);
    const v = await menu<number | string>("Pick a version", [
      ...tableSection(
        ["VERSION", "CURRENT", "CREATED (UTC)", "SOURCE", "FIELDS / FILE"],
        versions.map((x) => ({
          cells: [`v${x.version}`, x.current ? green("yes") : "", x.created_at, x.source, x.fields?.join(", ") ?? x.filename],
          value: x.version,
        })),
        { 4: 0 },
        undefined,
        ["SOURCE", "FIELDS / FILE"],
      ),
      new Separator(" "),
      backChoice,
    ]);
    if (v === BACK) return;
    const version = v as number;
    const vref: Ref = { ...ref, version };
    const fields = versions.find((x) => x.version === version)?.fields;
    page(vault, ["home", ref.tenant, ref.project, ref.service, key, `v${version}`]);
    const a = await menu<string>(`${bold(`v${version}`)} of ${key} — choose an action`, [
      section("Copy to clipboard"),
      ...(info.type === "credential" && fields
        ? fields.map((f) => ({ name: `Copy ${bold(f)}`, value: `copy:${f}` }))
        : [{ name: info.type === "file" ? "Copy file contents" : "Copy value", value: "copy" }]),
      section("View"),
      ...(info.type === "file" ? [{ name: "Save file to disk…", value: "save" }] : [{ name: "Show", value: "show" }]),
      ...(version !== info.version ? [section("Restore"), { name: `Roll back to v${version} ${dim("(copied forward as a new version)")}`, value: "rollback" }] : []),
      backChoice,
    ]);
    await act(async () => {
      if (a === "copy") await copy(vault, vref, `v${version}`);
      else if (a.startsWith("copy:")) await copy(vault, { ...vref, field: a.slice(5) }, `${a.slice(5)} (v${version})`);
      else if (a === "show") showItem(vault, vref);
      else if (a === "save") await saveFile(vault, vref);
      else if (a === "rollback") ok(`v${version} is now current as v${vault.rollback(ref, version, SOURCE)}`);
    });
    if (a === "rollback") return;
  }
}
