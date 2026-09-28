# 🔐 cvault

**A local, encrypted, multi-tenant password manager for Claude Code.** Claude can *use* your credentials (run commands, write `.env` files, call APIs) without the values ever entering the chat, and you get a fast terminal UI to browse, copy and edit them.

```
tenant (client / workspace)
 └─ project                     ← linked to a directory on disk
     └─ service                 (postgres, stripe, admin-panel, …)
         └─ item                secret · credential (multi-field) · file
                                 ├─ role + default   ("log in as admin")
                                 └─ versions v1, v2, … (never deleted)
```

<table>
<tr><td>

**For Claude (MCP server)**
- Uses secrets **without seeing them**: output is scrubbed to `***`
- **Sealed mode**: you type or receive values in a native macOS dialog or on the clipboard
- Knows the current project's credentials at **session start** (hook)
- Picks the right credential by **role**, or falls back to the default

</td><td>

**For you (CLI + interactive UI)**
- `cvault`: arrow-key explorer with tables, search, copy, edit
- Every change is a **new version**; roll back any time
- **Archive** instead of delete, restorable at any level
- Full **audit log** of every access

</td></tr>
</table>

---

## Contents

- [Quick start](#quick-start)
- [How Claude uses it](#how-claude-uses-it)
- [Interactive explorer](#interactive-explorer)
- [CLI reference](#cli-reference)
- [MCP tools](#mcp-tools)
- [Concepts](#concepts): refs · roles & defaults · versioning · archive · directory linking
- [Security model](#security-model)
- [Development](#development)

---

## Quick start

```bash
git clone <this repo> ~/mcp/vault-mcp && cd ~/mcp/vault-mcp
npm install && npm run build
npm link                       # puts `cvault` on your PATH

# 1. store a random master password in the macOS Keychain and create the vault
security add-generic-password -a "$USER" -s vault-mcp -w "$(openssl rand -base64 33)"
export VAULT_MASTER_PASSWORD_CMD='security find-generic-password -s vault-mcp -w'   # add to ~/.zshrc
cvault init

# 2. register the MCP server with Claude Code (user scope = every project)
claude mcp add cvault -s user \
  -e VAULT_MASTER_PASSWORD_CMD='security find-generic-password -s vault-mcp -w' \
  -- "$(which node)" ~/mcp/vault-mcp/dist/index.js

# 3. (recommended) SessionStart hook, so Claude knows each project's credentials
#    add to ~/.claude/settings.json → hooks.SessionStart:
#    { "hooks": [{ "type": "command", "timeout": 10,
#                  "command": "node ~/mcp/vault-mcp/dist/cli.js hook session-start" }] }

# 4. add your first project, linked to its directory
cvault project add acme/api --bind ~/work/acme-api
cvault set-cred acme/api/admin-panel/superadmin -u root --role admin --default   # password prompted, hidden
```

> The vault lives in `~/.vault-mcp/` (override with `VAULT_HOME`). The master password never leaves the Keychain.

---

## How Claude uses it

Start Claude inside a linked directory and the session hook tells it which items exist (names only, never values):

```
CVAULT: this working directory is bound to vault project "acme/api"
Available items (names only, no values):
- admin-panel/superadmin (credential; role: admin; DEFAULT; fields: username, password, url)
- admin-panel/auditor    (credential; role: viewer; fields: username, password)
- stripe/api_key         (secret; "Stripe live key")
```

Then just ask:

| You say | Claude does | Claude sees |
|---|---|---|
| "run the migrations with the DB creds" | `run_with_secrets` with `PGPASSWORD` ← `postgres/app` | command output with `***` |
| "create the .env for this project" | `write_env_file` (0600, refuses if not gitignored) | the list of keys written |
| "list Stripe customers" | `http_request` with `Bearer {{secret:stripe/api_key}}` | the response, scrubbed |
| "log into the admin panel as viewer" | picks `admin-panel/auditor` by role | nothing secret |
| "save the OpenAI key **sealed**" | `sealed_save` opens a masked macOS dialog | `stored … as v1` |
| "give me the DB password **sealed**" | `sealed_fetch` copies it to your clipboard (auto-clears in 30s) | `copied` |

---

## Interactive explorer

Run **`cvault`** with no arguments (or `cvault ui`). `cvault --help` lists the scriptable commands.

```
 cvault  5 items in 1 project · ~/.vault-mcp
 home › acme › api
──────────────────────────────────────────────── Esc back/cancel · Ctrl+C quit ──
? Pick an item
  SERVICE     │ KEY        │ TYPE       │ ROLE   │ DEFAULT │ FIELDS / FILE           │ VER │ DESCRIPTION
  ────────────┼────────────┼────────────┼────────┼─────────┼─────────────────────────┼─────┼────────────────
❯ admin-panel │ auditor    │ credential │ viewer │ -       │ username, password      │ v1  │ Read-only
  admin-panel │ superadmin │ credential │ admin  │ yes     │ username, password, url │ v2  │ Full access
  ssh         │ deploy-key │ file       │ -      │ -       │ deploy.pem (412 B)      │ v1  │ CI deploy key
  stripe      │ api_key    │ secret     │ -      │ -       │ -                       │ v3  │ Stripe live key
 ── Actions ──────────────────────
  + New item…
  Services…
```

- **Navigate:** opens at the project linked to your current directory; search across all items by ref, role or description.
- **Copy** any secret or credential field. The clipboard auto-clears after 30s, even if you've already quit.
- **View** all fields, version history and the audit log as tables.
- **Edit** values and fields, add or remove fields, replace files. Each change saves a new version.
- **Labels:** role, default and description, without creating a new version.
- **Manage:** create tenants, projects, services and items; link directories; toggle Claude reveal; archive and restore; roll back.
- **Keys:** `↑↓` move · `⏎` select · **`Esc`** back / cancel the current action · `Ctrl+C` quit.
- **Responsive:** tables drop low-priority columns on narrow terminals.

---

## CLI reference

| Command | What it does |
|---|---|
| `cvault` / `cvault ui` | interactive explorer |
| `cvault init` | create the vault |
| `cvault ls [scope] [--archived] [--json]` | tables of projects, services and **all items** |
| `cvault project add <t/p> [--bind dir]` | create a project, optionally linked to a directory |
| `cvault project bind <t/p> [dir] [--remove]` | link or unlink a directory |
| `cvault project reveal <t/p> on\|off` | allow Claude to read plaintext (`reveal_secret`) |
| `cvault service <t/p/s> [--url]` | create or update a service |
| `cvault set <ref> [--stdin] [-r role] [--default]` | store a secret (hidden prompt) |
| `cvault set-cred <ref> -u user [-f k=v] [-r role] [--default]` | store a credential (password prompted, hidden) |
| `cvault put-file <ref> <file>` | encrypt a file into the vault |
| `cvault get <ref>[@N][#field] [--out file]` | print a value (credentials as a table) |
| `cvault tag <ref> [-r role] [--default\|--no-default]` | set labels, no new version |
| `cvault versions <ref>` · `cvault rollback <ref> <N>` | history and roll back |
| `cvault archive <target>` · `cvault restore <target>` | archive or restore a tenant, project, service or item |
| `cvault import .env --into <t/p/s>` | bulk-import a `.env` file |
| `cvault context [dir]` | preview what the session hook injects |
| `cvault audit [-n N] [-r prefix]` | access log |
| `cvault backup <dir>` · `cvault change-password` | maintenance |

---

## MCP tools

| Group | Tools |
|---|---|
| Browse (no values) | `vault_status` · `resolve_context` · `list_tenants` · `list_projects` · `list_services` · `list_items` · `audit_log` |
| Use (values hidden) | `run_with_secrets` · `write_env_file` · `materialize_file` · `http_request` |
| Sealed (you ↔ vault) | `sealed_save` (masked dialog) · `sealed_fetch` (clipboard or dialog) |
| Manage | `create_tenant` · `create_project` · `create_service` · `bind_project_path` · `set_secret` · `set_credential` · `generate_secret` · `put_file` · `tag_item` |
| Versions & archive | `list_versions` · `rollback_secret` · `archive` · `restore` |
| Reveal (opt-in) | `reveal_secret`: only when you've enabled it per project with the CLI |

---

## Concepts

### Refs
`tenant/project/service/key[@version][#field]`. For example `acme/api/postgres/app#username` or `acme/api/stripe/api_key@2`. Inside a linked directory, the short form `service/key` works too. Credentials default to the `password` field.

### Roles & defaults
Give credentials a `role` (admin, viewer, tester, …) and mark one per service as the **default**. "Log in as viewer" picks the viewer item; with no role named, Claude uses the default and only asks when neither applies.

### Versioning
Every write creates version N+1. Old versions stay encrypted (and old files are kept as `<uid>.vN.bin`). `@N` reads any version; `rollback` copies an old version forward as a **new** version, so history is never rewritten.

### Archive, never delete
Archive a tenant, project, service or single item. It's hidden and unusable but fully restorable. Archiving a tenant hides everything under it.

### Directory linking
`cvault project bind` links a directory (and its subdirectories; the most specific link wins) to a project. This drives short refs, the explorer's start page and the SessionStart hook.

---

## Security model

- **Crypto:** master password → scrypt (N=2¹⁷) → key-encryption key, which wraps a random 256-bit data key. Every value and file is encrypted with **AES-256-GCM**, with the item's UUID as additional authenticated data. Metadata (names, roles, bindings) is stored unencrypted, so the session hook needs no password.
- **Master password** comes from the macOS Keychain via `VAULT_MASTER_PASSWORD_CMD`, and is removed from the server's environment at startup so child processes never inherit it.
- **Claude never sees values by default.** Injected secrets are scrubbed (raw, base64 and URL-encoded) from command and HTTP output. `reveal_secret` is off per project, and only the CLI can turn it on.
- **Sealed mode:** values travel through native macOS dialogs or the clipboard, never through tool arguments or results. They're passed to `osascript` via env, not argv.
- **Guardrails:** `.env` and file writes into a git repo are refused unless the file is gitignored, and files are written with mode 0600.
- **Audit log** of every use, reveal, copy and edit. It never records values.

> **Limit:** scrubbing keeps secrets out of the conversation and transcripts. It is not a sandbox, so a command can still misuse an injected secret on purpose. Review commands that come from untrusted content.

---

## Development

```bash
npm run build        # tsc → dist/
npm test             # vitest (crypto, versioning, archive, roles, injection, scrubbing)
npx @modelcontextprotocol/inspector node dist/index.js
```

```
src/
  index.ts    MCP server (tools, sealed mode, reveal gate)
  cli.ts      cvault CLI + SessionStart hook
  ui.ts       interactive explorer
  store.ts    vault: hierarchy, versioned items, archive, roles, audit
  crypto.ts   scrypt + AES-256-GCM
  inject.ts   run / .env / file / http injection + scrubbing
  sealed.ts   macOS dialogs + clipboard with auto-clear
  table.ts    table rendering
  db.ts       SQLite schema + migrations
```
