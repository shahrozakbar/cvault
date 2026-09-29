/** Minimal box-drawing table renderer for CLI output (ANSI-aware widths, no index column, no quotes). */

const ANSI = /\x1b\[[0-9;]*m/g;
const width = (s: string) => [...s.replace(ANSI, "")].length;

// colors only on a real terminal (and never when NO_COLOR is set), so piped output stays clean
const COLOR = !!process.stdout.isTTY && !process.env.NO_COLOR;
const bold = (s: string) => (COLOR ? `\x1b[1m${s}\x1b[22m` : s);
const dim = (s: string) => (COLOR ? `\x1b[2m${s}\x1b[22m` : s);

export type Cell = string | number | boolean | null | undefined;

function cellText(v: Cell): string {
  if (v === null || v === undefined || v === "") return dim("-");
  if (v === true) return "yes";
  if (v === false) return dim("no");
  return String(v).replace(/\r?\n/g, "⏎");
}

function truncate(s: string, max: number): string {
  if (width(s) <= max) return s;
  const plain = s.replace(ANSI, "");
  return [...plain].slice(0, Math.max(1, max - 1)).join("") + "…";
}

interface TableOpts {
  title?: string;
  /** default max width per column (0 = unlimited) */
  maxCol?: number;
  /** per-column overrides, by index (0 = unlimited) */
  maxCols?: Record<number, number>;
  /** total width to fit in (default: terminal width on a TTY, unlimited when piped) */
  maxWidth?: number;
  /** column headers to drop, least important first, while the table is too wide */
  dropOrder?: string[];
  /** column headers to shorten (with …) next, while still too wide */
  shrink?: string[];
  /**
   * Explicit fitting plan, applied in order while the table is too wide (overrides dropOrder/shrink):
   * { drop: "HEADER" } hides a column; { shrink: "HEADER", min: n } shortens it down to n chars.
   */
  steps?: Array<{ drop: string } | { shrink: string; min?: number }>;
}

const MIN_COL = 8;

/** Terminal width on a TTY; unlimited when piped so files/scripts get the full table. */
export function terminalWidth(): number {
  return process.stdout.isTTY && process.stdout.columns ? process.stdout.columns : Number.POSITIVE_INFINITY;
}

export function renderTable(headers: string[], rows: Cell[][], opts: TableOpts = {}): string {
  const limit = (i: number) => opts.maxCols?.[i] ?? opts.maxCol ?? 60;
  const raw = rows.map((r) => headers.map((_, i) => cellText(r[i])));
  const natural = (i: number) =>
    Math.max(width(headers[i]), ...raw.map((r) => (limit(i) ? Math.min(width(r[i]), limit(i)) : width(r[i]))));
  let keep = headers.map((_, i) => i);
  const w = new Map(keep.map((i) => [i, natural(i)]));
  const total = () => keep.reduce((sum, i) => sum + w.get(i)! + 3, 1);
  const max = opts.maxWidth ?? terminalWidth();

  const steps =
    opts.steps ??
    ([...(opts.dropOrder ?? []).map((drop) => ({ drop })), ...(opts.shrink ?? []).map((shrink) => ({ shrink }))] as NonNullable<TableOpts["steps"]>);
  for (const step of steps) {
    if (total() <= max) break;
    if ("drop" in step) {
      if (keep.length > 1) keep = keep.filter((i) => headers[i] !== step.drop);
    } else {
      const i = headers.indexOf(step.shrink);
      if (!keep.includes(i)) continue;
      const floor = Math.max((step as { shrink: string; min?: number }).min ?? MIN_COL, width(headers[i]));
      w.set(i, Math.max(Math.min(floor, w.get(i)!), w.get(i)! - (total() - max)));
    }
  }
  // 3. last resort: shorten the widest column until it fits (or nothing can shrink)
  while (total() > max) {
    const widest = keep.reduce((a, b) => (w.get(b)! > w.get(a)! ? b : a));
    if (w.get(widest)! <= MIN_COL) break;
    w.set(widest, Math.max(MIN_COL, w.get(widest)! - (total() - max)));
  }

  const widths = keep.map((i) => w.get(i)!);
  const body = raw.map((r) => keep.map((i, j) => truncate(r[i], widths[j])));
  const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - width(s)));
  const line = (l: string, m: string, r: string) => l + widths.map((n) => "─".repeat(n + 2)).join(m) + r;
  const row = (cells: string[]) => "│" + cells.map((c, j) => ` ${pad(c, widths[j])} `).join("│") + "│";
  const dropped = headers.length - keep.length;
  const title = opts.title
    ? bold(opts.title) + (dropped ? dim(`  (${dropped} column${dropped > 1 ? "s" : ""} hidden - widen the terminal to see all)`) : "")
    : null;
  const out = [
    ...(title ? [title] : []),
    line("┌", "┬", "┐"),
    row(keep.map((i, j) => bold(truncate(headers[i], widths[j])))),
    line("├", "┼", "┤"),
    ...(body.length ? body.map(row) : [row(keep.map((_, j) => (j === 0 ? dim("(none)") : "")))]),
    line("└", "┴", "┘"),
  ];
  return out.join("\n");
}

/**
 * Column-aligned lines for interactive menus (one line per selectable row) plus a header and rule.
 * `indent` compensates for the prompt's own prefix so the header lines up with the options.
 */
export function alignedRows(
  headers: string[],
  rows: Cell[][],
  opts: TableOpts & { indent?: number } = {},
): { header: string; rule: string; lines: string[] } {
  const limit = (i: number) => opts.maxCols?.[i] ?? opts.maxCol ?? 40;
  const body = rows.map((r) => headers.map((_, i) => (limit(i) ? truncate(cellText(r[i]), limit(i)) : cellText(r[i]))));
  const widths = headers.map((h, i) => Math.max(width(h), ...body.map((r) => width(r[i]))));
  const pad = (s: string, w: number) => s + " ".repeat(w - width(s));
  const join = (cells: string[]) => cells.map((c, i) => pad(c, widths[i])).join(dim(" │ "));
  const indent = " ".repeat(opts.indent ?? 0);
  return {
    header: indent + join(headers.map((h) => bold(h))),
    rule: indent + dim(widths.map((w) => "─".repeat(w)).join("─┼─")),
    lines: body.map(join),
  };
}

export function printTable(headers: string[], rows: Cell[][], opts: TableOpts = {}): void {
  console.log(renderTable(headers, rows, opts));
}

// ---------- vault-specific tables ----------

export interface ItemRowLike {
  ref: string;
  type: string;
  role?: string;
  default?: boolean;
  fields?: string[];
  filename?: string;
  size?: number;
  version: number;
  updated_at: string;
  description?: string;
  archived_at?: string;
}

export function humanSize(n?: number): string {
  if (n === undefined) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function itemsTable(items: ItemRowLike[], title = "Items"): string {
  return renderTable(
    ["REF", "TYPE", "ROLE", "DEFAULT", "FIELDS / FILE", "VER", "UPDATED", "DESCRIPTION"],
    items.map((i) => [
      i.ref + (i.archived_at ? " [archived]" : ""),
      i.type,
      i.role,
      i.default ? "yes" : "",
      i.type === "credential" ? i.fields?.join(", ") : i.type === "file" ? `${i.filename} (${humanSize(i.size)})` : "",
      `v${i.version}`,
      i.updated_at,
      i.description,
    ]),
    {
      title: `${title} (${items.length})`,
      maxCol: 50,
      maxCols: { 0: 0, 4: 0, 7: 45 },
      steps: [
        { drop: "UPDATED" },
        { shrink: "DESCRIPTION", min: 20 },
        { shrink: "FIELDS / FILE", min: 24 },
        { drop: "VER" },
        { drop: "DEFAULT" },
        { drop: "DESCRIPTION" },
        { drop: "TYPE" },
        { shrink: "FIELDS / FILE", min: 14 },
        { drop: "ROLE" },
        { shrink: "REF", min: 30 },
      ],
    },
  );
}

export function auditTable(rows: Array<{ ts: string; source: string; ref: string | null; action: string }>): string {
  return renderTable(
    ["TIME (UTC)", "SOURCE", "REF", "ACTION"],
    rows.map((r) => [r.ts, r.source, r.ref, r.action]),
    {
      title: "Audit log",
      maxCol: 70,
      maxCols: { 2: 0 },
      steps: [{ shrink: "ACTION", min: 28 }, { shrink: "REF", min: 40 }, { drop: "SOURCE" }, { shrink: "ACTION", min: 14 }, { shrink: "REF", min: 24 }],
    },
  );
}

export function versionsTable(
  rows: Array<{ version: number; current: boolean; type: string; created_at: string; source: string | null; fields?: string[]; filename?: string; role?: string }>,
): string {
  return renderTable(
    ["VERSION", "CURRENT", "TYPE", "CREATED (UTC)", "SOURCE", "FIELDS / FILE"],
    rows.map((v) => [`v${v.version}`, v.current ? "yes" : "", v.type, v.created_at, v.source, v.fields?.join(", ") ?? v.filename]),
    { title: "Versions", dropOrder: ["SOURCE", "TYPE"], shrink: ["FIELDS / FILE"] },
  );
}
