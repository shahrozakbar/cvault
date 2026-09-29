import { createPrompt, isDownKey, isEnterKey, isUpKey, useKeypress, useMemo, useState } from "@inquirer/core";

/**
 * A menu where rows can contain several selectable cells (e.g. a tenant row whose PROJECTS and
 * ENVIRONMENTS columns list selectable names).
 *
 *   ↑ ↓   move between rows (keeping the column when possible)
 *   ← →   move between cells of a row; ← on the first cell = back, → on the last cell = open
 *   ⏎     open the highlighted cell
 *   Esc   back (handled by the caller through an AbortSignal)
 *   q     quit                (returns config.quit)
 *   Space s   search          (returns config.search)
 */

export interface GridCell<T> {
  text: string;
  /** undefined = not selectable */
  value?: T;
}

export type GridLine<T> = { kind: "sep"; text: string } | { kind: "row"; cells: GridCell<T>[] };

export interface GridConfig<T> {
  message: string;
  lines: GridLine<T>[];
  default?: T;
  pageSize?: number;
  /** value returned when ← is pressed on the first cell of a row */
  back: T;
  /** value returned when q is pressed */
  quit?: T;
  /** value returned for the Space-then-s chord */
  search?: T;
}

const ANSI = /\x1b\[[0-9;]*m/g;
const plain = (s: string) => s.replace(ANSI, "");
const bold = (s: string) => `\x1b[1m${s}\x1b[22m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[22m`;
const cyan = (s: string) => `\x1b[36m${s}\x1b[39m`;
const inverse = (s: string) => `\x1b[7m${s}\x1b[27m`;
const SEP = dim(" │ ");

/** Visible width (ANSI-aware). */
const vwidth = (s: string) => [...plain(s)].length;
/** Cut a rendered line to `max` visible columns, keeping colours intact up to the cut. */
function fitLine(line: string, max: number): string {
  if (vwidth(line) <= max) return line;
  let out = "";
  let n = 0;
  for (const part of line.split(/(\x1b\[[0-9;]*m)/)) {
    if (part.startsWith("\x1b[")) {
      out += part;
      continue;
    }
    for (const ch of part) {
      if (n >= max - 1) return out + "…\x1b[0m";
      out += ch;
      n++;
    }
  }
  return out;
}

interface Pos {
  li: number;
  ci: number;
}

function selectable<T>(line: GridLine<T> | undefined): number[] {
  if (!line || line.kind !== "row") return [];
  return line.cells.flatMap((c, i) => (c.value !== undefined ? [i] : []));
}

/** Cell in `li` closest to column `ci` (same column if selectable). */
function nearest<T>(lines: GridLine<T>[], li: number, ci: number): number {
  const opts = selectable(lines[li]);
  if (opts.includes(ci)) return ci;
  return opts.reduce((best, i) => (Math.abs(i - ci) < Math.abs(best - ci) ? i : best), opts[0]);
}

function initial<T>(config: GridConfig<T>): Pos {
  const { lines } = config;
  if (config.default !== undefined) {
    for (let li = 0; li < lines.length; li++) {
      const line = lines[li];
      if (line.kind !== "row") continue;
      const ci = line.cells.findIndex((c) => c.value !== undefined && c.value === config.default);
      if (ci >= 0) return { li, ci };
    }
  }
  const li = lines.findIndex((l) => selectable(l).length > 0);
  return { li: Math.max(0, li), ci: li >= 0 ? selectable(lines[li])[0] : 0 };
}

export const gridSelect = createPrompt(<T>(config: GridConfig<T>, done: (value: T) => void) => {
  const { lines } = config;
  const start = useMemo(() => initial(config), []);
  const [pos, setPos] = useState<Pos>(start);
  const [status, setStatus] = useState<"idle" | "done">("idle");
  const [leader, setLeader] = useState(false);
  const pageSize = config.pageSize ?? 20;

  const valueAt = (p: Pos): T | undefined => {
    const line = lines[p.li];
    return line && line.kind === "row" ? line.cells[p.ci]?.value : undefined;
  };
  const finish = (value: T) => {
    setStatus("done");
    done(value);
  };

  useKeypress((key) => {
    if (status === "done") return;
    // Space then s = search
    if (leader) {
      setLeader(false);
      if (key.name === "s" && config.search !== undefined) return finish(config.search);
    }
    if (key.name === "space") {
      setLeader(true);
      return;
    }
    if (key.name === "q" && !key.ctrl && config.quit !== undefined) return finish(config.quit);
    if (isEnterKey(key)) {
      const v = valueAt(pos);
      if (v !== undefined) finish(v);
      return;
    }
    if (isUpKey(key) || isDownKey(key)) {
      const step = isUpKey(key) ? -1 : 1;
      for (let li = pos.li + step; li >= 0 && li < lines.length; li += step) {
        if (selectable(lines[li]).length) {
          setPos({ li, ci: nearest(lines, li, pos.ci) });
          return;
        }
      }
      return;
    }
    const cells = selectable(lines[pos.li]);
    const idx = cells.indexOf(pos.ci);
    if (key.name === "left") {
      if (idx > 0) setPos({ li: pos.li, ci: cells[idx - 1] });
      else finish(config.back);
    } else if (key.name === "right") {
      if (idx >= 0 && idx < cells.length - 1) setPos({ li: pos.li, ci: cells[idx + 1] });
      else {
        const v = valueAt(pos);
        if (v !== undefined) finish(v);
      }
    }
  });

  const multi = (l: GridLine<T>) => l.kind === "row" && l.cells.length > 1;
  const maxWidth = Math.max(20, (process.stdout.columns || 120) - 1);
  const render = (l: GridLine<T>, li: number): string => fitLine(renderRaw(l, li), maxWidth);
  const renderRaw = (l: GridLine<T>, li: number): string => {
    if (l.kind === "sep") return ` ${l.text}`;
    const active = li === pos.li;
    const text = l.cells
      .map((c, ci) => {
        if (!active || ci !== pos.ci) return c.text;
        return multi(l) ? inverse(plain(c.text)) : cyan(plain(c.text));
      })
      .join(SEP);
    return `${active ? cyan("❯") : " "} ${text}`;
  };

  // window around the cursor when there are more lines than fit
  let from = 0;
  if (lines.length > pageSize) from = Math.min(Math.max(0, pos.li - Math.floor(pageSize / 2)), lines.length - pageSize);
  const shown = lines.slice(from, from + pageSize).map((l, i) => render(l, from + i));
  if (from > 0) shown.unshift(dim("  ↑ more"));
  if (from + pageSize < lines.length) shown.push(dim("  ↓ more"));

  const hasColumns = lines.some((l) => selectable(l).length > 1);
  const keys = [
    hasColumns ? "↑↓ rows · ←→ columns · ⏎/→ open · ←/Esc back" : "↑↓ move · ⏎/→ open · ←/Esc back",
    ...(config.search !== undefined ? [leader ? cyan("space-s: press s to search") : "space s search"] : []),
    ...(config.quit !== undefined ? ["q quit"] : []),
  ];
  const help = fitLine(`  ${dim(keys.join(" · "))}`, maxWidth);
  return `${cyan("?")} ${bold(config.message)}\n${shown.join("\n")}\n${help}`;
});
