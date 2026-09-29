import { describe, expect, it } from "vitest";
import { renderTable, wrapText } from "../src/table.js";

describe("wrapText", () => {
  it("breaks at spaces within the width", () => {
    expect(wrapText("Super-admin login for the staging admin panel", 20)).toEqual(["Super-admin login", "for the staging", "admin panel"]);
  });
  it("keeps short text on one line and splits over-long words", () => {
    expect(wrapText("short", 20)).toEqual(["short"]);
    expect(wrapText("abcdefghijKLMNOP", 10)).toEqual(["abcdefghij", "KLMNOP"]);
  });
});

describe("renderTable wrap", () => {
  it("renders a wrapped column over several aligned lines", () => {
    const out = renderTable(["KEY", "DESCRIPTION"], [["a", "one two three four five six"]], { maxWidth: 200, maxCols: { 1: 10 }, wrap: ["DESCRIPTION"] });
    const rows = out.split("\n").filter((l) => l.startsWith("│") && !l.includes("KEY"));
    expect(rows.length).toBe(3);
    expect(new Set(rows.map((r) => r.length)).size).toBe(1); // all lines same width → aligned
    expect(rows.map((r) => r.split("│")[2].trim())).toEqual(["one two", "three four", "five six"]);
  });
});
