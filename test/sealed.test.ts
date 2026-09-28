import { describe, expect, it } from "vitest";
import { suggestPath } from "../src/sealed.js";
import { parseRef } from "../src/store.js";

const ctx = { tenant: "rezilens", project: "digrc-api-service" };

describe("suggestPath (dialog path correction)", () => {
  it("turns project-before-environment into tenant/env/project/service/key", () => {
    const s = suggestPath("rezilens/digrc-api-service/develop/admin-panel/systemadmin", ctx);
    expect(s).toBe("rezilens/develop/digrc-api-service/admin-panel/systemadmin");
    expect(parseRef(s!, ctx)).toMatchObject({ env: "develop", project: "digrc-api-service", service: "admin-panel" });
  });

  it("keeps a correct 5-level path as-is", () => {
    expect(suggestPath("rezilens/develop/digrc-api-service/admin-panel/systemadmin", ctx)).toBeNull();
  });

  it("recognises the linked tenant/project anywhere and folds extra levels into the service", () => {
    expect(suggestPath("develop/digrc-api-service/admin-panel/systemadmin", ctx)).toBe(
      "rezilens/develop/digrc-api-service/admin-panel/systemadmin",
    );
    expect(suggestPath("rezilens/digrc-api-service/staging/admin/panel/root", ctx)).toBe(
      "rezilens/staging/digrc-api-service/admin-panel/root",
    );
  });

  it("adds the linked project to short paths", () => {
    expect(suggestPath("Staging/Admin Panel/root", ctx)).toBe("rezilens/staging/digrc-api-service/admin-panel/root");
    expect(suggestPath("develop/admin-panel/systemadmin", null)).toBeNull();
  });

  it("cleans invalid characters but keeps key case and #field", () => {
    expect(suggestPath("Acme/My API/Admin Panel/Super Admin#password", null)).toBe("acme/my-api/admin-panel/Super-Admin#password");
  });

  it("returns null when the path is already valid or hopeless", () => {
    expect(suggestPath("acme/api/panel/admin", null)).toBeNull();
    expect(suggestPath("admin", ctx)).toBeNull();
    expect(suggestPath("panel/admin", null)).toBeNull();
  });
});
