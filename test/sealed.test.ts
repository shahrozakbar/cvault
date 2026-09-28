import { describe, expect, it } from "vitest";
import { suggestPath } from "../src/sealed.js";
import { parseRef } from "../src/store.js";

const ctx = { tenant: "rezilens", project: "digrc-api-service" };

describe("suggestPath (dialog path correction)", () => {
  it("folds extra levels into the service name", () => {
    const s = suggestPath("rezilens/digrc-api-service/develop/admin-panel/systemadmin", ctx);
    expect(s).toBe("rezilens/digrc-api-service/develop-admin-panel/systemadmin");
    expect(() => parseRef(s!, ctx)).not.toThrow();
  });

  it("recognises the linked tenant/project anywhere in the path", () => {
    expect(suggestPath("rezilens/develop/digrc-api-service/admin-panel/systemadmin", ctx)).toBe(
      "rezilens/digrc-api-service/develop-admin-panel/systemadmin",
    );
    expect(suggestPath("develop/digrc-api-service/admin-panel/systemadmin", ctx)).toBe(
      "rezilens/digrc-api-service/develop-admin-panel/systemadmin",
    );
  });

  it("adds the linked project to a 3-level path", () => {
    expect(suggestPath("develop/admin-panel/systemadmin", ctx)).toBe("rezilens/digrc-api-service/develop-admin-panel/systemadmin");
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
