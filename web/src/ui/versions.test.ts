import { describe, expect, it } from "vitest";
import { sharedVersion } from "./versions";

describe("sharedVersion", () => {
  it("finds the stamp every container carries", () => {
    const stamp = "sbom-consumer-metadata.0-f3811cc13";
    expect(sharedVersion([{ version: stamp }, { version: stamp }, { version: stamp }])).toBe(stamp);
  });

  it("ignores a sibling with no version at all", () => {
    // The real shape: the switch image's root has one child with no version
    // beside twenty-nine containers all carrying the same stamp. Counting the
    // versionless one as disagreement left the stamp on every row, which is
    // the noise this exists to remove.
    const stamp = "sbom-consumer-metadata.0-f3811cc13";
    expect(sharedVersion([{ version: "" }, { version: stamp }, { version: stamp }])).toBe(stamp);
  });

  it("says nothing where the versions differ", () => {
    // The ordinary case, and the one that must not be collapsed: real
    // versions on real packages are what somebody came to read.
    expect(sharedVersion([{ version: "1.2.3" }, { version: "4.5.6" }])).toBe("");
  });

  it("leaves a level of one alone", () => {
    // A single component's version is its own. Moving it above the row would
    // be saying something about a level that has one entry in it.
    expect(sharedVersion([{ version: "1.2.3" }])).toBe("");
  });

  it("says nothing where nothing has a version", () => {
    expect(sharedVersion([{ version: "" }, { version: "" }])).toBe("");
  });
});
