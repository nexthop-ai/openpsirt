// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { promised, queueReason } from "./queueReasons";

describe("the list the review queue opens on", () => {
  it("is the one the address names", () => {
    expect(queueReason(new URLSearchParams("reason=expired-deferral"))).toBe("expired-deferral");
    expect(queueReason(new URLSearchParams("reason=missed-fix-date"))).toBe("missed-fix-date");
  });

  it("is the approvals where the address names none or one the server does not take", () => {
    expect(queueReason(new URLSearchParams(""))).toBe("approval");
    expect(queueReason(new URLSearchParams("reason=lapsed"))).toBe("approval");
  });
});

describe("what a dated decision promised", () => {
  const decision = { upgradeTo: "", committedTo: "2026-09-01", deferredUntil: "2026-10-01" };

  it("names the version and the date of an upgrade", () => {
    expect(promised({ ...decision, outcome: "upgrade-needed", upgradeTo: "3.0.15" })).toBe(
      "Upgrade to 3.0.15 by 2026-09-01",
    );
  });

  it("names the date of an upgrade that names no version", () => {
    expect(promised({ ...decision, outcome: "upgrade-needed" })).toBe("Upgrade by 2026-09-01");
  });

  it("names the date of a patch", () => {
    expect(promised({ ...decision, outcome: "patch-needed" })).toBe("Patch by 2026-09-01");
  });

  it("names the date a deferral returns", () => {
    expect(promised({ ...decision, outcome: "deferred" })).toBe("Deferred until 2026-10-01");
  });

  it("says nothing for an outcome with no date", () => {
    expect(promised({ ...decision, outcome: "wont-fix" })).toBe("");
  });
});
