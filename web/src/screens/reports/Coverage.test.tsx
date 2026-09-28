// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { Body } from "../../api/client";
import { mounted } from "../../test/mount";
import { State } from "./Coverage";

const mount = mounted();

const build = (of: Partial<Body<"CoverageBody">>): Body<"CoverageBody"> => ({
  product: "sonic",
  stream: "master",
  stream_kind: "branch",
  variant: "broadcom",
  quiet_days: 3,
  ...of,
});

const said = (of: Partial<Body<"CoverageBody">>) => {
  mount.render(<State build={build(of)} />);
  return mount.host().textContent;
};

describe("the state a coverage row names", () => {
  it("calls a build past end of life out of support", () => {
    expect(said({ out_of_support: true })).toBe("out of support");
  });

  it("calls a build taken out of use that, and not out of support", () => {
    expect(said({ retired: true, last_received_at: "2026-01-01T00:00:00Z" })).toBe(
      "taken out of use",
    );
  });

  it("calls a quiet build quiet, or never scanned where nothing arrived", () => {
    expect(said({ quiet: true, last_received_at: "2026-01-01T00:00:00Z" })).toBe("quiet");
    expect(said({ quiet: true })).toBe("never scanned");
  });

  it("does not call a build nothing has reached scanned", () => {
    expect(said({})).toBe("never scanned");
  });

  it("calls a build scanned only where a scan reached it", () => {
    expect(said({ last_received_at: "2026-01-01T00:00:00Z" })).toBe("scanned");
  });
});
