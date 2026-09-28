// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useFindingNeighbors } from "./findingNeighbors";
import { useDecisionPrefill } from "./findingPrefill";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const at = {
  product: "sonic",
  vulnerability: "CVE-2026-0002",
  component: "zlib",
  version: "1.3",
  ecosystem: "",
  namespace: "",
};

function row(vulnerability: string) {
  return { vulnerability, component: "zlib", version: "1.3", stream: "main", variant: "x86" };
}

describe("where a finding sits in the list it was opened from", () => {
  let seen: ReturnType<typeof useFindingNeighbors> = null;
  function Walk({ walking, from }: { walking: boolean; from: string }) {
    seen = useFindingNeighbors(at, walking, from, "kept");
    return null;
  }

  it("names the row before and after, carrying the list and the rule", async () => {
    serve((path) =>
      path === "/v1/products/{product}/findings"
        ? {
            data: {
              items: [row("CVE-2026-0001"), row("CVE-2026-0002"), row("CVE-2026-0003")],
              total: 3,
            },
          }
        : undefined,
    );
    mount.render(screen(<Walk walking from="state=undecided" />));
    await settle();
    expect(seen?.at).toBe(1);
    expect(seen?.total).toBe(3);
    const next = new URL(seen?.next?.to ?? "", "http://here");
    expect(next.pathname).toContain("/findings/CVE-2026-0003/");
    expect(next.searchParams.get("from")).toBe("state=undecided");
    expect(next.searchParams.get("rule")).toBe("kept");
    expect(seen?.previous?.row.vulnerability).toBe("CVE-2026-0001");
  });

  it("asks nothing where the finding was not opened from a list", async () => {
    const asked = serve(() => undefined);
    mount.render(screen(<Walk walking={false} from="" />));
    await settle();
    expect(asked).not.toHaveBeenCalled();
    expect(seen).toBeNull();
  });
});

describe("what the decision form starts from", () => {
  let seen: ReturnType<typeof useDecisionPrefill> | undefined;
  function Prefill({ rule }: { rule: string }) {
    seen = useDecisionPrefill("sonic", "one", rule);
    return null;
  }
  function kept(prepares: Record<string, unknown>) {
    serve((path) =>
      path === "/v1/products/{product}/saved-filters"
        ? { data: { items: [{ name: "kept", query: "", prepares }] } }
        : undefined,
    );
  }

  it("opens on what the rule prepares, until the reader starts from something", async () => {
    kept({ outcome: "not-applicable", justification: "code-not-present", reasoning: "gone" });
    mount.render(screen(<Prefill rule="kept" />));
    await settle();
    expect(seen?.settled).toBe(true);
    expect(seen?.opening).toMatchObject({ outcome: "not-applicable", reasoning: "gone" });
    const first = seen?.opened;
    act(() => seen?.startFrom({ reasoning: "mine" }));
    expect(seen?.untouched).toBe(false);
    expect(seen?.opening).toEqual({ reasoning: "mine" });
    expect(seen?.opened).not.toBe(first);
  });

  it("fills nothing from a deferral with no length, and says so", async () => {
    kept({ outcome: "deferred", reasoning: "later" });
    mount.render(screen(<Prefill rule="kept" />));
    await settle();
    expect(seen?.lengthless).toBe(true);
    expect(seen?.opening).toBeNull();
  });

  it("says a rule that could not be read was not read", async () => {
    serve((path) =>
      path === "/v1/products/{product}/saved-filters" ? { status: 503 } : undefined,
    );
    mount.render(screen(<Prefill rule="kept" />));
    await settle();
    expect(seen?.ruleUnread).toBe(true);
    expect(seen?.opening).toBeNull();
  });
});
