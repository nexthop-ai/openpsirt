// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useFindingNeighbors } from "./findingNeighbors";
import { useDecisionPrefill } from "./findingPrefill";
import { findingsPageKey, listQuery, withinVariant } from "./list";
import { client, mounted, screen, serve, settle } from "../test/mount";

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

  // The page the findings list drew under an address, cached where the list
  // caches it.
  function listed(from: string, items: ReturnType<typeof row>[], total: number) {
    const queries = client();
    const asked = new URLSearchParams(from);
    queries.setQueryData(findingsPageKey("sonic", "", "", withinVariant(listQuery(asked), false)), {
      items,
      total,
    });
    return queries;
  }

  it("reads the row before and after from the list page it was opened from", async () => {
    const asked = serve(() => undefined);
    const queries = listed(
      "state=undecided",
      [row("CVE-2026-0001"), row("CVE-2026-0002"), row("CVE-2026-0003")],
      3,
    );
    mount.render(screen(<Walk walking from="state=undecided" />, "/", "*", queries));
    await settle();
    expect(asked).not.toHaveBeenCalled();
    expect(seen?.at).toBe(1);
    expect(seen?.previous?.row.vulnerability).toBe("CVE-2026-0001");
    expect(seen?.next?.row.vulnerability).toBe("CVE-2026-0003");
  });

  it("asks for the rows around it where it sits at the edge of a page with more after it", async () => {
    const asked = serve((path) =>
      path === "/v1/products/{product}/findings"
        ? {
            data: {
              items: [row("CVE-2026-0001"), row("CVE-2026-0002"), row("CVE-2026-0003")],
              total: 9,
            },
          }
        : undefined,
    );
    const queries = listed("state=undecided", [row("CVE-2026-0001"), row("CVE-2026-0002")], 9);
    mount.render(screen(<Walk walking from="state=undecided" />, "/", "*", queries));
    await settle();
    expect(asked).toHaveBeenCalled();
    expect(seen?.next?.row.vulnerability).toBe("CVE-2026-0003");
  });

  it("asks for the rows around it where it opens a held page that is not the first", async () => {
    const asked = serve((path) =>
      path === "/v1/products/{product}/findings"
        ? {
            data: {
              items: [row("CVE-2026-0001"), row("CVE-2026-0002"), row("CVE-2026-0003")],
              total: 100,
            },
          }
        : undefined,
    );
    const from = "state=undecided&offset=50";
    const queries = listed(from, [row("CVE-2026-0002"), row("CVE-2026-0003")], 100);
    mount.render(screen(<Walk walking from={from} />, "/", "*", queries));
    await settle();
    expect(asked).toHaveBeenCalled();
    expect(seen?.at).toBe(50);
    expect(seen?.previous?.row.vulnerability).toBe("CVE-2026-0001");
  });

  it("asks nothing where it is the last row of the whole list", async () => {
    const asked = serve(() => undefined);
    const queries = listed("state=undecided", [row("CVE-2026-0001"), row("CVE-2026-0002")], 2);
    mount.render(screen(<Walk walking from="state=undecided" />, "/", "*", queries));
    await settle();
    expect(asked).not.toHaveBeenCalled();
    expect(seen?.previous?.row.vulnerability).toBe("CVE-2026-0001");
    expect(seen?.next).toBeNull();
  });

  it("asks nothing at the edge of the largest page, where the window is the page", async () => {
    const asked = serve(() => undefined);
    const from = "state=undecided&page=200";
    const queries = listed(from, [row("CVE-2026-0001"), row("CVE-2026-0002")], 900);
    mount.render(screen(<Walk walking from={from} />, "/", "*", queries));
    await settle();
    expect(asked).not.toHaveBeenCalled();
    expect(seen?.previous?.row.vulnerability).toBe("CVE-2026-0001");
    expect(seen?.next).toBeNull();
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
  // Walks to another finding without remounting, as a params-only change does.
  let walkTo: (finding: string) => void = () => {};
  function Prefill({ rule }: { rule: string }) {
    const [finding, setFinding] = useState("one");
    walkTo = setFinding;
    seen = useDecisionPrefill(finding, rule);
    return null;
  }
  function kept(prepares: Record<string, unknown>) {
    serve((path) =>
      path === "/v1/session/me/saved-filters"
        ? { data: { items: [{ name: "kept", query: "", prepares }] } }
        : undefined,
    );
  }

  it("opens on what the rule prepares, until the reader starts from something", async () => {
    kept({ outcome: "not-applicable", justification: "code-not-present", reasoning: "gone" });
    mount.render(screen(<Prefill rule="kept" />));
    // Held until the rule is read, so the form does not open blank and refill.
    expect(seen?.settled).toBe(false);
    await settle();
    expect(seen?.settled).toBe(true);
    expect(seen?.opening).toMatchObject({ outcome: "not-applicable", reasoning: "gone" });
    const first = seen?.opened;
    act(() => seen?.startFrom({ reasoning: "mine" }));
    expect(seen?.untouched).toBe(false);
    expect(seen?.opening).toEqual({ reasoning: "mine" });
    expect(seen?.opened).not.toBe(first);
  });

  it("starts the next finding from the rule again, whatever this one started from", async () => {
    kept({ outcome: "not-applicable", justification: "code-not-present", reasoning: "gone" });
    mount.render(screen(<Prefill rule="kept" />));
    await settle();
    act(() => seen?.startFrom({ reasoning: "mine" }));
    act(() => walkTo("two"));
    expect(seen?.untouched).toBe(true);
    expect(seen?.opening).toMatchObject({ outcome: "not-applicable", reasoning: "gone" });
  });

  it("fills nothing from a deferral with no length, and says so", async () => {
    kept({ outcome: "deferred", reasoning: "later" });
    mount.render(screen(<Prefill rule="kept" />));
    await settle();
    expect(seen?.lengthless).toBe(true);
    expect(seen?.opening).toBeNull();
  });

  it("says a rule that could not be read was not read", async () => {
    serve((path) => (path === "/v1/session/me/saved-filters" ? { status: 503 } : undefined));
    mount.render(screen(<Prefill rule="kept" />));
    await settle();
    expect(seen?.ruleUnread).toBe(true);
    expect(seen?.opening).toBeNull();
  });
});
