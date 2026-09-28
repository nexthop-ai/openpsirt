// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { belongTo, keep } from "../app/drafts";
import { Carried } from "./Carried";
import { consumersOf, type Sitting } from "./Covering";
import { forecast } from "./Decide";
import { Editor } from "./Editor";
import { revisionStart } from "./ReasonEditor";
import { Scoring } from "./Scoring";
import { pasted } from "./Words";
import { screen, serve, settle, mounted } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

// A date this many days from today, as the form takes one.
const out = (days: number) => {
  const then = new Date();
  then.setUTCDate(then.getUTCDate() + days);
  return then.toISOString().slice(0, 10);
};

describe("what the decision form says about a second person", () => {
  it("counts what the place was already put off for", () => {
    expect(forecast("deferred", 30, out(10))).toContain("stands on its own");
    expect(forecast("deferred", 30, out(10), 25)).toContain("a second person has to agree");
  });

  it("measures to the moment, the way the server does", () => {
    // Thirty days out, asked at noon, is twenty-nine and a half days: short
    // of the threshold, and the server lets it stand alone.
    vi.useFakeTimers({ now: new Date("2026-03-01T12:00:00Z"), toFake: ["Date"] });
    try {
      expect(forecast("deferred", 30, "2026-03-31")).toContain("29 days is inside");
      expect(forecast("deferred", 30, "2026-04-01")).toContain("a second person has to agree");
      expect(forecast("deferred", 30, "2026-03-31", 0.5)).toContain(
        "a second person has to agree",
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not call a promise to act by a date a dismissal", () => {
    for (const outcome of ["patch-needed", "upgrade-needed"]) {
      const said = forecast(outcome, 30, "");
      expect(said, outcome).toContain("earliest deadline");
      expect(said, outcome).not.toContain("ismissal");
    }
  });

  it("names the act that waits for a second person", () => {
    expect(forecast("not-applicable", 30, "")).toBe(
      "A dismissal takes effect only after a second person approves.",
    );
    expect(forecast("affected", 30, "")).toBe("No approval needed. Goes to remediation.");
  });
});

describe("revising a claim's reasoning", () => {
  beforeEach(() => {
    window.localStorage.clear();
    belongTo("oidc:ana");
  });

  it("opens on the draft left from an earlier attempt", () => {
    keep("revise:7", "A paragraph somebody typed and did not send.");
    expect(revisionStart("revise:7", "The standing reasoning.")).toBe(
      "A paragraph somebody typed and did not send.",
    );
  });

  it("opens on the standing reasoning where nothing was left", () => {
    expect(revisionStart("revise:8", "The standing reasoning.")).toBe("The standing reasoning.");
  });
});

describe("words pasted into a filter", () => {
  it("splits a pasted list at its commas", () => {
    expect(pasted("openssl,libssl, zlib", [])).toEqual({
      finished: ["openssl", "libssl"],
      left: " zlib",
    });
  });

  it("drops a word already held or repeated", () => {
    expect(pasted("openssl,openssl,curl,", ["curl"])).toEqual({ finished: ["openssl"], left: "" });
  });

  it("finishes nothing while there is no comma", () => {
    expect(pasted("openssl", [])).toEqual({ finished: [], left: "openssl" });
  });
});

describe("the consumers a decision covers", () => {
  const at = (place: string, consumer: string) => ({ place, component: "linux", consumer });

  it("counts consumers rather than places", () => {
    const places = [at("a", "kmod"), at("b", "kmod"), at("c", "initrd")] as Sitting[];
    expect(consumersOf(places)).toBe(2);
  });
});

function Scored({ start }: { start: string }) {
  const [vector, setVector] = useState(start);
  return <Scoring vector={vector} onChange={setVector} />;
}

describe("working out a score", () => {
  const select = (id: string) => mount.host().querySelector<HTMLSelectElement>(`#${id}`);
  const choose = (id: string, value: string) =>
    act(() => {
      const box = select(id);
      if (!box) throw new Error(`no ${id}`);
      box.value = value;
      box.dispatchEvent(new Event("change", { bubbles: true }));
    });

  it("keeps the answers the other scheme shares when the scheme changes", async () => {
    serve(() => ({ data: { version: "3.1", score: 9.8, severity: "critical" } }));
    mount.render(screen(<Scored start="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" />));
    await settle();
    const open = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Change the score",
    );
    act(() => open?.click());
    choose("cvss-version", "CVSS:4.0");
    await settle();
    expect(select("cvss-AV")?.value).toBe("N");
    expect(select("cvss-AC")?.value).toBe("L");
    expect(select("cvss-PR")?.value).toBe("N");
  });

  it("keeps the other answers when one is blanked", async () => {
    serve(() => ({ data: { version: "3.1", score: 9.8, severity: "critical" } }));
    mount.render(screen(<Scored start="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" />));
    await settle();
    const open = Array.from(mount.host().querySelectorAll("button")).find(
      (each) => each.textContent === "Change the score",
    );
    act(() => open?.click());
    choose("cvss-AV", "");
    await settle();
    expect(select("cvss-AC")?.value).toBe("L");
    expect(select("cvss-C")?.value).toBe("H");
  });
});

function Writing() {
  const [value, setValue] = useState("");
  return (
    <Editor value={value} onChange={setValue} mentions={{ product: "sonic" }} label="Reasoning" />
  );
}

describe("offering somebody to mention", () => {
  it("asks the server for what was typed after the @", async () => {
    const asked: unknown[] = [];
    serve((path, init) => {
      if (path === "/v1/products/{product}/mentionable") {
        asked.push((init as { params: { query: Record<string, unknown> } }).params.query);
      }
      return { data: { items: [], total: 0 } };
    });
    mount.render(screen(<Writing />));
    const box = mount.host().querySelector("textarea");
    act(() => {
      if (!box) return;
      box.value = "ask @zz";
      box.setSelectionRange(box.value.length, box.value.length);
      box.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, key: "z" }));
    });
    await settle();
    expect(asked.at(-1)).toMatchObject({ q: "zz" });
  });
});

describe("carrying decisions from another line", () => {
  it("forgets what was ticked when the line carried from changes", async () => {
    serve((path) => {
      if (path === "/v1/products/{product}/streams") {
        return { data: { items: [{ name: "master" }, { name: "202411" }, { name: "202505" }] } };
      }
      return {
        data: {
          moved: [{ decision_id: 5, vulnerability: "CVE-2026-1" }],
          postponed: [],
          applying: 0,
          absent: 0,
        },
      };
    });
    mount.render(screen(<Carried at={{ product: "sonic", stream: "master", variant: "x" }} />));
    await settle();
    const from = () => mount.host().querySelector<HTMLSelectElement>("#carry-from");
    const pick = (line: string) =>
      act(() => {
        const box = from();
        if (!box) return;
        box.value = line;
        box.dispatchEvent(new Event("change", { bubbles: true }));
      });
    pick("202411");
    await settle();
    act(() => mount.host().querySelector<HTMLInputElement>('input[type="checkbox"]')?.click());
    const carry = () =>
      Array.from(mount.host().querySelectorAll("button")).find((each) =>
        each.textContent?.startsWith("Carry"),
      );
    expect(carry()?.textContent).toContain("Carry 1");
    pick("202505");
    await settle();
    expect(carry()?.textContent).not.toContain("Carry 1");
  });
});
