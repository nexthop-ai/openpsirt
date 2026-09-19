import { describe, expect, it } from "vitest";
import {
  LEAST_FIRST,
  daysBack,
  ORDERS,
  SORTS,
  asAsked,
  fromAt,
  listQuery,
  pageSize,
  pathTo,
  where,
  widened,
  windowFor,
} from "./list";

// The list's address is the list. What is tested here is the part a second
// screen depends on: the finding walks the list it came from by asking the
// server the same question, so the translation from address to query, and the
// arithmetic that finds the row either side, both have to be right somewhere
// nothing renders.

describe("the window a finding asks for", () => {
  it("reaches one row past the end of the page", () => {
    // The first page: there is nothing before it, and one row after it.
    expect(windowFor(0, 50)).toEqual({ offset: 0, limit: 51 });
  });

  it("reaches one row either side of a later page", () => {
    expect(windowFor(50, 50)).toEqual({ offset: 49, limit: 52 });
  });

  it("keeps the last row of the largest page inside its own window", () => {
    // At the largest page there is no room to widen, so the window is the page
    // itself and the walk ends at the page edge. Widening backward alone
    // shifted the window back a row, which put the page's last row outside it
    // — and the finding screen, which locates itself in the window by
    // identity, then drew no walk at all.
    expect(windowFor(0, 200)).toEqual({ offset: 0, limit: 200 });
    expect(windowFor(200, 200)).toEqual({ offset: 200, limit: 200 });
    expect(windowFor(400, 200)).toEqual({ offset: 400, limit: 200 });
  });
});

describe("the list a neighbor carries", () => {
  it("keeps the filters and drops an offset of zero", () => {
    expect(fromAt("state=undecided&offset=50", 3, 50)).toBe("state=undecided");
  });

  it("moves the page on when the walk crosses a boundary", () => {
    expect(fromAt("state=undecided", 50, 50)).toBe("state=undecided&offset=50");
    expect(fromAt("offset=50", 99, 50)).toBe("offset=50");
    expect(fromAt("offset=50", 100, 50)).toBe("offset=100");
  });
});

describe("the filters as the server takes them", () => {
  it("asks for nothing where the address says nothing", () => {
    expect(listQuery(new URLSearchParams())).toEqual({ limit: 50, offset: 0 });
  });

  it("carries what the address says", () => {
    const asked = listQuery(
      new URLSearchParams(
        "sort=severity&asc=yes&floor=high&only=exploited&state=undecided&hide=zlib,curl&running=overdue&open_for=30",
      ),
    );
    expect(asked).toMatchObject({
      sort: "severity",
      asc: true,
      severity: "high",
      exploited: true,
      state: ["undecided"],
      exclude: ["zlib", "curl"],
      overdue: true,
      open_for: 30,
    });
    expect(asked).not.toHaveProperty("due_within");
  });

  it("asks for every value of a filter the address repeats", () => {
    // "Undecided or waiting" is one question — everything nobody has finished
    // with — and a single value could not ask it.
    const asked = listQuery(
      new URLSearchParams(
        "state=undecided&state=waiting&fix_state=none&fix_state=wont-fix" +
          "&ecosystem=deb&ecosystem=golang&outcome=deferred",
      ),
    );
    expect(asked).toMatchObject({
      state: ["undecided", "waiting"],
      fix_state: ["none", "wont-fix"],
      ecosystem: ["deb", "golang"],
      outcome: ["deferred"],
    });
  });

  it("asks for every word typed into a filter that holds words", () => {
    const asked = listQuery(
      new URLSearchParams(
        "component=openssl&component=libssl3&tag=waiting&tag=escalated" +
          "&weakness=CWE-787&weakness=CWE-125&vex_publisher=debian&assigned=me&assigned=nobody",
      ),
    );
    expect(asked).toMatchObject({
      component: ["openssl", "libssl3"],
      tag: ["waiting", "escalated"],
      weakness: ["CWE-787", "CWE-125"],
      vex_publisher: ["debian"],
      assigned: ["me", "nobody"],
    });
  });

  it("asks for nothing where a repeated filter is empty", () => {
    // An empty word in the address is a filter that was cleared, not a value
    // nothing is ever in — left in, it would narrow the list to nothing.
    const asked = listQuery(
      new URLSearchParams(
        "state=&outcome=&fix_state=&ecosystem=&component=&tag=&weakness=&vex_publisher=&assigned=",
      ),
    );
    expect(asked).toEqual({ limit: 50, offset: 0 });
  });

  it("leaves out what a promised upgrade answers, unless the address says otherwise", () => {
    // A promise is made instead of deciding covered work again one finding at
    // a time. Written into the address rather than applied on the way to the
    // server, so it is a chip like every other filter — and the
    // by-component view, where the upgrade is managed, is untouched.
    expect(asAsked(new URLSearchParams(), "issues").get("planned")).toBe("unplanned");
    expect(asAsked(new URLSearchParams(), "components").get("planned")).toBe(null);
    // Whatever the reader said stands, including asking for both.
    expect(asAsked(new URLSearchParams("planned=planned"), "issues").get("planned")).toBe(
      "planned",
    );
    expect(asAsked(new URLSearchParams("planned=either"), "issues").get("planned")).toBe("either");
    // And "either" is how the address says "ask for everything", which the
    // query then does not send at all.
    expect(listQuery(new URLSearchParams("planned=either"))).not.toHaveProperty("planned");
    expect(listQuery(new URLSearchParams("planned=unplanned"))).toMatchObject({
      planned: "unplanned",
    });
  });

  it("keeps to the releases work can land in, and says so in the address", () => {
    // No work lands in a tag whatever anybody decides about it, and none
    // lands in a release past end-of-life either. Both defaults are written
    // into the address, on every view, so each is a chip somebody can widen
    // rather than a narrowing the screen applies and does not mention.
    for (const view of ["issues", "components", "bumps"]) {
      const asked = asAsked(new URLSearchParams(), view);
      expect(asked.getAll("on")).toEqual(["branch"]);
      expect(asked.getAll("support")).toEqual(["in-support"]);
    }
    // Whatever the reader said stands, including both.
    const both = asAsked(new URLSearchParams("on=branch&on=tag&support=past-eol"), "issues");
    expect(both.getAll("on")).toEqual(["branch", "tag"]);
    expect(both.getAll("support")).toEqual(["past-eol"]);
    // And the two travel to the server separately, so widening one leaves the
    // other where it was.
    expect(listQuery(new URLSearchParams("on=branch&on=tag&support=in-support"))).toMatchObject({
      on: ["branch", "tag"],
      support: ["in-support"],
    });
  });

  it("takes a number of days as a window rather than as overdue", () => {
    expect(listQuery(new URLSearchParams("running=7"))).toMatchObject({ due_within: 7 });
  });

  it("refuses a page size nobody offered", () => {
    // It reaches the server as a limit, and the server has its own bound; the
    // point here is that the screen and the query agree on one number.
    expect(pageSize(new URLSearchParams("page=1000"))).toBe(50);
    expect(pageSize(new URLSearchParams("page=200"))).toBe(200);
  });

  it("leaves out a build the address does not name", () => {
    expect(where(new URLSearchParams("stream=main"))).toEqual({ stream: "main" });
    expect(where(new URLSearchParams())).toEqual({});
  });
});

describe("where a row opens", () => {
  it("carries the version, because a component name is not unique in a build", () => {
    expect(
      pathTo(
        { product: "sonic", stream: "main", variant: "broadcom" },
        {
          vulnerability: "CVE-2024-1",
          component: "zlib",
          version: "1.2.11",
        },
      ),
    ).toBe(
      "/products/sonic/streams/main/variants/broadcom/findings/CVE-2024-1/components/zlib?version=1.2.11",
    );
  });

  it("carries the list as one value, so a filter added to the list needs nothing here", () => {
    const at = pathTo(
      { product: "sonic", stream: "main", variant: "broadcom" },
      { vulnerability: "CVE-2024-1", component: "zlib", version: "" },
      "state=undecided&offset=50",
    );
    const asked = new URLSearchParams(at.split("?")[1]);
    expect(asked.get("from")).toBe("state=undecided&offset=50");
    expect(asked.has("version")).toBe(false);
  });

  // A rule prepares a claim and a person proposes it, so what travels to the
  // finding is which filter was picked. The name rather than the words: the
  // filter decides what it says, and a copy in the address would go stale the
  // moment somebody saved over the name.
  it("names the saved filter a prepared claim comes from", () => {
    const at = pathTo(
      { product: "sonic", stream: "main", variant: "broadcom" },
      { vulnerability: "CVE-2024-1", component: "zlib", version: "" },
      "state=undecided",
      "overdue kernel",
    );
    expect(new URLSearchParams(at.split("?")[1]).get("rule")).toBe("overdue kernel");
  });

  it("says nothing about a rule where no filter prepares one", () => {
    const at = pathTo(
      { product: "sonic", stream: "main", variant: "broadcom" },
      { vulnerability: "CVE-2024-1", component: "zlib", version: "" },
      "",
    );
    expect(new URLSearchParams(at.split("?")[1]).has("rule")).toBe(false);
  });
});

describe("a number the address carries", () => {
  // `Number("")` is 0 and `Number("soon")` is NaN, and both went to the server
  // as they were: NaN reached it as the text "NaN", and 0 reached a parameter
  // whose stated minimum is 1. The address is somebody else's text like any
  // other, and a value outside what the server takes is a parameter to leave
  // off rather than one to send wrong.
  it("is left off where it is not a number at all", () => {
    expect(listQuery(new URLSearchParams("running=soon")).due_within).toBeUndefined();
    expect(listQuery(new URLSearchParams("open_for=lately")).open_for).toBeUndefined();
  });

  it("is left off where it is outside what the server takes", () => {
    expect(listQuery(new URLSearchParams("open_for=0")).open_for).toBeUndefined();
    expect(listQuery(new URLSearchParams("running=0")).due_within).toBeUndefined();
    expect(listQuery(new URLSearchParams("open_for=-3")).open_for).toBeUndefined();
  });

  it("is sent where it is one", () => {
    expect(listQuery(new URLSearchParams("open_for=14")).open_for).toBe(14);
    expect(listQuery(new URLSearchParams("running=7")).due_within).toBe(7);
  });

  it("reads an offset that is not a number as the first page", () => {
    expect(listQuery(new URLSearchParams("offset=nowhere")).offset).toBe(0);
    expect(listQuery(new URLSearchParams("offset=100")).offset).toBe(100);
  });
});

describe("every order the list offers", () => {
  it("names each of the server's own orders", () => {
    // The typing is what enforces this; the assertion is here so that the
    // reason is written down beside the words. An order the server gains and
    // the control does not offer is reachable by typing an address and by
    // nothing else, which is what happened to urgency and age.
    expect(Object.keys(ORDERS).sort()).toEqual(
      ["age", "deadline", "epss", "places", "severity", "urgency"].sort(),
    );
  });

  it("puts the four column headers among them", () => {
    for (const word of Object.values(SORTS)) expect(ORDERS).toHaveProperty(word);
  });

  it("opens a deadline at the soonest and everything else at the worst", () => {
    // Due opened at the furthest-away date, which answers a question nobody
    // asks. Age is the same shape: what has sat here longest is the question.
    expect(LEAST_FIRST).toContain("deadline");
    expect(LEAST_FIRST).toContain("age");
    for (const word of ["severity", "epss", "places", "urgency"] as const) {
      expect(LEAST_FIRST).not.toContain(word);
    }
  });
});

describe("a date the address carries", () => {
  it("is the date rather than the word", () => {
    // A relative word in an address means something different whenever the
    // link is opened, and every filter here lives in the address so that a
    // list can be sent to somebody.
    expect(daysBack(1, new Date("2026-03-01T09:30:00Z"))).toBe("2026-02-28");
    expect(daysBack(7, new Date("2026-01-03T00:00:00Z"))).toBe("2025-12-27");
  });

  it("crosses a leap day like any other", () => {
    expect(daysBack(1, new Date("2028-03-01T12:00:00Z"))).toBe("2028-02-29");
  });
});

describe("widening out of a scope", () => {
  // The query half of what widened() built, since the rest of it is a path.
  const query = (address: string) => new URLSearchParams(address.split("?")[1] ?? "");

  // The selection rides on the path, so widening is a move. What it must not
  // do is drop the narrowing somebody actually chose on the way: that is the
  // second surprise on top of the one the scope chip exists to end.
  it("carries the filters across", () => {
    const asked = new URLSearchParams("assigned=nobody&state=undecided&on=branch");
    const out = query(widened("/findings", asked));
    expect(out.get("assigned")).toBe("nobody");
    expect(out.get("state")).toBe("undecided");
    expect(out.get("on")).toBe("branch");
  });

  it("lets the address being built own the branch and the variant", () => {
    // findingsPath puts back whichever of these the new scope still has, so
    // carrying the old ones would name a build the new path is not about.
    const asked = new URLSearchParams("state=undecided&stream=master&variant=broadcom");
    const out = query(widened("/products/sonic/findings?stream=master", asked));
    expect(out.getAll("stream")).toEqual(["master"]);
    expect(out.getAll("variant")).toEqual([]);
    expect(out.get("state")).toBe("undecided");
  });

  it("keeps every value of a filter that has several", () => {
    const asked = new URLSearchParams("state=undecided&state=waiting&state=lapsed");
    const out = query(widened("/findings", asked));
    expect(out.getAll("state")).toEqual(["undecided", "waiting", "lapsed"]);
  });

  it("asks for nothing where nothing was asked", () => {
    expect(widened("/findings", new URLSearchParams())).toBe("/findings");
  });
});
