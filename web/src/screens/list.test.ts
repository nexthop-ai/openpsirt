import { describe, expect, it } from "vitest";
import { asAsked, fromAt, listQuery, pageSize, pathTo, where, windowFor } from "./list";

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

  it("asks for no more than the server returns", () => {
    // At the largest page there is no room to widen, so the walk ends at the
    // page edge rather than quietly asking for more than it can have.
    expect(windowFor(0, 200)).toEqual({ offset: 0, limit: 200 });
    expect(windowFor(200, 200)).toEqual({ offset: 199, limit: 200 });
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
    // Deciding covered work again one finding at a time is what the promise
    // was made instead of. Written into the address rather than applied on the
    // way to the server, so it is a chip like every other filter — and the
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
});
