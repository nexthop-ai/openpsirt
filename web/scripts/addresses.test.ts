// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { addressesIn, readsIn, screensOf, table, unread, unrouted } from "./addresses.mjs";

// Both directions per shape — one input that must be reported and one that
// must not — because the failure that matters here is the check going quiet.

const routes = table();
const found = (text: string) =>
  addressesIn(routes, text).found.map((each: { address: string }) => each.address);

describe("an address written out whole", () => {
  it("is reported where no route answers it", () => {
    expect(found(`navigate("/queue?mine=true");`)).toEqual(["/queue?mine=true"]);
    expect(found(`<Link to="/review-queue" />;`)).toEqual([]);
  });

  it("is reported where the screen there does not read a parameter it sets", () => {
    expect(found(`navigate("/review-queue?tab=mine");`)).toEqual(["/review-queue?tab=mine"]);
    expect(found(`navigate("/review-queue?mine=1#lapsed");`)).toEqual([]);
  });

  it("is not a file the page loads", () => {
    expect(found(`<img src="/brand/logo.svg" />;`)).toEqual([]);
  });
});

describe("an address put together from parts", () => {
  it("is reported as a template outside routes.ts", () => {
    expect(found("const to = `/products/${encodeURIComponent(p)}/inbox`;")).toEqual([
      "/products/${}/inbox",
    ]);
  });

  it("is reported where a prefix held in a name has a segment joined on", () => {
    expect(found(`const to = buildAt + "/tree?at=" + encodeURIComponent(c);`)).toEqual([
      "/tree?at=",
    ]);
    expect(found("const to = `${inbox}/${encodeURIComponent(reference)}`;")).toEqual(["${}/${}"]);
  });

  it("is reported where a query is glued onto an address built elsewhere", () => {
    expect(found("const to = `${findingsPath(at)}?${asked}`;")).toEqual(["${}?${}"]);
    expect(found('const to = `${path}${path.includes("?") ? "&" : "?"}q=${term}`;')).toEqual([
      "${}${}q=${}",
    ]);
    expect(found("const to = `${path}&only=${only}`;")).toEqual(["${}&only=${}"]);
    expect(found("const asked = `Remove ${name}?`;")).toEqual([]);
  });

  it("is not reported where it is an address of the API", () => {
    expect(found(`const file = apiBuildPath(at) + "/vex";`)).toEqual([]);
    expect(found("const file = `${apiBuildPath(at)}/pending-upgrades.${format}`;")).toEqual([]);
    expect(
      found("const base = apiBuildPath(at) + `/vex`;\nconst one = `${base}/issuance/${v}`;"),
    ).toEqual([]);
    expect(found("const where = `/v1/products/${encodeURIComponent(p)}`;")).toEqual([]);
    expect(
      found(
        'const base = all ? "/v1/findings" : `/v1/products/${p}`;\nconst to = `${base}.csv?${q}`;',
      ),
    ).toEqual([]);
  });

  it("is not reported where it is a React key or an address elsewhere", () => {
    expect(found("<div key={`${path}/version`} />;")).toEqual([]);
    expect(
      found("const to = `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;"),
    ).toEqual([]);
  });
});

describe("a parameter the route table lists", () => {
  const screens = screensOf(
    `const Queue = retrying(() =>\n  import("../screens/Queue").then((m) => m.Queue));\n` +
      `<Route path={ROUTES.reviewQueue} element={<Queue />} />`,
  );

  it("reads the screen each route renders", () => {
    expect(screens.get("reviewQueue")).toBe("../screens/Queue");
  });

  it("is reported where the screen reads no such parameter", () => {
    const reads = () => readsIn(`const mine = params.get("mine");`);
    expect(
      unread({ reviewQueue: { path: "/review-queue", query: ["tab"] } }, screens, reads),
    ).toEqual([{ route: "reviewQueue", key: "tab", why: "unread" }]);
    expect(
      unread({ reviewQueue: { path: "/review-queue", query: ["mine"] } }, screens, reads),
    ).toEqual([]);
  });

  it("is reported where the route renders no screen to read it", () => {
    expect(
      unread({ unassigned: { path: "/unassigned", query: ["tab"] } }, screens, () => new Set()),
    ).toHaveLength(1);
  });
});

describe("the route check", () => {
  it("matches one segment per parameter, and none empty", () => {
    expect(unrouted(routes, "/claims/7")).toBe("");
    expect(unrouted(routes, "/claims/")).not.toBe("");
    expect(unrouted(routes, "/claims/7/8")).not.toBe("");
  });
});
