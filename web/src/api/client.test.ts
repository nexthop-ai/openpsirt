// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import { api, csrf, csrfCookie, dotSegments } from "./client";

// The `__Host-` prefix is the only thing stopping a sibling host under the
// same registrable domain writing a cookie this deployment then reads. Two
// cookies of equal path length are ordered by when they were created, so a
// reader taking whichever name comes first sends a planted one.
// jsdom's own cookie jar orders by its own rules, so the two names are put in
// the order under test directly. What is being pinned is which of two the
// reader prefers, not how a browser stores them.
function set(...pairs: string[]) {
  Object.defineProperty(document, "cookie", { value: pairs.join("; "), configurable: true });
}

afterEach(() => {
  Object.defineProperty(document, "cookie", { value: "", configurable: true });
});

describe("which CSRF cookie is echoed", () => {
  it("prefers the prefixed one, whichever was written first", () => {
    set("openpsirt_csrf=planted", "__Host-openpsirt_csrf=ours");
    expect(csrfCookie()).toBe("ours");
    set("__Host-openpsirt_csrf=ours", "openpsirt_csrf=planted");
    expect(csrfCookie()).toBe("ours");
  });

  it("takes the bare one where there is no prefixed one", () => {
    // A deployment served without TLS holds only this name: a browser refuses
    // the prefix over plain HTTP, so dropping the fallback would break every
    // write there.
    set("openpsirt_csrf=plain");
    expect(csrfCookie()).toBe("plain");
  });

  it("decodes what it finds, and passes on what will not decode", () => {
    set("__Host-openpsirt_csrf=a%20b");
    expect(csrfCookie()).toBe("a b");
    // A malformed escape throws out of `decodeURIComponent`, and this runs in
    // the middleware every write goes through, so a throw here fails every
    // write in the application.
    set("__Host-openpsirt_csrf=%E0%A4%A");
    expect(() => csrfCookie()).not.toThrow();
    expect(csrfCookie()).toBe("%E0%A4%A");
  });

  it("answers with nothing where neither is set", () => {
    set("");
    expect(csrfCookie()).toBe("");
  });
});

// The middleware every request passes through. Called directly, because what
// is pinned is which requests carry the token, and that needs no server.
async function sent(method: string): Promise<Request> {
  const request = new Request("http://psirt.example/v1/anything", { method });
  const out = await csrf.onRequest!({ request } as never);
  return (out as Request | undefined) ?? request;
}

describe("which requests carry the CSRF token", () => {
  it.each(["POST", "PUT", "PATCH", "DELETE"])("%s carries the cookie's value", async (method) => {
    set("__Host-openpsirt_csrf=ours");
    expect((await sent(method)).headers.get("X-CSRF-Token")).toBe("ours");
  });

  it.each(["GET", "HEAD"])("%s carries none", async (method) => {
    set("__Host-openpsirt_csrf=ours");
    expect((await sent(method)).headers.has("X-CSRF-Token")).toBe(false);
  });

  it("sends no empty header where there is no cookie", async () => {
    set("");
    expect((await sent("POST")).headers.has("X-CSRF-Token")).toBe(false);
  });
});

// The middleware above does nothing unless the client every screen uses runs
// it. Verified by removing the registration: this request then leaves with no
// token, which every write in the application would too.
describe("the application's client", () => {
  it("runs the CSRF middleware on what it sends", async () => {
    set("__Host-openpsirt_csrf=ours");
    let seen: Request | undefined;
    await api.POST("/v1/teams", {
      body: { name: "desk" },
      // A test has no page to resolve the client's relative base against.
      baseUrl: "http://psirt.example",
      fetch: async (request: Request) => {
        seen = request;
        return new Response("{}", {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      },
    } as never);
    expect(seen?.headers.get("X-CSRF-Token")).toBe("ours");
  });
});

describe("a request naming a dot segment", () => {
  it("is answered as a refusal before it is sent", async () => {
    // The browser would send it to the route above: deleting a branch named
    // ".." would ask to delete its product.
    const ask = (branch_or_tag: string) =>
      dotSegments.onRequest?.({
        request: new Request("http://psirt.example/v1/products/sonic"),
        schemaPath: "/v1/products/{product}/branches-and-tags/{branch_or_tag}",
        params: { path: { product: "sonic", branch_or_tag } },
        options: {} as never,
        id: "1",
      });
    for (const dots of [".", ".."]) {
      const answered = await ask(dots);
      expect(answered).toBeInstanceOf(Response);
      expect((answered as Response).status).toBe(400);
      expect(await (answered as Response).text()).toContain("{branch_or_tag}");
    }
    expect(await ask("...")).toBeUndefined();
  });

  // The middleware does nothing unless the client every screen uses runs it.
  // Sent, revoking a token of a person named ".." would revoke the caller's
  // own token of that name.
  it("is never sent by the client every screen uses", async () => {
    let sent = false;
    const out = await api.DELETE("/v1/people/{identity}/tokens/{name}", {
      params: { path: { identity: "..", name: "build" } },
      baseUrl: "http://psirt.example",
      fetch: async () => {
        sent = true;
        return new Response(null, { status: 204 });
      },
    } as never);
    expect(sent).toBe(false);
    expect(out.response.status).toBe(400);
  });
});
