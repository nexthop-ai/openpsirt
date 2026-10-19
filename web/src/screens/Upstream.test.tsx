// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UpstreamDrawer } from "./Upstream";
import { UpstreamOffers } from "./QueueOffers";
import { UpstreamSaid } from "../ui/UpstreamSaid";
import { accept, answer, mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const ADDRESS = "https://psirt.example.org/.well-known/csaf/provider-metadata.json";

function button(label: string) {
  return Array.from(document.querySelectorAll<HTMLButtonElement>("button")).find(
    (each) => each.textContent?.trim() === label,
  );
}

function type(value: string) {
  const input = document.getElementById("declare-provider-description") as HTMLInputElement;
  act(() => {
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    set?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

describe("the upstream drawer", () => {
  it("checks an upstream, shows its key, and trusts it with that key", async () => {
    serve((path) => (path === "/v1/products/{product}/upstream" ? { status: 404 } : undefined));
    accept(() => ({ data: { publisher: "SONiC Project", fingerprint: "ABCD1234" } }));
    const trusted = answer("PUT", () => ({ data: { url: ADDRESS, publisher: "SONiC Project" } }));
    mount.render(screen(<UpstreamDrawer product="fork-os" open onClose={() => undefined} />));
    await settle();
    expect(document.body.textContent).toContain("None.");

    type(ADDRESS);
    await settle();
    act(() => button("Check")?.click());
    await settle();
    expect(document.body.textContent).toContain("SONiC Project");
    expect(document.body.textContent).toContain("ABCD1234");

    act(() => button("Trust")?.click());
    await settle();
    const [path, init] = trusted()[0] ?? [];
    expect(path).toBe("/v1/products/{product}/upstream");
    expect((init as { body: unknown }).body).toEqual({ url: ADDRESS, fingerprint: "ABCD1234" });
  });

  it("says when the upstream names a key other than the one trusted", async () => {
    serve((path) =>
      path === "/v1/products/{product}/upstream"
        ? {
            data: {
              url: ADDRESS,
              publisher: "SONiC Project",
              fingerprint: "ABCD1234",
              key_offered: "EEEE9999",
              trusted_at: "2026-10-19T00:00:00Z",
              because: "the upstream names a signing key other than the one trusted",
            },
          }
        : undefined,
    );
    mount.render(screen(<UpstreamDrawer product="fork-os" open onClose={() => undefined} />));
    await settle();
    expect(document.body.textContent).toContain("now signs with EEEE9999");
    expect(document.body.textContent).toContain("Last error");
    expect(document.body.textContent).toContain("names a signing key other than the one trusted");
    expect(button("Stop trusting")).toBeDefined();
  });
});

describe("an upstream's statement", () => {
  it("links its document only where the address is one to send a reader to", async () => {
    serve(() => undefined);
    mount.render(
      screen(
        <>
          <UpstreamSaid
            statement={1}
            forAnybody
            declined={false}
            document="https://psirt.example.org/doc.json"
            mayTriage={false}
          />
          <UpstreamSaid
            statement={2}
            forAnybody={false}
            declined
            document="javascript:alert(1)"
            mayTriage={false}
          />
        </>,
      ),
    );
    await settle();
    const links = mount.host().querySelectorAll("a");
    expect(links).toHaveLength(1);
    expect(links[0]?.getAttribute("href")).toBe("https://psirt.example.org/doc.json");
    expect(mount.host().textContent).toContain("upstream · applies here");
    expect(mount.host().textContent).toContain("upstream · declined");
    expect(button("Decline")).toBeUndefined();
  });

  it("is declined, and restored, by somebody who triages", async () => {
    serve(() => undefined);
    const declined = answer("PUT", () => ({ status: 204 }));
    const restored = answer("DELETE", () => ({ status: 204 }));
    mount.render(
      screen(
        <>
          <UpstreamSaid statement={7} forAnybody declined={false} document="" mayTriage />
          <UpstreamSaid statement={8} forAnybody declined document="" mayTriage />
        </>,
      ),
    );
    await settle();
    act(() => button("Decline")?.click());
    act(() => button("Restore")?.click());
    await settle();
    type Asked = { params: { path: { statement: number } } };
    expect(declined()[0]?.[0]).toBe("/v1/statements/{statement}/declined");
    expect((declined()[0]?.[1] as Asked).params.path.statement).toBe(7);
    expect((restored()[0]?.[1] as Asked).params.path.statement).toBe(8);
  });
});

describe("what upstreams offer for review", () => {
  it("lists each offer beside the finding it speaks about, and nothing where none is", async () => {
    serve((path) =>
      path === "/v1/upstream-offers"
        ? {
            data: {
              items: [
                {
                  statement: 3,
                  finding: 9,
                  product: "fork-os",
                  stream: "main",
                  variant: "x86",
                  publisher: "sonic project",
                  issue: "CVE-2026-1002",
                  component: "libnl-3-200",
                  version: "3.7.0",
                  status: "not_affected",
                  justification: "vulnerable_code_not_in_execute_path",
                  document: "https://psirt.example.org/doc.json",
                  document_id: "VEX-sonic-CVE-2026-1002",
                },
              ],
            },
          }
        : { data: {} },
    );
    mount.render(screen(<UpstreamOffers />));
    await settle();
    expect(mount.host().textContent).toContain("Offered by an upstream");
    expect(mount.host().textContent).toContain("CVE-2026-1002 · libnl-3-200 3.7.0");
    expect(mount.host().textContent).toContain("upstream · for review");
  });

  it("draws nothing where nothing is offered", async () => {
    serve((path) => (path === "/v1/upstream-offers" ? { data: { items: [] } } : { data: {} }));
    mount.render(screen(<UpstreamOffers product="fork-os" />));
    await settle();
    expect(mount.host().textContent).toBe("");
  });
});
