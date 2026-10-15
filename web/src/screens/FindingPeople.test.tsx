// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { belongTo } from "../app/drafts";
import { Attachments, Collaborators, Marks, Resolve } from "./FindingPeople";
import { Disclose } from "./FindingDisclose";
import { FindingWhich } from "./FindingWhich";
import { Notes } from "./FindingNotes";
import { button, change, press } from "../test/controls";
import { accept, answer, mounted, screen, serve, settle, type Sent } from "../test/mount";

const mount = mounted();

beforeEach(() => {
  window.localStorage.clear();
  belongTo("oidc:ana");
});

afterEach(() => vi.restoreAllMocks());

const issue = { product: "sonic", vulnerability: "OPENPSIRT-2026-1" };
const at = {
  product: "sonic",
  stream: "master",
  variant: "broadcom",
  vulnerability: "OPENPSIRT-2026-1",
  component: "libnl",
  version: "3.7",
  ecosystem: "",
  namespace: "",
};

const pathOf = (sent: Sent) =>
  (sent[1] as { params: { path: Record<string, string> } }).params.path;
const bodyOf = (sent: Sent) => (sent[1] as { body: unknown }).body;

describe("the people on a case", () => {
  it("brings in the person typed and takes off the person pressed", async () => {
    serve((path) => {
      if (path === "/v1/products/{product}/issues/{vulnerability}/collaborators") {
        return { data: { items: [{ identity: "bob", name: "Bob", added_by: "ana" }] } };
      }
      if (path === "/v1/products/{product}/mentionable") {
        return {
          data: {
            items: [
              { identity: "bob", name: "Bob" },
              { identity: "cy", name: "Cy" },
            ],
          },
        };
      }
      return undefined;
    });
    const put = answer("PUT", () => ({ data: {} }));
    const taken = answer("DELETE", () => ({ data: {} }));
    mount.render(screen(<Collaborators {...issue} />));
    await settle();
    expect(mount.host().textContent).toContain("1 person has been brought in.");
    expect(button(mount.host(), "Add collaborator").disabled).toBe(true);
    change(mount.host().querySelector<HTMLInputElement>("#bring-in"), "Cy (cy)");
    await settle();
    await press(mount.host(), "Add collaborator");
    await settle();
    expect(put().map(pathOf)).toEqual([{ ...issue, identity: "cy" }]);
    await press(mount.host(), "×");
    await settle();
    expect(taken().map(pathOf)).toEqual([{ ...issue, identity: "bob" }]);
  });

  it("stays quiet for somebody the case is not open to", async () => {
    serve((path) =>
      path === "/v1/products/{product}/issues/{vulnerability}/collaborators"
        ? { status: 403 }
        : { data: { items: [] } },
    );
    mount.render(screen(<Collaborators {...issue} />));
    await settle();
    expect(mount.host().textContent).toBe("");
  });
});

describe("closing a recorded flaw by hand", () => {
  it("sends the fix as written, and only once there is one", async () => {
    serve(() => undefined);
    const sent = accept(() => ({ data: {} }));
    mount.render(
      screen(
        <Resolve
          at={{ product: "sonic", stream: "master", variant: "broadcom" }}
          vulnerability="OPENPSIRT-2026-1"
        />,
      ),
    );
    await press(mount.host(), "Close as fixed…");
    expect(button(mount.host(), "Close as fixed").disabled).toBe(true);
    change(mount.host().querySelector("#res-because"), "  Checked in 1.0.1.  ");
    await press(mount.host(), "Close as fixed");
    await settle();
    expect(sent().map(bodyOf)).toEqual([{ because: "Checked in 1.0.1." }]);
  });
});

describe("the files attached to an issue", () => {
  it("removes a file only with a reason, naming that file", async () => {
    serve((path) =>
      path === "/v1/products/{product}/issues/{vulnerability}/attachments"
        ? {
            data: {
              items: [
                { token: "tok-1", filename: "trace.txt", size: 10, content_type: "text/plain" },
              ],
            },
          }
        : undefined,
    );
    const removed = answer("DELETE", () => ({ data: {} }));
    mount.render(screen(<Attachments about={issue} admin />));
    await settle();
    await press(mount.host(), "Remove");
    expect(button(mount.host(), "Remove the file").disabled).toBe(true);
    change(
      mount.host().querySelector<HTMLInputElement>(".files input"),
      "A credential was pasted.",
    );
    await press(mount.host(), "Remove the file");
    await settle();
    expect(removed().map(pathOf)).toEqual([{ token: "tok-1" }]);
    expect(removed().map(bodyOf)).toEqual([{ reason: "A credential was pasted." }]);
  });

  it("offers no removal to somebody who is not an administrator", async () => {
    serve(() => ({ data: { items: [{ token: "tok-1", filename: "trace.txt" }] } }));
    mount.render(screen(<Attachments about={issue} admin={false} />));
    await settle();
    expect(() => button(mount.host(), "Remove")).toThrow();
  });
});

describe("the tags on a finding", () => {
  it("adds the tag typed and removes the one pressed, on this component", async () => {
    serve(() => ({ data: { items: ["waiting on vendor"] } }));
    const put = answer("PUT", () => ({ data: {} }));
    const removed = answer("DELETE", () => ({ data: {} }));
    const changed = vi.fn();
    mount.render(screen(<Marks at={at} tags={["triaged"]} mayMark onChanged={changed} />));
    await press(mount.host(), "+ Tag");
    await settle();
    change(mount.host().querySelector<HTMLInputElement>("#tag-with"), "upstream asked");
    await press(mount.host(), "Add");
    await settle();
    expect(put().map(pathOf)).toEqual([
      {
        product: "sonic",
        stream: "master",
        variant: "broadcom",
        vulnerability: "OPENPSIRT-2026-1",
        component: "libnl",
        tag: "upstream asked",
      },
    ]);
    const remove = mount
      .host()
      .querySelector<HTMLButtonElement>('[aria-label="Remove tag triaged"]');
    act(() => remove?.click());
    await settle();
    expect(removed().map((each) => pathOf(each).tag)).toEqual(["triaged"]);
    expect(changed).toHaveBeenCalledTimes(2);
  });

  it("shows the tags and no control to somebody who may only read", () => {
    serve(() => undefined);
    mount.render(
      screen(<Marks at={at} tags={["triaged"]} mayMark={false} onChanged={() => undefined} />),
    );
    expect(mount.host().textContent).toBe("triaged");
    expect(mount.host().querySelectorAll("button")).toHaveLength(0);
  });
});

describe("ending an embargo", () => {
  it("says it waits on a second person when the server does not put it in force", async () => {
    serve(() => ({ data: { items: [] } }));
    const sent = accept(() => ({ data: { in_force: false } }));
    mount.render(screen(<Disclose {...issue} />));
    await press(mount.host(), "Disclose…");
    expect(button(mount.host(), "Disclose").disabled).toBe(true);
    change(mount.host().querySelector("textarea"), "Published upstream.");
    await press(mount.host(), "Disclose");
    await settle();
    expect(sent().map(bodyOf)).toEqual([{ reason: "Published upstream." }]);
    expect(mount.host().textContent).toContain("stays undisclosed until a second person agrees");
  });
});

describe("the notes on an issue", () => {
  it("adds a note to the issue in this product", async () => {
    serve((path) =>
      path === "/v1/products/{product}/issues/{vulnerability}/notes"
        ? { data: { items: [] } }
        : { data: { items: [] } },
    );
    const sent = accept(() => ({ data: { id: 1, not_notified: [] } }));
    mount.render(screen(<Notes {...issue} mine={() => true} />));
    await settle();
    expect(mount.host().textContent).toContain("Notes on this issue");
    change(mount.host().querySelector("textarea"), "Vendor says next week.");
    await press(mount.host(), "Note");
    await settle();
    expect(sent().map(pathOf)).toEqual([issue]);
    expect(sent().map(bodyOf)).toEqual([{ body: "Vendor says next week." }]);
  });
});

describe("which component a finding is about", () => {
  it("links each choice with what picks it, keeping the list it was opened from", () => {
    mount.render(
      screen(
        <FindingWhich
          component="libnl"
          choices={[{ version: "3.7", ecosystem: "deb", namespace: "debian" }, { version: "3.8" }]}
          params={new URLSearchParams("from=state%3Dopen&version=old")}
        />,
      ),
    );
    const links = Array.from(mount.host().querySelectorAll("a")).map((each) =>
      each.getAttribute("href"),
    );
    expect(links).toEqual([
      "/?from=state%3Dopen&version=3.7&ecosystem=deb&namespace=debian",
      "/?from=state%3Dopen&version=3.8",
    ]);
    expect(mount.host().textContent).toContain("deb/debian");
  });
});
