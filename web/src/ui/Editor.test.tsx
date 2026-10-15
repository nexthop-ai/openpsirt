// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { act, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { belongTo } from "../app/drafts";
import { Editor } from "./Editor";
import { Thread } from "./Thread";
import { mounted, screen, serve, settle } from "../test/mount";

const mount = mounted();

beforeEach(() => {
  window.localStorage.clear();
  belongTo("oidc:ana");
});

afterEach(() => vi.restoreAllMocks());

function type(field: HTMLTextAreaElement | null, value: string) {
  if (!field) throw new Error("no such field");
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(
      field,
      value,
    );
    field.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function Writing({ start = "", draftKey }: { start?: string; draftKey?: string }) {
  const [value, setValue] = useState(start);
  return (
    <>
      <Editor
        value={value}
        onChange={setValue}
        draftKey={draftKey}
        label="Reasoning"
        attachTo={{ product: "sonic", vulnerability: "CVE-2026-1" }}
      />
      <button type="button" onClick={() => setValue("")}>
        Clear
      </button>
    </>
  );
}

describe("the editor", () => {
  it("keeps what was typed while a file was uploading", async () => {
    serve(() => ({ data: { items: [] } }));
    let answer: (value: unknown) => void = () => undefined;
    vi.spyOn(api, "POST").mockImplementation(
      (() =>
        new Promise((resolve) => {
          answer = resolve;
        })) as never,
    );
    mount.render(screen(<Writing />));
    const box = mount.host().querySelector("textarea");
    const chooser = mount.host().querySelector<HTMLInputElement>('input[type="file"]');
    if (!chooser) throw new Error("no attach control");
    Object.defineProperty(chooser, "files", { value: [new File(["x"], "proof.png")] });
    act(() => {
      chooser.dispatchEvent(new Event("change", { bubbles: true }));
    });
    type(box, "Typed while it uploaded. ");
    await act(async () => {
      answer({
        data: { filename: "proof.png", reference: "attachment:1", inline: true },
        response: new Response(null, { status: 201 }),
      });
    });
    await settle();
    expect(box?.value).toContain("Typed while it uploaded.");
    expect(box?.value).toContain("![proof.png](attachment:1)");
  });

  it("leaves prefilled text cleared once it is cleared", async () => {
    serve(() => ({ data: { items: [] } }));
    mount.render(screen(<Writing start="Filled in from a rule." draftKey="decide:1" />));
    await settle();
    act(() => {
      Array.from(mount.host().querySelectorAll("button"))
        .find((each) => each.textContent === "Clear")
        ?.click();
    });
    await settle();
    expect(mount.host().querySelector("textarea")?.value).toBe("");
  });
});

function useHistory(id: number) {
  return useQuery({
    queryKey: ["comment", id, "history"],
    queryFn: async () => ({
      items: [{ version: 1, body: "What it said first.", replaced_at: "2026-10-01T00:00:00Z" }],
    }),
  });
}

describe("a thread", () => {
  it("shows an edited piece's earlier wording", async () => {
    serve(() => ({ data: { items: [] } }));
    mount.render(
      screen(
        <Thread
          items={[
            {
              id: 3,
              body: "What it says now.",
              written_by: "ana",
              written_at: "2026-10-01T00:00:00Z",
              edited_at: "2026-10-02T00:00:00Z",
            },
          ]}
          mine={() => false}
          about={{ product: "sonic", vulnerability: "CVE-2026-1" }}
          word="Comment"
          consequence="Does not affect the approval"
          placeholder=""
          draftKey="comment:9"
          notNotified={[]}
          adding={{ isPending: false, error: null }}
          onAdd={() => undefined}
          edit={() => null}
          useHistory={useHistory}
        />,
      ),
    );
    await settle();
    act(() => mount.host().querySelector<HTMLButtonElement>("button.edited")?.click());
    await settle();
    expect(mount.host().textContent).toContain("What it said first.");
  });
});

describe("naming somebody and attaching a file", () => {
  function Mentioning({ visibility }: { visibility?: "public" | "private" }) {
    const [value, setValue] = useState("");
    return (
      <>
        <Editor
          value={value}
          onChange={setValue}
          label="Reasoning"
          mentions={{ product: "sonic", visibility }}
          attachTo={{ product: "sonic", vulnerability: "CVE-2026-1" }}
        />
        <output>{value}</output>
      </>
    );
  }

  const field = () => mount.host().querySelector<HTMLTextAreaElement>("textarea");
  const said = () => mount.host().querySelector("output")?.textContent;

  it("offers only people who may read what this is about, narrowed by what follows the @", async () => {
    const reads = serve((path) =>
      path === "/v1/products/{product}/mentionable"
        ? { data: { items: [{ identity: "ana", name: "Ana Lopez" }] } }
        : undefined,
    );
    mount.render(screen(<Mentioning visibility="private" />));
    await settle();
    type(field(), "Ask @an");
    await settle();
    const asked = (reads.mock.calls as unknown as [string, { params: { query: object } }][]).at(-1);
    expect(asked?.[1].params.query).toEqual({ visibility: "private", limit: 25, q: "an" });
    const offered = Array.from(mount.host().querySelectorAll("button")).find((each) =>
      each.textContent?.startsWith("@ana"),
    );
    await act(async () => offered?.click());
    expect(said()).toBe("Ask @ana ");
  });

  it("writes an image the server took as one inline, and anything else as a link", async () => {
    serve(() => undefined);
    const answers = [
      { filename: "shot.png", reference: "attachment:aaaa", inline: true },
      { filename: "trace.txt", reference: "attachment:bbbb", inline: false },
    ];
    vi.spyOn(api, "POST").mockImplementation((async () => ({
      data: answers.shift(),
      error: undefined,
      response: new Response(null, { status: 201 }),
    })) as never);
    mount.render(screen(<Mentioning />));
    await settle();
    const chooser = mount.host().querySelector<HTMLInputElement>('input[type="file"]');
    for (const name of ["shot.png", "trace.txt"]) {
      Object.defineProperty(chooser, "files", {
        value: [new File(["x"], name)],
        configurable: true,
      });
      await act(async () => chooser?.dispatchEvent(new Event("change", { bubbles: true })));
      await settle();
    }
    expect(said()).toContain("![shot.png](attachment:aaaa)");
    expect(said()).toContain("[trace.txt](attachment:bbbb)");
    expect(said()).not.toContain("![trace.txt]");
  });

  it("says why a file was refused", async () => {
    serve(() => undefined);
    vi.spyOn(api, "POST").mockImplementation((async () => ({
      data: undefined,
      error: { detail: "the file is larger than this deployment takes" },
      response: new Response(null, { status: 413 }),
    })) as never);
    mount.render(screen(<Mentioning />));
    await settle();
    const chooser = mount.host().querySelector<HTMLInputElement>('input[type="file"]');
    Object.defineProperty(chooser, "files", {
      value: [new File(["x"], "big.bin")],
      configurable: true,
    });
    await act(async () => chooser?.dispatchEvent(new Event("change", { bubbles: true })));
    await settle();
    expect(mount.host().textContent).toContain("larger than this deployment takes");
  });

  it("wraps the cursor in the mark pressed, and previews the text", async () => {
    serve(() => undefined);
    mount.render(screen(<Mentioning />));
    await settle();
    type(field(), "see ");
    await act(async () =>
      mount.host().querySelector<HTMLButtonElement>('button[title="Bold"]')?.click(),
    );
    expect(said()).toBe("see ****");
    await act(async () =>
      Array.from(mount.host().querySelectorAll("button"))
        .find((each) => each.textContent === "Preview")
        ?.click(),
    );
    expect(field()).toBeNull();
  });
});
