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
