// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Repositories } from "./Repositories";
import { answer, client, mounted, screen, serve, settle, watchInvalidations } from "../test/mount";
import { button, change, only, press } from "../test/controls";

const mount = mounted();

afterEach(() => vi.restoreAllMocks());

const HELD = {
  hosts: [
    { remote: "github.com", web: "https://github.com", style: "github" },
    {
      remote: "git.example.com",
      web: "https://git.example.com",
      style: "custom",
      file_template: "{repo}/src/{commit}/{path}",
      compare_template: "{repo}/compare/{from}..{to}",
    },
  ],
  paths: [
    { prefix: "", snippets: false },
    {
      prefix: "src/sonic-swss",
      remote: "github.com/sonic-net/sonic-swss",
      branch: "master",
      snippets: true,
    },
  ],
};

async function drawn(admin = true, held: unknown = HELD) {
  const reads = serve((path) => {
    if (path === "/v1/session/me")
      return {
        data: { identity: "ana", name: "Ana", admin, kind: "person", reach: [], outcomes: [] },
      };
    if (path === "/v1/products/{product}/repositories") return { data: held };
    return undefined;
  });
  const put = answer("PUT", () => ({ status: 204 }));
  const queries = client();
  const invalidated = watchInvalidations(queries);
  mount.render(
    screen(
      <Repositories />,
      "/products/sonic/repositories",
      "/products/:product/repositories",
      queries,
    ),
  );
  await settle();
  return { reads, put, invalidated };
}

const host = () => mount.host();
const field = <T extends Element>(label: string) => {
  const found = host().querySelector<T>(`[aria-label="${label}"]`);
  if (!found) throw new Error(`no control labeled "${label}"`);
  return found;
};
// Presses the remove control the label names: each row has one, all reading
// "Remove", so the row is told apart by its label.
const remove = async (label: string) => {
  const control = field<HTMLButtonElement>(label);
  await act(async () => control.click());
};
const asked = (reads: ReturnType<typeof serve>) =>
  (reads.mock.calls as unknown as [string][]).map(([path]) => path);

describe("a product's repository settings, for an administrator", () => {
  it("draws each host and path as the server holds it", async () => {
    await drawn();
    expect(field<HTMLInputElement>("Remote of host 1").value).toBe("github.com");
    expect(field<HTMLSelectElement>("Server of host 2").value).toBe("custom");
    expect(field<HTMLInputElement>("File template of host 2").value).toBe(
      "{repo}/src/{commit}/{path}",
    );
    expect(field<HTMLInputElement>("Branch of path 2").value).toBe("master");
    expect(field<HTMLSelectElement>("Snippets of path 1").value).toBe("no");
    expect(field<HTMLSelectElement>("Disclosure of path 1").value).toBe("");
  });

  it("offers templates only on a custom host", async () => {
    await drawn();
    expect(host().querySelector('[aria-label="File template of host 1"]')).toBeNull();
    change(field<HTMLSelectElement>("Server of host 1"), "custom");
    expect(host().querySelector('[aria-label="File template of host 1"]')).not.toBeNull();
  });

  it("saves nothing until something changed", async () => {
    await drawn();
    expect(button(host(), "Save").disabled).toBe(true);
    change(field<HTMLInputElement>("Branch of path 2"), "main");
    expect(button(host(), "Save").disabled).toBe(false);
  });

  it("sends every row, trimmed, with an inherited setting and an empty field left out", async () => {
    const { put } = await drawn();
    change(field<HTMLInputElement>("Branch of path 2"), " main ");
    change(field<HTMLSelectElement>("Disclosure of path 2"), "yes");
    await press(host(), "Save");
    await settle();
    const [path, init] = only(put);
    expect(path).toBe("/v1/products/{product}/repositories");
    expect(init.params?.path).toEqual({ product: "sonic" });
    expect(init.body).toStrictEqual({
      hosts: [
        { remote: "github.com", web: "https://github.com", style: "github" },
        {
          remote: "git.example.com",
          web: "https://git.example.com",
          style: "custom",
          file_template: "{repo}/src/{commit}/{path}",
          compare_template: "{repo}/compare/{from}..{to}",
        },
      ],
      paths: [
        { prefix: "", snippets: false },
        {
          prefix: "src/sonic-swss",
          remote: "github.com/sonic-net/sonic-swss",
          branch: "main",
          snippets: true,
          disclosed_snippets: true,
        },
      ],
    });
  });

  it("drops a template from a host that is no longer custom", async () => {
    const { put } = await drawn();
    change(field<HTMLSelectElement>("Server of host 2"), "gitea");
    await press(host(), "Save");
    await settle();
    expect((only(put)[1].body as typeof HELD).hosts[1]).toStrictEqual({
      remote: "git.example.com",
      web: "https://git.example.com",
      style: "gitea",
    });
  });

  it("adds and removes rows, and sends what is left", async () => {
    const { put } = await drawn();
    await press(host(), "Add host");
    change(field<HTMLInputElement>("Remote of host 3"), "gitlab.com");
    change(field<HTMLInputElement>("Web address of host 3"), "https://gitlab.com");
    change(field<HTMLSelectElement>("Server of host 3"), "gitlab");
    await press(host(), "Add path");
    change(field<HTMLInputElement>("Prefix of path 3"), "third_party");
    change(field<HTMLSelectElement>("Disclosure of path 3"), "no");
    await remove("Remove host 1");
    await remove("Remove path 1");
    await press(host(), "Save");
    await settle();
    const body = only(put)[1].body as typeof HELD;
    expect(body.hosts.map((each) => each.remote)).toEqual(["git.example.com", "gitlab.com"]);
    expect(body.paths).toStrictEqual([
      {
        prefix: "src/sonic-swss",
        remote: "github.com/sonic-net/sonic-swss",
        branch: "master",
        snippets: true,
      },
      { prefix: "third_party", disclosed_snippets: false },
    ]);
  });

  it("sends empty lists where every row was removed", async () => {
    const { put } = await drawn();
    await remove("Remove host 2");
    await remove("Remove host 1");
    await remove("Remove path 2");
    await remove("Remove path 1");
    expect(host().textContent).toContain("No hosts.");
    expect(host().textContent).toContain("No paths.");
    await press(host(), "Save");
    await settle();
    expect(only(put)[1].body).toStrictEqual({ hosts: [], paths: [] });
  });

  it("moves the settings and every code finding's links once a save lands, leaving nothing to save", async () => {
    const { invalidated } = await drawn();
    change(field<HTMLInputElement>("Branch of path 2"), "main");
    await press(host(), "Save");
    await settle();
    expect(invalidated()).toEqual(["code-finding", "repositories/sonic"]);
    expect(button(host(), "Save").disabled).toBe(true);
  });

  it("says what the server refused, and keeps what was typed", async () => {
    await drawn();
    vi.restoreAllMocks();
    serve((path) => (path === "/v1/products/{product}/repositories" ? { data: HELD } : undefined));
    answer("PUT", () => ({ status: 422 }));
    change(field<HTMLInputElement>("Web address of host 1"), "http://github.com");
    await press(host(), "Save");
    await settle();
    expect(host().textContent).toContain("The repository settings were not saved.");
    expect(field<HTMLInputElement>("Web address of host 1").value).toBe("http://github.com");
  });

  it("says where nothing is stated yet", async () => {
    await drawn(true, { hosts: [], paths: [] });
    expect(host().textContent).toContain("No hosts.");
    expect(host().textContent).toContain("No paths.");
  });

  it("says the settings could not be read", async () => {
    serve((path) =>
      path === "/v1/session/me"
        ? {
            data: { identity: "ana", name: "Ana", admin: true, kind: "person", reach: [] },
          }
        : undefined,
    );
    mount.render(
      screen(<Repositories />, "/products/sonic/repositories", "/products/:product/repositories"),
    );
    await settle();
    expect(host().textContent).toContain("The repository settings could not be read.");
  });
});

describe("a product's repository settings, for anybody else", () => {
  it("asks for nothing and offers no control", async () => {
    const { reads } = await drawn(false);
    expect(asked(reads)).not.toContain("/v1/products/{product}/repositories");
    expect(host().textContent).toContain("Administrators only.");
    expect(host().querySelector("input, select, button")).toBeNull();
  });
});
