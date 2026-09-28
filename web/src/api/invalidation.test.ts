// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";

// The keys each act invalidates, recorded by a query client that does nothing
// else. The hooks need nothing from React but the client, so the client is
// all that is replaced.
const invalidated: string[][] = [];

vi.mock("@tanstack/react-query", async (actual) => ({
  ...(await actual<typeof import("@tanstack/react-query")>()),
  useQueryClient: () => ({
    invalidateQueries: ({ queryKey }: { queryKey: string[] }) => {
      invalidated.push(queryKey);
      return Promise.resolve();
    },
  }),
}));

const { useAfterClaim } = await import("./claims");
const { useAfterAdvisory } = await import("./advisories");
const { useAfterReport } = await import("./intake");

beforeEach(() => {
  invalidated.length = 0;
});

// What one act invalidates, as a sorted list of key prefixes.
function after(hook: () => () => void): string[] {
  hook()();
  return invalidated.map((key) => key.join("/")).sort();
}

// A key dropped from one of these sets leaves a screen showing what the act
// changed as it stood before. For a claim that is an approval a revision took
// back still drawn as standing, which is the state the second-person control
// exists to make visible.
describe("what an act invalidates", () => {
  it("a change to a claim reaches the queue, its decisions, its findings and its own blocks", () => {
    expect(after(useAfterClaim)).toEqual(
      [
        "claim",
        "comments",
        "decided",
        "decision",
        "finding",
        "findings",
        "home",
        "my-claims",
        "queue",
      ].sort(),
    );
  });

  it("a change to an advisory reaches the list, the advisory, its document and what went out", () => {
    expect(after(useAfterAdvisory)).toEqual(
      ["advisories", "advisory", "advisory-document", "advisory-issuances"].sort(),
    );
  });

  it("a change to a report reaches the reports, the rulings and the duplicates", () => {
    expect(after(useAfterReport)).toEqual(
      ["duplicates", "recorded-report", "report", "reports", "rulings"].sort(),
    );
  });
});
