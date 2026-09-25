// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { components } from "../api/schema";

// A section the server files a setting under.
type Section = components["schemas"]["SettingBody"]["section"];

// What each section is called, in the order its tab is offered. Keyed on the
// server's own list, so a section the server adds is a type error here until
// it has a name, rather than settings served under a tab nobody draws.
const NAMES = {
  deadlines: "Deadlines",
  own: "Our products",
  triage: "Triage",
  disclosure: "Disclosure",
  scanning: "Scanning",
  signin: "Sign-in",
  limits: "Limits",
  outbound: "Outbound",
} as const satisfies Record<Section, string>;

export const SECTIONS = Object.entries(NAMES) as [Section, string][];

// Tabs that hold something other than settings, for administrators alone:
// their endpoints refuse anybody else.
export const ADMIN_TABS = [
  ["webhooks", "Webhooks"],
  ["suppliers", "Suppliers"],
] as const;

export type Tab = Section | (typeof ADMIN_TABS)[number][0];

// The tab an address names. An unknown or missing one is the first section,
// and an administrator's tab asked for by somebody else is too.
export function tabOf(asked: string | undefined, admin: boolean): Tab {
  if (SECTIONS.some(([key]) => key === asked)) return asked as Tab;
  if (admin && ADMIN_TABS.some(([key]) => key === asked)) return asked as Tab;
  return SECTIONS[0]?.[0] ?? "deadlines";
}

// What a tab says beside its name: how many of its settings hold a value
// somebody stored, or how many it holds where none do. A value set on a tab
// nobody opened is otherwise invisible. Stored rather than differing: a value
// set back to what ships still counts, and reads as set.
export function tally(items: readonly { section: string; default?: boolean }[], section: string) {
  const here = items.filter((each) => each.section === section);
  const set = here.filter((each) => !each.default).length;
  return set > 0 ? `${set} set` : String(here.length);
}
