// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The sections of the settings screen, in the order they are offered. Which
// section a setting belongs to is served with the setting; what a section is
// called and where its tab sits is the screen's.
export const SECTIONS = [
  ["deadlines", "Deadlines"],
  ["own", "Our products"],
  ["triage", "Triage"],
  ["disclosure", "Disclosure"],
  ["scanning", "Scanning"],
  ["signin", "Sign-in"],
  ["limits", "Limits"],
  ["outbound", "Outbound"],
] as const;

// Tabs that hold something other than settings, for administrators alone:
// their endpoints refuse anybody else.
export const ADMIN_TABS = [
  ["webhooks", "Webhooks"],
  ["suppliers", "Suppliers"],
] as const;

export type Tab = (typeof SECTIONS)[number][0] | (typeof ADMIN_TABS)[number][0];

// The tab an address names. An unknown or missing one is the first section,
// and an administrator's tab asked for by somebody else is too.
export function tabOf(asked: string | undefined, admin: boolean): Tab {
  if (SECTIONS.some(([key]) => key === asked)) return asked as Tab;
  if (admin && ADMIN_TABS.some(([key]) => key === asked)) return asked as Tab;
  return SECTIONS[0][0];
}

// What a tab says beside its name: how many of its settings differ from the
// shipped value, or how many it holds where none do. A value changed on a tab
// nobody opened is otherwise invisible.
export function tally(items: readonly { section: string; default?: boolean }[], section: string) {
  const here = items.filter((each) => each.section === section);
  const changed = here.filter((each) => !each.default).length;
  return changed > 0 ? `${changed} changed` : String(here.length);
}
