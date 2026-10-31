// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The groups of the rail that are folded away.
//
// The rail unfolded is taller than the window on most laptops. A scroll
// region of its own puts a second scrollbar down the middle of the screen,
// and scrolling with the page leaves the menu far above somebody reading the
// foot of a findings list, so it folds. "Manage" is shut to begin with: it is
// where somebody goes occasionally to grant a role or change a setting, and
// folding it shortens the rail by its entries.
//
// Kept in the browser, per person, the same rule as the look and saved
// filters: it changes what one person sees and nothing anybody else is shown.

const KEPT = "openpsirt.rail";
const SHUT_TO_BEGIN_WITH = ["manage"];

export function folded(): Set<string> {
  try {
    const kept = window.localStorage.getItem(KEPT);
    if (kept === null) return new Set(SHUT_TO_BEGIN_WITH);
    const names = JSON.parse(kept) as unknown;
    if (Array.isArray(names)) return new Set(names.filter((n) => typeof n === "string"));
  } catch {
    // A browser that refuses storage gets the shipped arrangement.
  }
  return new Set(SHUT_TO_BEGIN_WITH);
}

export function fold(shut: Set<string>) {
  try {
    window.localStorage.setItem(KEPT, JSON.stringify([...shut]));
  } catch {
    // The fold still applies for this page.
  }
}
