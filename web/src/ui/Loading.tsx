// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The placeholder a screen shows while it is waiting.
//
// One component rather than a sentence typed out on every screen. Nothing
// about it is clever: the point is that a change to how waiting looks reaches
// every screen, and that the one thing this has to get right is announced
// rather than left to a reader who cannot see the page.
//
// `inline` is for waiting inside a line of text rather than in place of a
// block, which is the one real variation between screens.
//
// A mark that moves sits beside the word. The word alone is one line of faint
// text on a page that is otherwise still, and a page that is still reads as a
// page that has stopped; the eye finds movement where it does not find a
// sentence. The mark is drawn by the stylesheet and carries no text of its
// own, so a screen reader hears the word once.
export function Loading({ inline = false }: { inline?: boolean }) {
  const said = "Loading…";
  // Announced politely: a reader using a screen reader otherwise hears nothing
  // between asking and arriving, which is indistinguishable from a page that
  // did nothing.
  if (inline) {
    return (
      <span className="hint loading" role="status">
        {said}
      </span>
    );
  }
  return (
    <p className="hint loading" role="status">
      {said}
    </p>
  );
}
