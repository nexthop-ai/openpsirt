// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { MouseEvent } from "react";
import { useNavigate, type To } from "react-router-dom";

// What inside a row answers a click itself. A click on one of these is that
// control's, and the row leaves it alone: the checkbox picks, the button acts,
// and a link goes where it says, including a second link in the same row.
const OWN =
  "a, button, input, select, textarea, label, summary, [role='button'], [contenteditable]";

// What makes a whole cell its control's. A click that misses a checkbox by its
// cell's padding is aimed at the checkbox, and opening the row on it throws
// away whatever has been ticked or typed on the screen being left. A cell
// holding a link or a button opens the row: the link is the row's own target,
// and a button that is missed has done nothing to lose.
const FIELD = "input, select, textarea";

// opensRow is whether a click on a row should open the row's target.
//
// Only a plain primary click on the row itself. A modified or middle click is
// the browser's, and the row's link is there for it. A click in a cell holding
// a form field is the field's. A click that ends a drag across text is
// somebody selecting the text to copy it.
function opensRow(event: MouseEvent<HTMLElement>): boolean {
  if (event.defaultPrevented || event.button !== 0) return false;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return false;
  const own = event.target instanceof Element ? event.target.closest(OWN) : null;
  if (own && event.currentTarget.contains(own)) return false;
  const cell = event.target instanceof Element ? event.target.closest("td, th") : null;
  if (cell && event.currentTarget.contains(cell) && cell.querySelector(FIELD)) return false;
  return (window.getSelection()?.toString() ?? "") === "";
}

// useRowOpener is the click handler for a row with one target: a click
// anywhere on the row that is not one of its own controls opens the target.
//
// The row keeps the target as a real link as well. A keyboard reaches a link
// and not a row, and a middle click opens a link in a new tab.
export function useRowOpener(): (to: To) => (event: MouseEvent<HTMLElement>) => void {
  const navigate = useNavigate();
  return (to) => (event) => {
    if (opensRow(event)) navigate(to);
  };
}
