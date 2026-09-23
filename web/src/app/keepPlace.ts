// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect } from "react";
import { useLocation, useNavigationType } from "react-router-dom";
import { markPlace, placeOf } from "./place";

// Remember where somebody was on this page, and put them back on the way in.
//
// Restored only on the way back. A list opened fresh opens at the top,
// which is what a fresh list is; one arrived at by pressing back is one
// somebody was already reading. React Router says which kind of arrival it
// was, and using it is the difference between restoring a place and jumping
// somebody down a list they have not read.
//
// ready says the rows are on the page. Scrolling before they are drawn scrolls
// a page that is a few hundred pixels tall, and the browser clamps it to the
// bottom — so the restore lands somewhere arbitrary and looks like a bug in
// the list rather than in this.
export function useKeepPlace(ready: boolean) {
  const { pathname, search } = useLocation();
  const how = useNavigationType();
  const address = pathname + search;

  useEffect(() => {
    if (!ready || how !== "POP") return;
    const y = placeOf(address);
    if (y <= 0) return;
    // After paint, because the rows have just been committed and the page is
    // its full height only once they are laid out.
    const at = requestAnimationFrame(() => window.scrollTo({ top: y }));
    return () => cancelAnimationFrame(at);
  }, [address, how, ready]);

  useEffect(() => {
    // Written as somebody scrolls rather than as they leave: a route change
    // unmounts this, and an unmount is too late to read the position the
    // browser has already moved. Passive, because nothing here decides
    // whether the scroll happens.
    function moved() {
      markPlace(address, window.scrollY);
    }
    window.addEventListener("scroll", moved, { passive: true });
    return () => window.removeEventListener("scroll", moved);
  }, [address]);
}
