// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef } from "react";
import { useLocation, useNavigationType } from "react-router-dom";

// A new screen starts at its own top. Picking an entry from the foot of the
// rail otherwise leaves the document where it was, so the screen that arrives
// is already scrolled past its heading and its controls, which reads as the
// wrong screen rather than as a scroll position.
//
// Not on Back or Forward. A list puts somebody back where they were on it, and
// a scroll to the top here, before the list's rows arrive, is recorded as where
// they were.
//
// Only on a change of path. How a screen was reached is read through a ref, so
// a filter ticked on a list somebody came Back to, which is a push on the same
// path, leaves the page where it is.
export function useTopOnArrival(): void {
  const { pathname } = useLocation();
  const navigation = useNavigationType();
  const how = useRef(navigation);
  useEffect(() => {
    how.current = navigation;
  });
  useEffect(() => {
    if (how.current !== "POP") window.scrollTo({ top: 0 });
  }, [pathname]);
}
