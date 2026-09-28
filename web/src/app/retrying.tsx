// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { lazy, type ComponentType, type LazyExoticComponent } from "react";

// How many times somebody has asked for a failed screen again.
let asked = 0;

// askAgain is Try again, pressed: every screen whose load failed before now is
// loaded afresh the next time it is drawn.
export function askAgain() {
  asked++;
}

// A screen loaded when it is first drawn, which can be asked for again after
// the load failed.
//
// React holds a lazy component's rejection for good: a chunk that failed to
// arrive once, on a flaky connection, fails every later render the same way
// until the page is reloaded. So a failed load is marked, and once somebody
// asks again the next render is handed a new lazy component that loads again.
//
// Only once somebody asks. Replaced as soon as it failed, the render React
// makes after a rejection would load again at once, and a chunk that cannot
// arrive would be asked for without end.
export function retrying<P extends object>(
  load: () => Promise<ComponentType<P>>,
): ComponentType<P> {
  const held: {
    now: LazyExoticComponent<ComponentType<P>>;
    failed: boolean;
    at: number;
  } = { now: lazy(attempt), failed: false, at: asked };
  function attempt(): Promise<{ default: ComponentType<P> }> {
    return load().then(
      (screen) => ({ default: screen }),
      (error: unknown) => {
        held.failed = true;
        throw error;
      },
    );
  }
  function current(): LazyExoticComponent<ComponentType<P>> {
    if (held.failed && held.at !== asked) {
      held.failed = false;
      held.at = asked;
      held.now = lazy(attempt);
    }
    return held.now;
  }
  return function Screen(props: P) {
    const Loaded = current();
    return <Loaded {...props} />;
  };
}
