// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { intoTheTree, wayDown } from "./waydown";
import type { Sitting } from "../ui/Covering";

// The two separators the tree's path parameter uses, written as escapes: a
// file holding the bytes themselves reads as binary to every text tool, which
// skips it and says nothing. One between steps, and one inside a step, which
// carries the component, the version and the kind of package — a name the
// build ships twice names two rows in the tree.
const SEPARATOR = "\u001f";
const WITHIN = "\u001e";

const place = (at: Partial<Sitting>): Sitting =>
  ({ place: "p", component: "curl", ...at }) as Sitting;

describe("the way down to a place", () => {
  it("is the whole chain where the graph could be walked", () => {
    const drawn = wayDown(
      place({
        chain: [{ component: "sonic-broadcom" }, { component: "curl", version: "8.14.1" }],
      }),
    );
    expect(drawn.steps.map((step) => step.component)).toEqual(["sonic-broadcom", "curl"]);
    expect(drawn.rootless).toBe(false);
  });

  // The record names what pulls the component in even where nothing places the
  // consumer itself, so the answer is one hop rather than no answer.
  it("is one hop where the consumer is recorded and the route up is not", () => {
    const drawn = wayDown(place({ component: "curl", consumer: "opennsl-modules" }));
    expect(drawn.steps.map((step) => step.component)).toEqual(["opennsl-modules", "curl"]);
    expect(drawn.rootless).toBe(true);
  });

  // The component's own name comes off the place rather than off the end of a
  // chain that is not there, which is what drew a row with no name in it.
  it("carries the version that ships into a way down of one hop", () => {
    const drawn = wayDown(place({ component: "curl", consumer: "opennsl-modules" }), "8.14.1");
    expect(drawn.steps[1]).toEqual({ component: "curl", version: "8.14.1" });
  });

  it("names the component where nothing placed it at all", () => {
    const drawn = wayDown(place({ component: "curl" }));
    expect(drawn.steps).toEqual([{ component: "curl" }]);
    expect(drawn.rootless).toBe(true);
  });
});

describe("opening the dependency tree from a finding", () => {
  it("walks from a place that has a route up rather than from the first", () => {
    const query = new URLSearchParams(
      intoTheTree([
        place({ component: "curl", consumer: "opennsl-modules" }),
        place({
          component: "curl",
          chain: [{ component: "sonic-broadcom" }, { component: "curl", version: "8.14.1" }],
        }),
      ]),
    );
    expect(query.get("at")).toBe("curl");
    // Each step carries what tells it from another row of the same name, so
    // the tree opens the step it was given rather than every component
    // sharing its name.
    expect(query.get("path")).toBe(
      `sonic-broadcom${WITHIN}${WITHIN}${SEPARATOR}curl${WITHIN}8.14.1${WITHIN}`,
    );
    expect(query.get("version")).toBe("8.14.1");
  });

  it("sends the component alone where no place has one", () => {
    const query = new URLSearchParams(
      intoTheTree([place({ component: "curl", consumer: "opennsl-modules" })]),
    );
    expect(query.get("at")).toBe("curl");
    expect(query.get("path")).toBeNull();
  });
});
