// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Sitting } from "../ui/Covering";
import { keyOf } from "./treeshape";

// The way down to one place, as the rows a reader sees.
//
// Three situations, and they are not one. A place the graph could be walked to
// carries the whole chain, the build first. A place whose consumer is recorded
// but whose route up is not — an inventory describing something under a
// component that nothing reaches from the root — is still one hop: this
// component under that consumer, which is what a decision is keyed on. Only a
// place with neither is unplaced, and only there does the screen say nothing
// recorded what pulls it in.
//
// Drawing the second as the third said something false about a record that had
// the answer, and drew it with the component's own name missing: the name was
// read off the end of a chain that was not there.

export type Step = { component: string; version?: string };

export type WayDown = {
  steps: Step[];
  // Rootless says the walk up from the first step reached nothing, so what is
  // above it is unknown rather than absent.
  rootless: boolean;
};

// The version is the one that ships here, which the chain carries at every
// step and a place with no chain does not carry at all. Handed in, so a way
// down of one hop names the same thing its siblings do rather than a bare
// name.
export function wayDown(place: Sitting, version?: string): WayDown {
  const chain = place.chain ?? [];
  if (chain.length > 0) {
    return {
      steps: chain.map((step) => ({
        component: step.component ?? "",
        version: step.version ?? undefined,
      })),
      rootless: false,
    };
  }
  const here: Step = { component: place.component ?? "", version: version || undefined };
  if (place.consumer) {
    return { steps: [{ component: place.consumer }, here], rootless: true };
  }
  return { steps: [here], rootless: true };
}

// The place the dependency tree opens from a finding: the place the graph
// could be walked to, whichever of them that is, as the query the tree takes.
//
// The tree opens along a chain, expanding each step. Handed a place with no
// route up, it has a name to land on and nothing to walk, so it opens at the
// root with the component nowhere in sight. Where no place has one, the
// component alone is the honest answer: the tree says what it can find.
export function intoTheTree(places: Sitting[]): string {
  const walked = places.find((place) => (place.chain ?? []).length > 0);
  const query = new URLSearchParams();
  if (!walked) {
    query.set("at", places[0]?.component ?? "");
    return query.toString();
  }
  const steps = wayDown(walked).steps;
  const last = steps[steps.length - 1];
  query.set("at", last?.component ?? "");
  // Each step as the tree's own identity for a row, not as a bare name: the
  // tree opens the set it is handed, and a name the build ships twice names
  // two rows there.
  query.set("path", steps.map((step) => keyOf(step)).join("\u001f"));
  if (last?.version) query.set("version", last.version);
  return query.toString();
}

// How many ways down the path shows before it is asked for the rest.
export const CHAINS = 6;

// What the control under the path does, in the words of what it adds: the
// rest of them while folded, and back to the first few once open. Absent where
// every way down already shows.
export function moreWays(total: number, open: boolean): string | undefined {
  if (total <= CHAINS) return undefined;
  return open ? "Show fewer" : `Show ${total - CHAINS} more`;
}
