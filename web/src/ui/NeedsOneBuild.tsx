// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { askForScope } from "../app/scope";
import { Empty } from "./Empty";

// What a list or figure narrowed to at or under a component draws where no one
// build is picked: the walk is over one build's edges, so it asks for one and
// reads nothing. `andProduct` where no product is picked either.
export function NeedsOneBuild({ andProduct = false }: { andProduct?: boolean }) {
  return (
    <Empty
      title="This needs one build."
      detail={`At or under a component is read on one build. Pick ${
        andProduct ? "a product, a branch" : "a branch"
      } and a variant.`}
    >
      <button type="button" className="btn" onClick={askForScope}>
        Pick a build
      </button>
    </Empty>
  );
}
