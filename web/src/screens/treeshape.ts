// A tree row, and the build it is drawn for.
//
// A file of their own so the shapes the tree is built on are stated once,
// separately from the screen that draws them.

export type At = { product: string; stream: string; variant: string };
export type Node = {
  component: string;
  version: string;
  // The count open against this component itself, and the count open in
  // everything under it. A container holds none of its own, so the second is
  // the number that says whether a branch is worth opening.
  findings: number;
  beneath: number;
  // The parts of that number. Five thousand beneath a node says nothing
  // about whether any of it matters, which is exactly what somebody deciding
  // where to descend is asking.
  beneath_by_severity?: Record<string, number>;
  children: number;
  // The field that tells two components of one name and one version apart. A
  // build ships one twice, and the endpoint that answers about a component
  // refuses a name that means two things — so this travels with the name.
  ecosystem?: string;
};

// A row's own identity, as a string.
//
// The name alone is not it. A build ships one name at more than one version,
// and a few at one version as two components that only the kind of package
// tells apart — and the endpoint that answers about a component refuses a
// name that means two things, rightly, since the two are two components. So
// the open set, the widened set and the map of what sits under each node are
// all keyed on this rather than on the name: keyed on the name, a component
// the build ships twice could never be opened at all, because the request
// asking for its children carried no version to disambiguate it.
const APART = "\u001e";

export function keyOf(node: { component: string; version?: string; ecosystem?: string }): string {
  return [node.component, node.version ?? "", node.ecosystem ?? ""].join(APART);
}

// partsOf reads a key back into the three things a request needs.
export function partsOf(key: string): { component: string; version: string; ecosystem: string } {
  const [component = "", version = "", ecosystem = ""] = key.split(APART);
  return { component, version, ecosystem };
}
