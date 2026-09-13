// What a tree row is, and which build it is drawn for.
//
// A file of their own so the shapes the tree is built on are stated once,
// separately from the screen that draws them.

export type At = { product: string; stream: string; variant: string };
export type Node = {
  component: string;
  version: string;
  // What is open against this component itself, and what is open in everything
  // under it. A container holds none of its own, so the second is the number
  // that says whether a branch is worth opening.
  findings: number;
  beneath: number;
  // What that number is made of. Five thousand beneath a node says nothing
  // about whether any of it matters, which is exactly what somebody deciding
  // where to descend is asking.
  beneath_by_severity?: Record<string, number>;
  children: number;
  // What tells two components of one name and one version apart. A build
  // ships one twice, and the endpoint that answers about a component refuses
  // a name that means two things — so this travels with the name.
  ecosystem?: string;
};
