// What a tree row is, and which build it is drawn for.
//
// Their own file because the tree and the component screen both read them and
// neither owns the other.

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

// What is known about one component, over the graph it sits in.
//
// Walking the graph and asking about a node are two questions, and the second
// took a third of the page while the first was on screen. It is drawn over
// rather than beside for the same reason: a panel that stands open costs the
// width whether or not anybody asked.

// Something over the screen rather than beside it.
//
// **A panel that stands open costs the width whether or not anybody asked.**
// This one took a third of the page for one component's dependents and trend,
// while the tree — which is what the screen is — drew indented rows into what
// was left, so a name six levels down wrapped and the counts beside it stopped
// lining up. Asked for, it takes the width it needs and gives it back.
//
// Closed by the button, by Escape, and by clicking away from it: a thing over
// the page that only one gesture dismisses is a thing somebody gets stuck
// behind.
