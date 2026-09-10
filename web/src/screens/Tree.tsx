import { ROLLED } from "../ui/severities";
import { notACredential } from "../ui/noautofill";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Loading } from "../ui/Loading";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Pace } from "../ui/Charts";
import { sharedVersion } from "../ui/versions";
import { Crumbs } from "../ui/Crumbs";
import { Icon } from "../ui/Icons";
import { useWho } from "../app/session";

type At = { product: string; stream: string; variant: string };
type Node = {
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

// What is beneath a node, worst first, as a short strip. Only the bands that
// are there: a row of zeros is noise on a screen whose whole job is saying
// which branch is worth opening.
function Strip({ by }: { by?: Record<string, number> }) {
  const there = ROLLED.filter((band) => (by ?? {})[band]);
  // Drawn empty rather than left out: the strip is a column, and a row that
  // omits it is a row whose count sits where every other row's bands are.
  if (there.length === 0) return <span className="strip" />;
  return (
    <span className="strip" aria-hidden={false}>
      {there.map((band) => (
        <span key={band} className={`band ${band}`} title={`${(by ?? {})[band]} ${band}`}>
          {(by ?? {})[band]}
        </span>
      ))}
    </span>
  );
}

// How many children of one node are drawn before it offers the rest.
//
// A level is shown whole. An inventory that describes a build honestly has
// tens of things at a level, not hundreds, and truncating those hid entries
// for no reason — the reader could not tell a level they had all of from one
// they had five of, which is worse than a long list.
//
// The cap is still here, high, for the inventory that is not honest: a real
// image has been seen with 5,270 components directly under its root, and
// drawing five thousand rows inside an expandable tree is a page that stops
// responding rather than a page that is long. Past this the node says how many
// there are and offers all of them.
const CHILDREN = 400;

// The version every component at one level carries, where they all carry the
// same one, and empty otherwise.
//
// A count past this is emphasised, so the branch worth descending is visible
// without reading every number on the way down.
const HOT = 500;

const aroundKey = (at: At, component: string, version = "", ecosystem = "") =>
  ["tree-around", at, component, version, ecosystem] as const;

// A name is not always enough: a build ships some libraries at several
// versions, and a finding arriving here says which one it meant — and a few
// it ships at one version as two components, which only the kind of package
// tells apart.
const fetchAround =
  (at: At, component: string, version = "", ecosystem = "") =>
  async () =>
    unwrap(
      await api.GET(
        "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/around",
        {
          params: {
            path: { ...at, component },
            query: {
              ...(version ? { version } : {}),
              ...(ecosystem ? { ecosystem } : {}),
            },
          },
        },
      ),
    );

// The dependency graph, drawn as a tree and expanded a node at a time.
//
// Not a full render: a real image holds thousands of components and tens of
// thousands of edges, which neither draws nor reads. What makes opening nodes
// worth doing is that every one of them carries how many findings are open
// beneath it, so descending follows the findings rather than being
// exploration.
//
// Which component is selected lives in the URL, so a link carries it.
export function Tree() {
  const { product = "" } = useParams();
  const who = useWho();
  // Somebody who holds no reading on the product gets the tree seen upward
  // instead. Descended from the root, this tree is the inventory of what the
  // product contains — the breadth they were deliberately not granted — so it
  // is not drawn for them with rows hidden: a container's count would still
  // say how much sits under it, and opening one is the question they may not
  // ask.
  if (who.isPending) return <Loading />;
  if (who.data && !who.data.reach.some((each) => each.product === product)) return <Yours />;
  return <Whole />;
}

// The chains somebody's own findings sit on.
//
// **The part that makes a finding judgeable.** The chain upward says what
// pulled the thing in, which is what somebody deciding needs, and every node
// on it sits above something they were already given. The counts are theirs:
// a node says how much of their own work hangs beneath it, never how much the
// build holds there.
function Yours() {
  const { product = "", stream = "", variant = "" } = useParams();
  const at = useMemo(() => ({ product, stream, variant }), [product, stream, variant]);
  const mine = useQuery({
    queryKey: ["tree-mine", at],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/components/mine",
          { params: { path: at } },
        ),
      ),
  });
  const rows = mine.data?.items ?? [];
  const placed = rows.filter((row) => row.placed);
  const loose = rows.filter((row) => !row.placed);

  return (
    <div>
      <Crumbs product={product} stream={stream} variant={variant} />
      <div className="screen-head">
        <h2>Dependency paths</h2>
        <p>
          {product} · {stream} · {variant}
        </p>
      </div>
      <div className="card">
        <p className="reading" style={{ marginBottom: 10 }}>
          The build&rsquo;s dependency graph seen upward from your own findings: from each component
          you hold one on, up to the build itself. The numbers are yours — what hangs beneath a node
          is your work, not what the build holds there. You read this product only through what you
          have been handed, so descending a node is not offered.
        </p>
        {mine.isPending && <Loading />}
        {mine.isError && <Failed error={mine.error} what="Your own work here could not be read." />}
        {!mine.isPending && !mine.isError && rows.length === 0 && (
          <Empty
            title="Nothing here is yours."
            detail="This shows the chains your own findings sit on. Nothing in this build has been handed to you or to a team you are on."
          />
        )}
        {placed.length > 0 && (
          <ul className="branchlist">
            {placed.map((row, i) => (
              <li
                key={`${row.component}@${row.version}@${i}`}
                className="branch"
                style={{ paddingLeft: 10 + (row.depth ?? 0) * 18 }}
              >
                <span className="id">{row.component}</span>{" "}
                <span className="hint">{row.version}</span>
                {/* Both numbers open the list they count. A node saying
                    "5,650 beneath · 0 here" and going nowhere is the shape of
                    a figure nobody can act on from where they read it. */}
                <span className="counts">
                  {(row.findings ?? 0) > 0 && (
                    <Link
                      className="n"
                      title="Your own open issues on this component"
                      to={onComponent(at, row.component)}
                    >
                      {row.findings} here
                    </Link>
                  )}
                  <Link
                    className="n hint"
                    title="Your own open issues at or under it"
                    to={beneathComponent(at, row.component)}
                  >
                    {row.beneath} beneath
                  </Link>
                </span>
              </li>
            ))}
          </ul>
        )}
        {loose.length > 0 && (
          <>
            <h4 style={{ margin: "14px 0 4px" }}>Placed nowhere</h4>
            <p className="hint" style={{ marginTop: 0 }}>
              The inventory listed these and said nothing about what pulls them in, so there is no
              chain to show.
            </p>
            <ul className="branchlist">
              {loose.map((row, i) => (
                <li key={`${row.component}@${i}`} className="branch" style={{ paddingLeft: 10 }}>
                  <span className="id">{row.component}</span>{" "}
                  <span className="hint">{row.version}</span>
                  <span className="counts">
                    <Link className="n" to={onComponent(at, row.component)}>
                      {row.findings} here
                    </Link>
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}
        {mine.data && mine.data.complete === false && (
          <p className="alert" style={{ marginTop: 10 }}>
            <strong>Not all of it.</strong>
            <span>
              You hold work on more components than this draws, so the counts under-report. The
              findings list carries all of it.
            </span>
          </p>
        )}
      </div>
    </div>
  );
}

function Whole() {
  const { product = "", stream = "", variant = "" } = useParams();
  const at = useMemo(() => ({ product, stream, variant }), [product, stream, variant]);
  const [params, setParams] = useSearchParams();
  const focus = params.get("at") ?? "";

  const [opened, setOpened] = useState<Set<string>>(() => new Set());
  const [widened, setWidened] = useState<Set<string>>(() => new Set());
  const term = params.get("q") ?? "";
  const [typed, setTyped] = useState(term);

  const top = useQuery({
    queryKey: ["tree-top", at, term],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/components", {
          params: { path: at, query: term ? { q: term } : {} },
        }),
      ),
  });

  const root = (top.data?.root ?? null) as Node | null;
  const rootName = root?.component ?? "";
  const searching = term !== "";
  const found = (top.data?.items ?? []) as Node[];

  function search(next: string) {
    const now = new URLSearchParams(params);
    if (next.trim()) now.set("q", next.trim());
    else now.delete("q");
    setParams(now);
  }

  // The root starts open, because a tree whose only visible row is the thing
  // you already knew you were looking at has told you nothing. Closing it
  // afterwards sticks: this runs once per build, not once per render.
  //
  // Arriving from a finding brings the chain along, and every step of it is
  // opened so the component is on screen under the parents that pull it in,
  // rather than the reader being left at the root to find it again.
  const path = params.get("path") ?? "";
  useEffect(() => {
    if (!rootName) return;
    const steps = path.split("\u001f").filter(Boolean);
    setOpened((prev) => {
      const next = new Set(prev);
      next.add(rootName);
      for (const step of steps) next.add(step);
      return next;
    });
  }, [rootName, path]);

  // The components on the way down to the one being arrived at.
  //
  // A level past the cap draws its first few hundred and offers the rest, and
  // the step on the path has to be drawn whether or not it is among them —
  // otherwise arriving from a finding lands on a tree that does not contain
  // the component it was opened for. Each of those rows is kept individually
  // rather than by drawing the whole level: the step here is `host-image`,
  // whose level is 5,157 rows, and widening it renders every one of them.
  const onPath = useMemo(() => new Set(path.split("\u001f").filter(Boolean)), [path]);

  // Children are read for each node the reader has opened. The root's own are
  // already in hand from the query above, so it is not asked for twice.
  const wanted = useMemo(
    () => [...opened].filter((name) => name !== "" && name !== rootName),
    [opened, rootName],
  );
  const branches = useQueries({
    queries: wanted.map((name) => ({
      queryKey: aroundKey(at, name),
      queryFn: fetchAround(at, name),
    })),
  });

  // What is selected. The key matches the one above, so selecting a node that
  // is already open costs nothing.
  const version = params.get("version") ?? "";
  const ecosystem = params.get("ecosystem") ?? "";
  const selected = useQuery({
    queryKey: aroundKey(at, focus, version, ecosystem),
    queryFn: fetchAround(at, focus, version, ecosystem),
    enabled: focus !== "",
  });

  const below = useMemo(() => {
    const map = new Map<string, Node[] | undefined>();
    if (rootName) map.set(rootName, (top.data?.items ?? []) as Node[]);
    wanted.forEach((name, i) => {
      const answer = branches[i]?.data;
      map.set(name, answer ? ((answer.below ?? []) as Node[]) : undefined);
    });
    return map;
  }, [rootName, top.data, wanted, branches]);

  function toggle(name: string) {
    setOpened((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  // Selecting also opens, because the question "what is under this" is the one
  // being asked by clicking it — and clicking the row you are already on is
  // the second half of that pair, which can only mean close it again. Without
  // that, the name opened and never closed: the triangle beside it toggled and
  // the larger target, the one people actually hit, did not.
  //
  // A node with nothing under it is only selected, never opened. Opening one
  // asked the server for children it does not have, and the row drew "Loading"
  // underneath until the empty answer arrived and took it away again — a
  // flicker under a leaf, which is what it looked like.
  // The version travels with the name. A build that ships one name as two
  // components refuses to answer about "that name" — rightly, since the two
  // are two components — and the tree knows which one was clicked, so asking
  // without it turned every such component into one nobody could look at.
  function select(name: string, children = 0, version = "", ecosystem = "") {
    setParams(
      name
        ? {
            at: name,
            ...(version ? { version } : {}),
            ...(ecosystem ? { ecosystem } : {}),
          }
        : {},
    );
    if (!name || children === 0) return;
    setOpened((prev) => {
      const next = new Set(prev);
      if (prev.has(name) && name === focus) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  return (
    <div>
      <Crumbs product={product} stream={stream} variant={variant} />
      <div className="screen-head">
        <h2>Dependencies</h2>
        <p>
          {product} · {stream} · {variant} — {(top.data?.components ?? 0).toLocaleString()}{" "}
          components, {(top.data?.edges ?? 0).toLocaleString()} edges
        </p>
      </div>

      {/* Searching is the way in, and browsing is for answering "what else is
          under this" once somebody is already somewhere. Eight thousand
          components under a root with five thousand children is not a graph
          anybody reaches the middle of by opening nodes. */}
      <div className="treehead">
        <form
          className="searchbox"
          onSubmit={(event) => {
            event.preventDefault();
            search(typed);
          }}
        >
          <Icon name="search" />
          <input
            {...notACredential}
            type="text"
            value={typed}
            aria-label="Find a component"
            placeholder="Find a component — openssl, linux, python…"
            onChange={(event) => setTyped(event.target.value)}
          />
        </form>
        {searching && (
          <button
            type="button"
            className="linkish"
            onClick={() => {
              setTyped("");
              search("");
            }}
          >
            Back to the tree
          </button>
        )}
        <span className="found">
          counts are distinct issues, cumulative: what is open beneath a node as well as on it
        </span>
      </div>

      <div className="wholewidth">
        <div>
          <div className="card">
            {top.isPending && <Loading />}
            {top.isError && (
              <Failed error={top.error} what="The build's contents could not be read." />
            )}
            {!searching && !top.isPending && !top.isError && !root && (
              <Empty
                title="This build has no root."
                detail="Nothing has been scanned here, or the inventory described no component that everything else descends from."
              />
            )}
            {searching &&
              !top.isPending &&
              !top.isError &&
              (found.length === 0 ? (
                <Empty
                  title={`Nothing here is called "${term}".`}
                  detail="Matched on part of a name, ignoring case. A component that is in the inventory but not in this build will not appear."
                />
              ) : (
                <Matches found={found} focus={focus} onSelect={select} />
              ))}
            {!searching && root && (
              <Branches
                root={root}
                below={below}
                opened={opened}
                widened={widened}
                onPath={onPath}
                focus={focus}
                onToggle={toggle}
                onSelect={select}
                onWiden={(name) => setWidened((prev) => new Set(prev).add(name))}
              />
            )}
            <p className="hint" style={{ margin: "12px 0 0" }}>
              {searching
                ? "Matches anywhere in the build, most findings first. Selecting one shows what pulls it in."
                : "Children load when a node is opened. The count on a node is the distinct issues open in everything under it, which is a smaller number than the findings list shows — that list has a row per issue and component, and one issue can sit in several."}
            </p>
          </div>
        </div>
      </div>

      {/* What sits around one component, over the tree rather than beside it.
          Beside it, the panel took a third of the width for something nobody
          had asked for yet, and the tree — which is the screen — was left
          drawing indented rows into what was left, so a name at depth six
          wrapped. Asked for, it takes the width it needs and gives it back. */}
      {focus !== "" && (
        <Over onClose={() => select("")}>
          <Pane
            at={at}
            focus={focus}
            rootName={rootName}
            above={(selected.data?.above ?? []) as Node[]}
            belowCount={(selected.data?.below ?? []).length}
            node={findNode(focus, root, below)}
            pending={selected.isPending}
            error={selected.isError ? selected.error : null}
            version={version}
            ecosystem={ecosystem}
          />
        </Over>
      )}
    </div>
  );
}

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
function Over({ children, onClose }: { children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [onClose]);
  return (
    <div className="over" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="overbox" onClick={(event) => event.stopPropagation()}>
        <button type="button" className="overshut" aria-label="Close" onClick={onClose}>
          ×
        </button>
        {children}
      </div>
    </div>
  );
}

// The node a name refers to, wherever it has already been read. The tree holds
// every answer the pane needs except the count of what is under a component
// nothing has opened yet, which is what the pane's own query is for.
function findNode(
  name: string,
  root: Node | null,
  below: Map<string, Node[] | undefined>,
): Node | null {
  if (!name) return null;
  if (root && root.component === name) return root;
  for (const kids of below.values()) {
    const hit = kids?.find((k) => k.component === name);
    if (hit) return hit;
  }
  return null;
}

// A search answers with a set of components rather than a position, so it is
// drawn as a list and not as a tree with one branch. Selecting one moves the
// pane to it, which is where "what pulls this in" is answered.
function Matches({
  found,
  focus,
  onSelect,
}: {
  found: Node[];
  focus: string;
  onSelect: (name: string, children?: number, version?: string, ecosystem?: string) => void;
}) {
  return (
    <div className="tree">
      {found.map((node, i) => (
        <div
          key={`${node.component}\u0000${node.version}\u0000${i}`}
          className={`node openable${node.component === focus ? " here" : ""}`}
        >
          <span className="rule">·</span>
          <button
            type="button"
            className="id"
            onClick={() => onSelect(node.component, node.children, node.version, node.ecosystem)}
          >
            {node.component}
          </button>
          <span className="ver">{node.version}</span>
          <Strip by={node.beneath_by_severity} />
          <span
            className={`count${node.beneath > HOT ? " hot" : node.beneath === 0 ? " none" : ""}`}
            title={`${node.beneath.toLocaleString()} distinct issues open beneath this`}
          >
            {node.beneath.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

// The findings list narrowed to one component, and to everything at or under
// it. Built here so a node's number and the screen it opens ask the same
// question — "beneath" is the tree's own walk, which is why the list has a
// filter for it rather than a name match.
function onComponent(at: At, component: string | undefined): string {
  return `${buildPath(at)}/findings?component=${encodeURIComponent(component ?? "")}`;
}

function beneathComponent(at: At, component: string | undefined): string {
  return `${buildPath(at)}/findings?beneath=${encodeURIComponent(component ?? "")}`;
}

function buildPath(at: At): string {
  return (
    `/products/${encodeURIComponent(at.product)}` +
    `/streams/${encodeURIComponent(at.stream)}` +
    `/variants/${encodeURIComponent(at.variant)}`
  );
}

// One flat list of indented rows rather than nested lists, so the rule down the
// left stays a straight line whatever a branch does.
function Branches({
  root,
  below,
  opened,
  widened,
  onPath,
  focus,
  onToggle,
  onSelect,
  onWiden,
}: {
  root: Node;
  below: Map<string, Node[] | undefined>;
  opened: Set<string>;
  widened: Set<string>;
  onPath: Set<string>;
  focus: string;
  onToggle: (name: string) => void;
  onSelect: (name: string, children?: number, version?: string, ecosystem?: string) => void;
  onWiden: (name: string) => void;
}) {
  const rows: React.ReactNode[] = [];
  // A component already drawn higher up is marked rather than expanded again.
  // Without this the same library is redrawn under every parent that pulls it
  // in, and a graph with any sharing at all never finishes.
  const seen = new Set<string>();

  // sharedHere is the version every versioned component at this node's own
  // level carries, where they all carry one. This row leaves it out; the level
  // says it once instead. A row whose version differs still shows its own.
  function walk(node: Node, depth: number, path: string, sharedHere = "") {
    const name = node.component;
    const repeated = seen.has(name);
    seen.add(name);

    const isOpen = opened.has(name);
    const openable = node.children > 0 && !repeated;
    const kids = below.get(name);

    rows.push(
      <div
        key={path}
        className={`node${name === focus ? " here" : ""}${openable ? " openable" : ""}`}
        style={{ paddingLeft: depth * 20 }}
      >
        {/* Whether anything hangs off this row, said by the marker itself.
            Both states were drawn in the same faint line color, so a node
            with a hundred things under it and a leaf looked alike until you
            clicked one — and clicking the wrong one was how the leaf's
            behavior got noticed. The triangle is ink, because it is a
            control; the leaf's dot stays faint, because it is punctuation. */}
        {/* A button where it opens something, and punctuation where it does
            not. It was a span with a click handler either way, so a tree
            could be walked from a keyboard — the names are buttons — and
            never expanded: every node past the first level was unreachable
            without a pointer, on the screen whose whole purpose is walking
            down. */}
        {openable ? (
          <button
            type="button"
            className="rule has"
            aria-expanded={isOpen}
            title={
              isOpen
                ? "Close what this pulls in"
                : `Open what this pulls in — ${node.children.toLocaleString()} ${
                    node.children === 1 ? "component" : "components"
                  }`
            }
            onClick={(event) => {
              event.stopPropagation();
              onToggle(name);
            }}
          >
            {isOpen ? "▾" : "▸"}
          </button>
        ) : (
          <span
            className="rule"
            title={repeated ? "Shown above, where it is open" : "Pulls nothing in"}
          >
            ·
          </span>
        )}
        {/* Openable rather than the raw count: a component already drawn
            higher up is marked instead of expanded again, and clicking its
            name should not open a second copy of it. */}
        {/* A button rather than a span with a click handler: selecting a node
            is the whole of how this screen is navigated, and a tree nobody can
            reach from a keyboard is a tree nobody can use without a pointer. */}
        <button
          type="button"
          className="id"
          onClick={() =>
            openable ? onToggle(name) : onSelect(name, 0, node.version, node.ecosystem)
          }
        >
          {name}
        </button>
        <span className="ver" title={node.version}>
          {sharedHere !== "" && node.version === sharedHere ? "" : node.version}
        </span>
        {repeated && <span className="repeat">shown above</span>}
        {/* What that number is made of, worst first. Five thousand beneath a
            node says nothing about whether any of it matters, which is what
            somebody deciding where to descend is asking.

            In a column of its own, right-aligned, with every band the same
            width whether it holds one digit or four: down a page of rows at
            six different depths, bands that start wherever the name ends are
            five numbers a reader cannot compare, which is the one thing they
            are for. */}
        <Strip by={node.beneath_by_severity} />
        {/* What is open in everything under it, not only on it. A container
            holds none of its own, so counting only itself said every one of
            them was clean while the packages inside held thousands. */}
        <span
          className={`count${node.beneath > HOT ? " hot" : node.beneath === 0 ? " none" : ""}`}
          title={
            node.children > 0
              ? `${node.beneath.toLocaleString()} open in here, ${node.findings.toLocaleString()} against this component itself`
              : undefined
          }
        >
          {node.beneath.toLocaleString()}
        </span>
        {/* Everything else about this component, asked for rather than
            standing open beside the tree. */}
        <button
          type="button"
          className="look"
          title={`What pulls ${name} in, what it pulls in, and what is open against it`}
          aria-label={`Look at ${name}`}
          onClick={(event) => {
            event.stopPropagation();
            onSelect(name, 0, node.version, node.ecosystem);
          }}
        >
          ⋯
        </button>
      </div>,
    );

    if (!isOpen || repeated) return;

    if (kids === undefined) {
      rows.push(
        <div key={`${path}/…`} className="node" style={{ paddingLeft: (depth + 1) * 20 }}>
          <span className="rule">·</span>
          <Loading inline />
        </div>,
      );
      return;
    }

    // The server has already put these in the order somebody reads them:
    // what opens first, then the most findings. Truncation, where it happens
    // at all, therefore takes from the end rather than from the middle.
    const all = widened.has(name);
    // Past the cap, the step on the way to the component being arrived at is
    // kept whatever its position. Otherwise a link from a finding opens a tree
    // that does not contain the component it was opened for, which is the one
    // thing the link exists to show.
    const shown = all
      ? kids
      : kids
          .slice(0, CHILDREN)
          .concat(kids.slice(CHILDREN).filter((kid) => onPath.has(kid.component)));
    const hidden = kids.length - shown.length;

    // A version every child at this level shares is not a version of any of
    // them — it is the producer describing the build, and repeating it on
    // every row is the noise it looks like. Said once instead, and still on
    // each row's tooltip.
    const common = sharedVersion(kids);
    if (common) {
      rows.push(
        <div key={`${path}/version`} className="node" style={{ paddingLeft: (depth + 1) * 20 }}>
          <span className="rule">·</span>
          <span className="hint">
            all at <span className="id">{common}</span>
          </span>
        </div>,
      );
    }
    if (hidden > 0) {
      rows.push(
        <button
          key={`${path}/more`}
          type="button"
          className="more"
          style={{ marginLeft: (depth + 1) * 20 }}
          onClick={() => onWiden(name)}
        >
          Show all {kids.length.toLocaleString()} under {name} — {shown.length} shown
        </button>,
      );
    }
    shown.forEach((kid, i) => walk(kid, depth + 1, `${path}/${i}:${kid.component}`, common));
  }

  walk(root, 0, root.component);
  return <div className="tree">{rows}</div>;
}

// What is selected: what pulls it in, what is open against it, and what it
// pulls in. Upward is the direction people actually use — somebody arrives
// from a finding and asks why the component is here.
function Pane({
  at,
  focus,
  rootName,
  above,
  belowCount,
  node,
  pending,
  error,
  version,
  ecosystem,
}: {
  at: At;
  focus: string;
  rootName: string;
  above: Node[];
  belowCount: number;
  node: Node | null;
  pending: boolean;
  error: unknown;
  version: string;
  ecosystem: string;
}) {
  const build =
    `/products/${encodeURIComponent(at.product)}` +
    `/streams/${encodeURIComponent(at.stream)}` +
    `/variants/${encodeURIComponent(at.variant)}`;
  const list = `${build}/findings`;
  if (!focus) {
    return (
      <div>
        <div className="card">
          <h3>No component selected</h3>
          <p className="reading">
            Pick a component on the left to see its dependents, its dependencies, and what is open
            against it.
          </p>
        </div>
      </div>
    );
  }
  if (pending) {
    return (
      <div>
        <div className="card">
          <Loading />
        </div>
      </div>
    );
  }
  if (error) {
    return (
      <div>
        <div className="card">
          <Failed error={error} what="What sits around this could not be read." />
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="card">
        <h3>{focus}</h3>
        {node && (
          <p className="hint" style={{ margin: "0 0 10px" }}>
            <span className="id">{node.version}</span>
          </p>
        )}

        <History
          at={at}
          focus={focus}
          whole={focus === rootName}
          version={version}
          ecosystem={ecosystem}
        />

        <div className="upward">
          <h5>Dependents</h5>
          {above.length === 0 ? (
            <p className="reading" style={{ margin: 0 }}>
              {focus === rootName
                ? "Nothing — this is the product itself."
                : "Nothing — the build contains it directly."}
            </p>
          ) : (
            <ol>
              {/* Keyed by position as well as by name. One component reaches
                  another by more than one edge — the sentence below this list
                  says so — and a name alone is therefore not unique here,
                  which React resolves by dropping rows. */}
              {above.map((parent, at) => (
                <li key={`${parent.component} ${at}`}>
                  <span className="id">{parent.component}</span>
                </li>
              ))}
            </ol>
          )}
          {above.length > 1 && (
            <p className="reading" style={{ marginTop: 7 }}>
              Reached {above.length} ways: one component with several edges, not several copies.
            </p>
          )}
        </div>

        <div className="evblock">
          <h4>Open issues</h4>
          <p
            style={{
              fontSize: "var(--step-2)",
              fontWeight: 700,
              margin: 0,
              letterSpacing: "-0.02em",
            }}
          >
            {node ? node.beneath.toLocaleString() : "—"}
          </p>
          {node && node.children > 0 && (
            <p className="hint">
              in everything under it by this path. {node.findings.toLocaleString()} at this
              component here.
            </p>
          )}
          {node && node.children === 0 && (
            <p className="hint">at this component, under the parent shown.</p>
          )}
          {/* The count is a way in, not a fact to admire: the list it counts
              is one link away, narrowed on the server the way the list
              narrows everything else. */}
          {node && node.beneath > 0 && (
            <p style={{ margin: "8px 0 0", display: "flex", flexWrap: "wrap", gap: "6px 14px" }}>
              {focus === rootName ? (
                <Link to={`${list}`} className="linkish">
                  View all {node.beneath.toLocaleString()} findings →
                </Link>
              ) : (
                <>
                  {node.findings > 0 && (
                    <Link to={`${list}?component=${encodeURIComponent(focus)}`} className="linkish">
                      Findings at this component →
                    </Link>
                  )}
                  {node.children > 0 && (
                    <Link to={`${list}?beneath=${encodeURIComponent(focus)}`} className="linkish">
                      Findings under it →
                    </Link>
                  )}
                </>
              )}
            </p>
          )}
        </div>

        <div className="evblock">
          <h4>Dependencies</h4>
          <p className="hint">
            {belowCount ? `${belowCount.toLocaleString()} components` : "Nothing — it is a leaf"}
          </p>
        </div>

        {node && node.findings > 0 && (
          <Link to={`${build}/components/${encodeURIComponent(focus)}/decide`} className="linkish">
            Bulk decision →
          </Link>
        )}
      </div>
    </div>
  );
}

// What has happened in this part of the tree, over twelve weeks.
//
// **A team owns an area, not a product.** The three lines on the home page
// answer "are we keeping pace" for whoever owns the whole of it; the same
// question about a kernel, or about one library and everything under it, had
// no answer anywhere — the trend took a product, a branch and a variant and
// nothing else, while the list beside it had narrowed by a subtree from the
// start.
//
// It is also where a build starting to carry patches becomes visible. A
// carried patch is read at ingest and files a suppression saying it resolves
// the issue, so the findings close without the version moving — which is
// invisible in a list of what is open now and is a step down in this.
//
// Read only for a selected node, and never for the build's root: that chart
// already exists on the home page, and drawing it again here under a different
// heading would be two answers to one question.
function History({
  at,
  focus,
  whole,
  version,
  ecosystem,
}: {
  at: At;
  focus: string;
  whole: boolean;
  // Which component, where the name means more than one. Without these the
  // chart asked about a name the build holds twice and was refused.
  version: string;
  ecosystem: string;
}) {
  const trend = useQuery({
    enabled: focus !== "" && !whole,
    queryKey: ["subtree-trend", at.product, at.stream, at.variant, focus, version, ecosystem],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/trend", {
          params: {
            query: {
              product: at.product,
              stream: at.stream,
              variant: at.variant,
              beneath: focus,
              ...(version ? { beneath_version: version } : {}),
              ...(ecosystem ? { beneath_ecosystem: ecosystem } : {}),
              weeks: 12,
            },
          },
        }),
      ),
    retry: false,
  });
  if (whole || focus === "") return null;
  const points = trend.data?.items ?? [];
  return (
    <div className="evblock">
      <h4>Twelve-week history</h4>
      {trend.isError ? (
        <Failed error={trend.error} what="The history of this subtree could not be read." />
      ) : trend.isPending ? (
        <p className="hint">Working it out…</p>
      ) : points.length === 0 ? (
        <p className="hint">Nothing has opened or closed under this in twelve weeks.</p>
      ) : (
        <>
          <Pace points={points} />
          <p className="hint">
            Open, new and resolved for this component and everything under it, counted as distinct
            issues. A drop with no version moving is a patch the build started carrying: one that
            names what it resolves closes the finding where it is, without the package moving.
          </p>
        </>
      )}
    </div>
  );
}
