import { useEffect, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Pace } from "../ui/Charts";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";

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
export function Over({ children, onClose }: { children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [onClose]);
  return (
    <div className="overpane" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="overbox" onClick={(event) => event.stopPropagation()}>
        <button type="button" className="overshut" aria-label="Close" onClick={onClose}>
          ×
        </button>
        {children}
      </div>
    </div>
  );
}

// What is selected: what pulls it in, what is open against it, and what it
// pulls in. Upward is the direction people actually use — somebody arrives
// from a finding and asks why the component is here.
export function Pane({
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
