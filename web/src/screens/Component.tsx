import { useState } from "react";
import { Holder, type Held } from "../ui/Holder";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Loading } from "../ui/Loading";
import { Failed } from "../ui/Failed";
import { Empty } from "../ui/Empty";
import { on } from "../ui/when";
import { Editor } from "../ui/Editor";
import { notACredential } from "../ui/noautofill";
import { Pace } from "../ui/Charts";

// One component, across the builds that carry it.
//
// **The screen that was missing.** The by-component view answers where the
// weight is, and clicking a component opened a filtered list of its findings —
// so a component could be read and never acted on. The act of upgrading one
// therefore ended up on a screen of its own, keyed on version pairs, which put
// the thing somebody does on a different page from the thing it is done to.
//
// **Answered per build, because the answer differs by build.** A stream
// staying on a maintained older line and a stream that has moved on are
// different work with different testing, and one target across both would be
// wrong for one of them.
// How many versions to move to are worth listing. A kernel offers twenty, and
// the question somebody is answering is which one to take rather than what the
// whole set is.
const SHOWN = 4;

export function Component() {
  const { product = "", component = "" } = useParams();
  const [params] = useSearchParams();
  const builds = useQuery({
    queryKey: ["component", product, component],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/components/{component}", {
          params: { path: { product, component } },
        }),
      ),
  });

  const queries = useQueryClient();
  // Which builds this promise is for, the version it moves to, and when. One
  // record per target version: ticking builds that need different versions is
  // two promises, not one act with a version that is wrong for one of them.
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [to, setTo] = useState("");
  const [by, setBy] = useState("");
  const [because, setBecause] = useState("");
  // Who carries it. A team as readily as a person: moving a package is work a
  // queue tracks rather than a judgment one person makes, and it is part of
  // this act rather than a second one somebody has to remember.
  const [holder, setHolder] = useState<Held | null>(null);
  const [said, setSaid] = useState<string | null>(null);

  const plan = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/components/{component}/upgrade", {
          params: { path: { product, component } },
          body: {
            to: to.trim(),
            by,
            reasoning: because,
            ...(holder?.kind === "team" ? { team: holder.identity } : {}),
            ...(holder?.kind === "person" ? { person: holder.identity } : {}),
            builds: [...chosen].map((each) => {
              const [stream, variant] = each.split("\u0000");
              return { stream: stream ?? "", variant: variant ?? "" };
            }),
          },
        }),
      ),
    onSuccess: (done) => {
      setSaid(
        `Recorded against ${done.decisions} ${done.decisions === 1 ? "place" : "places"}` +
          ` across ${done.issues} ${done.issues === 1 ? "issue" : "issues"}.` +
          (done.waiting
            ? " It is past the earliest deadline it covers, so it waits for a second person."
            : " In force now.") +
          (done.held
            ? ` ${done.held} ${done.held === 1 ? "finding is" : "findings are"} now carried by ` +
              `${holder?.name ?? "them"}.`
            : ""),
      );
      setChosen(new Set());
      setTo("");
      setBy("");
      setBecause("");
      setHolder(null);
      void queries.invalidateQueries({ queryKey: ["component"] });
      void queries.invalidateQueries({ queryKey: ["holdings"] });
      void queries.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  if (builds.isPending) return <Loading />;
  if (builds.isError) {
    return <Failed error={builds.error} what="This component could not be read." />;
  }
  const rows = builds.data?.items ?? [];

  return (
    <>
      <div className="screen-head">
        <h2>{component}</h2>
        <p>
          What each build of {product} ships, what is open against it there, and where it could go.
          Answered per build: a stream on a maintained older line and a stream that has moved on are
          different work.
        </p>
      </div>

      {rows.length === 0 ? (
        <Empty
          title="No build carries this with anything open against it."
          detail="Either the name is not one this product ships, or nothing is open against it — which is the good case."
        />
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Build</th>
                <th>Ships</th>
                <th>Upgrade to</th>
                <th className="num">Issues</th>
                <th className="num">Consumers</th>
                <th>Due</th>
                <th>Planned</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.stream} ${row.variant}`} className="row">
                  <td>
                    <label className="check">
                      <input
                        type="checkbox"
                        aria-label={`Plan an upgrade for ${row.stream} ${row.variant}`}
                        checked={chosen.has(`${row.stream}\u0000${row.variant}`)}
                        onChange={(event) => {
                          const key = `${row.stream}\u0000${row.variant}`;
                          setChosen((was) => {
                            const next = new Set(was);
                            if (event.target.checked) next.add(key);
                            else next.delete(key);
                            return next;
                          });
                        }}
                      />
                      <span>
                        <span className="id">{row.stream}</span>{" "}
                        <span className="hint">{row.variant}</span>
                      </span>
                    </label>
                  </td>
                  <td className="id">{row.version}</td>
                  {/* The few worth reading, not all of them. A kernel names
                      thirteen versions and a column listing all thirteen is one
                      nobody reads to the end of. Where they can be ordered the
                      first is the one furthest along, and what it closes counts
                      every earlier fix — so the leading row is the answer and
                      the rest are the line behind it. */}
                  <td>
                    {(row.upgrades ?? []).length === 0 ? (
                      <span className="hint">nothing to move to</span>
                    ) : (
                      <>
                        {(row.upgrades ?? []).slice(0, SHOWN).map((up) => (
                          <div key={up.to}>
                            <span className="id">{up.to}</span>{" "}
                            <span className="hint">
                              {up.ordered ? `closes ${up.reached}` : `fixed ${up.fixed_here}`}
                            </span>
                          </div>
                        ))}
                        {(row.upgrades ?? []).length > SHOWN && (
                          <div className="hint">
                            and {(row.upgrades ?? []).length - SHOWN} more
                          </div>
                        )}
                        {(row.upgrades ?? []).length > 0 && !row.upgrades?.[0]?.ordered && (
                          <div
                            className="hint"
                            title="These versions could not be put in order, so each count is what that release fixed itself"
                          >
                            not ranked
                          </div>
                        )}
                      </>
                    )}
                  </td>
                  <td className="num">
                    {/* The way through to what is actually open here, which is
                        what clicking the component used to do and still has
                        to. */}
                    <Link
                      to={
                        `/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(row.stream ?? "")}` +
                        `/variants/${encodeURIComponent(row.variant ?? "")}/findings` +
                        `?component=${encodeURIComponent(component)}`
                      }
                    >
                      {(row.issues ?? 0).toLocaleString()}
                    </Link>
                  </td>
                  {/* The unit somebody acts in: one judgment covers the
                      whole fold, and what varies underneath it is what pulls
                      the package in. The place count is the title, being what
                      the bulk cap is measured against and nothing a reader
                      reconciles with anything else on the row. */}
                  <td
                    className="num"
                    style={{ color: "var(--faint)" }}
                    title={`${(row.places ?? 0).toLocaleString()} places underneath`}
                  >
                    {(row.consumers ?? 0).toLocaleString()}
                  </td>
                  <td className="hint">{row.due_at ? on(row.due_at) : "—"}</td>
                  <td>
                    {row.upgrade_to ? (
                      <>
                        <span className="id">{row.upgrade_to}</span>
                        {row.committed_to && (
                          <>
                            {" "}
                            <span className="hint">by {on(row.committed_to)}</span>
                          </>
                        )}
                      </>
                    ) : (
                      <span className="hint">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {rows.length > 0 && (
        <Around
          product={product}
          component={component}
          builds={rows.map((row) => ({ stream: row.stream ?? "", variant: row.variant ?? "" }))}
          asked={{ stream: params.get("stream") ?? "", variant: params.get("variant") ?? "" }}
        />
      )}

      {said && (
        <div className="alert info" style={{ margin: "10px 0" }}>
          <strong>Recorded</strong>
          <span>{said}</span>
        </div>
      )}

      {chosen.size > 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <h3>Plan an upgrade</h3>
          <p className="reading" style={{ marginBottom: 8 }}>
            Everything open against <b>{component}</b> in the{" "}
            {chosen.size === 1 ? "release" : `${chosen.size} releases`} ticked above is recorded as
            waiting on this upgrade. Moving to a version is a claim that it answers what is open on
            the package — the next scan says which of it was true, and nothing here is ticked off by
            hand. A date past the earliest deadline it covers needs a second person, because that
            defers the worst thing in it.
          </p>
          {plan.error != null && <Failed error={plan.error} what="That could not be recorded." />}
          <div className="filters">
            <label className="field">
              <span>Move to</span>
              <input
                {...notACredential}
                type="text"
                value={to}
                placeholder="the version, as its packager writes it"
                onChange={(event) => setTo(event.target.value)}
              />
            </label>
            <label className="field">
              <span>Done by</span>
              <input
                {...notACredential}
                type="date"
                value={by}
                onChange={(event) => setBy(event.target.value)}
              />
            </label>
            <label className="field">
              <span>Carried by</span>
              <Holder
                product={product}
                value={holder ? { identity: holder.identity, name: holder.name } : null}
                onPick={setHolder}
                placeholder="a person or a team"
                none="No one yet"
              />
              <span className="hint">
                A team queue stays unassigned until someone takes it. Covers every build of the
                product.
              </span>
            </label>
          </div>
          <Editor
            value={because}
            onChange={setBecause}
            placeholder="Why this is the answer here."
          />
          <div className="actions" style={{ marginTop: 10 }}>
            <button
              type="button"
              className="btn"
              disabled={!to.trim() || !by || !because.trim() || plan.isPending}
              onClick={() => plan.mutate()}
            >
              {plan.isPending ? "Recording…" : `Plan for ${chosen.size}`}
            </button>
            <button type="button" className="linkish" onClick={() => setChosen(new Set())}>
              Clear
            </button>
          </div>
        </div>
      )}

      <p className="hint" style={{ marginTop: 10 }}>
        Listed by how much each closes, not by version order. The deadline is the earliest open in
        that build.
      </p>
    </>
  );
}

// Where this component sits in one build's graph, and what has happened to it
// over twelve weeks.
//
// Per build, because an edge is a fact about one: the same library is pulled
// in by different things in different builds. The table above lists them, so
// the build is picked from that set rather than typed, and a link naming one
// arrives on it.
function Around({
  product,
  component,
  builds,
  asked,
}: {
  product: string;
  component: string;
  builds: { stream: string; variant: string }[];
  asked: { stream: string; variant: string };
}) {
  const named = builds.find((b) => b.stream === asked.stream && b.variant === asked.variant);
  const [at, setAt] = useState(named ?? builds[0]);
  const here = at ?? builds[0];
  const scope = here ? { product, stream: here.stream, variant: here.variant } : null;

  const around = useQuery({
    enabled: scope !== null,
    queryKey: ["around", product, component, here?.stream, here?.variant],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/around",
          { params: { path: { ...scope!, component } } },
        ),
      ),
    retry: false,
  });
  const trend = useQuery({
    enabled: scope !== null,
    queryKey: ["component-trend", product, component, here?.stream, here?.variant],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/trend", {
          params: { query: { ...scope!, beneath: component, weeks: 12 } },
        }),
      ),
    retry: false,
  });

  if (!here) return null;
  const above = around.data?.above ?? [];
  const below = around.data?.below ?? [];
  const points = trend.data?.items ?? [];
  const buildAt =
    `/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(here.stream)}` +
    `/variants/${encodeURIComponent(here.variant)}`;
  const componentAt = (name: string) =>
    `/products/${encodeURIComponent(product)}/components/${encodeURIComponent(name)}` +
    `?stream=${encodeURIComponent(here.stream)}&variant=${encodeURIComponent(here.variant)}`;

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="screen-head" style={{ marginBottom: 8 }}>
        <h3>In the graph</h3>
        {builds.length > 1 && (
          <label className="hint" style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            <span>Build</span>
            <select
              aria-label="Which build"
              style={{ width: "auto" }}
              value={here.stream + "\u0000" + here.variant}
              onChange={(event) => {
                const [stream, variant] = event.target.value.split("\u0000");
                setAt({ stream: stream ?? "", variant: variant ?? "" });
              }}
            >
              {builds.map((b) => (
                <option key={b.stream + b.variant} value={b.stream + "\u0000" + b.variant}>
                  {b.stream} · {b.variant}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      {around.isError ? (
        <Failed error={around.error} what="What sits around this could not be read." />
      ) : (
        <div className="evidence">
          <div className="evblock">
            <h4>Pulled in by</h4>
            {around.isPending ? (
              <p className="hint">Working it out…</p>
            ) : above.length === 0 ? (
              <p className="hint">The build contains it directly.</p>
            ) : (
              <>
                <ol className="refs">
                  {above.map((parent, i) => (
                    <li key={(parent.component ?? "") + i}>
                      <Link className="id" to={componentAt(parent.component ?? "")}>
                        {parent.component}
                      </Link>
                    </li>
                  ))}
                </ol>
                {above.length > 1 && (
                  <p className="hint">
                    Reached {above.length} ways, not {above.length} copies.
                  </p>
                )}
              </>
            )}
          </div>

          <div className="evblock">
            <h4>Pulls in</h4>
            <p className="hint">
              {around.isPending
                ? "Working it out…"
                : below.length === 0
                  ? "Nothing — it is a leaf."
                  : below.length.toLocaleString() + " components"}
            </p>
            <p style={{ margin: "8px 0 0" }}>
              <Link className="linkish" to={buildAt + "/tree?at=" + encodeURIComponent(component)}>
                Open in the tree →
              </Link>
            </p>
          </div>

          <div className="evblock">
            <h4>Twelve-week history</h4>
            {trend.isError ? (
              <p className="hint">Could not be read.</p>
            ) : trend.isPending ? (
              <p className="hint">Working it out…</p>
            ) : points.length === 0 ? (
              <p className="hint">Nothing opened or closed in twelve weeks.</p>
            ) : (
              <Pace points={points} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
