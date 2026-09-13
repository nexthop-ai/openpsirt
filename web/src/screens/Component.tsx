import { useMemo, useState } from "react";
import { Holder, type Held } from "../ui/Holder";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Loading } from "../ui/Loading";
import { Failed } from "../ui/Failed";
import { Empty } from "../ui/Empty";
import { Outward } from "../ui/Outward";
import { on } from "../ui/when";
import { Editor } from "../ui/Editor";
import { notACredential } from "../ui/noautofill";
import { Pace } from "../ui/Charts";
import { upstream } from "../ui/upstream";
import { ROLLED } from "../ui/severities";
import { Severity } from "../ui/Severity";

// One component, and the one piece of work it is.
//
// **Arranged on where it sits.** What can be done about a package is mostly a
// function of its position: a leaf carries its own risk and is upgraded, and
// something vendored in pre-built carries everything beneath it and moves only
// when it does. So the graph leads — what pulls it in, the package, what it
// carries — and the act hangs off that.
//
// **A build is listed because it ships it**, not because something is open
// against it. A package whose risk is all inherited still has a version, a
// position, and things pulling it in.
//
// **One entry per version.** A build shipping a name at two versions holds two
// components, and they are two pieces of code to decide about. The page is
// about the one asked for and says what the others are.
type Build = Body<"PerBuildBody">;

// The separator inside a key naming one build. Not a character either name can
// hold, so a key cannot be two builds.
const APART = "\u0000";

// How many versions to offer before the rest are a count. A kernel names
// twenty, and the question is which to take rather than what the whole set is.
const SHOWN = 5;

const keyOf = (row: { stream?: string; variant?: string }) =>
  (row.stream ?? "") + APART + (row.variant ?? "");

const findingsAt = (product: string, row: Build, component: string) =>
  `/products/${encodeURIComponent(product)}` +
  `/streams/${encodeURIComponent(row.stream ?? "")}` +
  `/variants/${encodeURIComponent(row.variant ?? "")}/findings` +
  `?component=${encodeURIComponent(component)}`;

export function Component() {
  const { product = "", component = "" } = useParams();
  const [params, setParams] = useSearchParams();

  const builds = useQuery({
    queryKey: ["component", product, component],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/components/{component}", {
          params: { path: { product, component } },
        }),
      ),
  });
  const rows = useMemo(() => builds.data?.items ?? [], [builds.data]);

  // Which of them the page is about. The address names it, so a link from the
  // tree or from a findings list arrives on what somebody was reading.
  const stream = params.get("stream") ?? "";
  const variant = params.get("variant") ?? "";
  const version = params.get("version") ?? "";
  const here = useMemo(() => {
    const match = rows.find(
      (row) =>
        (!stream || row.stream === stream) &&
        (!variant || row.variant === variant) &&
        (!version || row.version === version),
    );
    // The worst of them where nothing was named, so the page opens on the build
    // with something to answer rather than on whichever sorted first.
    return match ?? [...rows].sort((a, b) => (b.issues ?? 0) - (a.issues ?? 0))[0];
  }, [rows, stream, variant, version]);

  // The versions this product ships the name at. More than one is two pieces of
  // code, and the reader picks which.
  const versions = useMemo(() => {
    const seen = new Map<string, number>();
    for (const row of rows) {
      const at = row.version ?? "";
      seen.set(at, (seen.get(at) ?? 0) + (row.issues ?? 0));
    }
    return [...seen.entries()].map(([at, issues]) => ({ at, issues }));
  }, [rows]);

  function go(next: Record<string, string>) {
    const to = new URLSearchParams(params);
    for (const [key, value] of Object.entries(next)) to.set(key, value);
    setParams(to);
  }

  if (builds.isPending) return <Loading />;
  if (builds.isError) {
    return <Failed error={builds.error} what="This component could not be read." />;
  }
  if (!here) {
    return (
      <>
        <div className="screen-head">
          <h2 className="id">{component}</h2>
        </div>
        <Empty
          title="No build of this product ships it."
          detail="The name is not one any scanned build carries."
        />
      </>
    );
  }

  const sameVersion = rows.filter((row) => row.version === here.version);
  const link = upstream(here.purl);
  // The bands are declared worst first, so the first one present is the worst.
  const worst = ROLLED.find((band) => (here.by_severity ?? {})[band]);

  return (
    <>
      <div className="screen-head">
        <h2 className="id">{component}</h2>
        <p className="variants">
          <span className="vchip id">{here.version}</span>
          {here.ecosystem && <span className="vchip">{here.ecosystem}</span>}
          {(here.issues ?? 0) > 0 ? (
            <Link className="vchip" to={findingsAt(product, here, component)}>
              {(here.issues ?? 0).toLocaleString()} open on it →
            </Link>
          ) : (
            <span className="vchip ok">nothing open on it</span>
          )}
          {here.exploited && <span className="vchip bad">known exploited</span>}
          {worst && <Severity word={worst} />}
          {here.due_at && <span className="vchip differs">due {on(here.due_at)}</span>}
        </p>
      </div>

      {versions.length > 1 && (
        <div className="card" style={{ marginBottom: 12 }}>
          <h3>Shipped at {versions.length} versions</h3>
          <p className="reading" style={{ marginBottom: 8 }}>
            Different code, decided separately.
          </p>
          <p className="variants">
            {versions.map((each) => (
              <button
                key={each.at}
                type="button"
                className={each.at === here.version ? "vchip on" : "vchip"}
                aria-pressed={each.at === here.version}
                onClick={() => go({ version: each.at })}
              >
                <span className="id">{each.at}</span>{" "}
                <span className="hint">{each.issues} open</span>
              </button>
            ))}
          </p>
        </div>
      )}

      <div className="detail">
        <div>
          <Sits
            product={product}
            component={component}
            here={here}
            builds={rows}
            onBuild={(row) =>
              go({
                stream: row.stream ?? "",
                variant: row.variant ?? "",
                version: row.version ?? "",
              })
            }
          />
          <Upgrade product={product} component={component} here={here} covering={sameVersion} />
        </div>

        <div>
          <div className="card">
            <h3>What this package is</h3>
            {here.summary && <p className="reading">{here.summary}</p>}
            <dl className="facts">
              <dt>Identifier</dt>
              <dd className="id" style={{ wordBreak: "break-all" }}>
                {here.purl || "—"}
              </dd>
              <dt>Project</dt>
              <dd>
                {here.project_url ? (
                  <Outward href={here.project_url}>
                    {here.project_url.replace(/^https?:\/\//, "")}
                  </Outward>
                ) : link ? (
                  <Outward href={link}>{link.replace(/^https:\/\//, "")}</Outward>
                ) : (
                  <span className="hint">not known</span>
                )}
              </dd>
              <dt>Supplier</dt>
              <dd>
                {here.supplier ? (
                  here.supplier
                ) : (
                  <span className="hint" title="The inventory did not say who supplied it">
                    not stated
                  </span>
                )}
              </dd>
              <dt>Newest known</dt>
              <dd>
                {here.newest_version ? (
                  <>
                    <span className="id">{here.newest_version}</span>
                    {here.newest_released_at && (
                      <span className="hint"> · {on(here.newest_released_at)}</span>
                    )}
                  </>
                ) : (
                  <span
                    className="hint"
                    title="No index is asked about a distribution package: the distribution is its maintainer, and an upstream release date says nothing about the software inside"
                  >
                    no index asked
                  </span>
                )}
              </dd>
              <dt>First seen</dt>
              <dd className="hint">{here.first_seen ? on(here.first_seen) : "—"}</dd>
              <dt>Upgrade scheduled</dt>
              <dd>
                {here.upgrade_to ? (
                  <>
                    <span className="id">{here.upgrade_to}</span>
                    {here.committed_to && <span className="hint"> by {on(here.committed_to)}</span>}
                  </>
                ) : (
                  <span className="hint">none</span>
                )}
              </dd>
            </dl>
            <p className="hint">
              {here.project_url
                ? "As the ecosystem's index states it."
                : "Built from the identifier, since no index stated one."}{" "}
              Nothing is fetched from it.
            </p>
          </div>

          <Landed here={here} />
        </div>
      </div>

      <Ships product={product} component={component} rows={rows} here={here} />

      <History product={product} component={component} here={here} />
    </>
  );
}

// Where the package sits, drawn as the chain it sits in.
//
// Per build, because an edge is a fact about one: the same library is pulled in
// by different things in different builds. The build comes from the rows rather
// than being typed.
function Sits({
  product,
  component,
  here,
  builds,
  onBuild,
}: {
  product: string;
  component: string;
  here: Build;
  builds: Build[];
  onBuild: (row: Build) => void;
}) {
  const scope = { product, stream: here.stream ?? "", variant: here.variant ?? "" };
  const around = useQuery({
    queryKey: ["around", product, component, here.stream, here.variant, here.version],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/around",
          {
            params: {
              path: { ...scope, component },
              query: here.version ? { version: here.version } : {},
            },
          },
        ),
      ),
    retry: false,
  });

  const above = around.data?.above ?? [];
  const below = around.data?.below ?? [];
  const carrying = below.filter((each) => (each.findings ?? 0) > 0);
  const buildAt =
    `/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(scope.stream)}` +
    `/variants/${encodeURIComponent(scope.variant)}`;
  const componentAt = (name: string) =>
    `/products/${encodeURIComponent(product)}/components/${encodeURIComponent(name)}` +
    `?stream=${encodeURIComponent(scope.stream)}&variant=${encodeURIComponent(scope.variant)}`;

  return (
    <div>
      <div className="screen-head" style={{ marginBottom: 10 }}>
        {builds.length > 1 && (
          <label className="hint" style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            <span>Build</span>
            <select
              aria-label="Which build"
              style={{ width: "auto" }}
              value={keyOf(here) + APART + (here.version ?? "")}
              onChange={(event) => {
                const row = builds.find(
                  (each) => keyOf(each) + APART + (each.version ?? "") === event.target.value,
                );
                if (row) onBuild(row);
              }}
            >
              {builds.map((row) => (
                <option
                  key={keyOf(row) + row.version}
                  value={keyOf(row) + APART + (row.version ?? "")}
                >
                  {row.stream} · {row.variant} · {row.version}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      {around.isError ? (
        <Failed error={around.error} what="Where it sits could not be read." />
      ) : (
        <ol className="sits">
          <li>
            <span className="step">Pulled in by{above.length > 0 ? ` · ${above.length}` : ""}</span>
            {around.isPending ? (
              <span className="sub">Working it out…</span>
            ) : above.length === 0 ? (
              <span className="sub">The build contains it directly.</span>
            ) : (
              <span className="nm">
                {above.slice(0, 3).map((parent, i) => (
                  <span key={(parent.component ?? "") + i}>
                    {i > 0 && ", "}
                    <Link className="id" to={componentAt(parent.component ?? "")}>
                      {parent.component}
                    </Link>
                  </span>
                ))}
                {above.length > 3 && <span className="sub"> and {above.length - 3} more</span>}
                {above.length > 1 && (
                  <span className="sub">
                    {" "}
                    · reached {above.length} ways, not {above.length} copies
                  </span>
                )}
              </span>
            )}
          </li>

          <li className="at">
            <span className="step">This package{here.ecosystem ? ` · ${here.ecosystem}` : ""}</span>
            <span className="nm id">
              {component} <span className="hint">{here.version}</span>
            </span>
            <span className="sub">
              {(here.issues ?? 0).toLocaleString()} open on it, at{" "}
              {(here.places ?? 0).toLocaleString()} {here.places === 1 ? "place" : "places"} under{" "}
              {(here.consumers ?? 0).toLocaleString()}{" "}
              {here.consumers === 1 ? "consumer" : "consumers"}
              {(here.issues ?? 0) > 0 && (
                <>
                  {" · "}
                  <Link to={findingsAt(product, here, component)}>Read them →</Link>
                </>
              )}
            </span>
            {Object.keys(here.by_severity ?? {}).length > 0 && (
              <span className="strip">
                {ROLLED.filter((band) => (here.by_severity ?? {})[band]).map((band) => (
                  <span
                    key={band}
                    className={`band ${band}`}
                    title={`${(here.by_severity ?? {})[band]} ${band}`}
                  >
                    {(here.by_severity ?? {})[band]}
                  </span>
                ))}
              </span>
            )}
          </li>

          <li>
            <span className="step">
              What it carries{below.length > 0 ? ` · ${below.length.toLocaleString()}` : ""}
            </span>
            {around.isPending ? (
              <span className="sub">Working it out…</span>
            ) : below.length === 0 ? (
              <span className="sub">Nothing — a leaf, so none of this is inherited.</span>
            ) : (
              <>
                <span className="sub">
                  {below.length.toLocaleString()} packages, {carrying.length} with something open
                </span>
                {carrying.length > 0 && (
                  <ul className="branchlist">
                    {carrying.slice(0, 5).map((each, i) => (
                      <li key={(each.component ?? "") + i} className="branch">
                        <Link className="id" to={componentAt(each.component ?? "")}>
                          {each.component}
                        </Link>{" "}
                        <span className="hint">{each.version}</span>
                        <span className="counts">
                          <span className="n">{each.findings}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
            <Link className="linkish" to={buildAt + "/tree?at=" + encodeURIComponent(component)}>
              Open in the tree →
            </Link>
          </li>
        </ol>
      )}
    </div>
  );
}

// Where the fixes landed: each release the findings name, and what it fixed.
//
// Two counts, because they answer different questions. What a release fixed is
// how many name that exact version — its own security content. What reaching it
// closes counts every earlier fix too, which is what somebody choosing between
// two versions asks, and it needs the ecosystem's ordering. Unranked, the two
// are equal and the panel says so.
function Landed({ here }: { here: Build }) {
  const landed = here.upgrades ?? [];
  const ordered = landed[0]?.ordered ?? false;
  const total = landed.reduce((sum, each) => sum + (each.fixed_here ?? 0), 0);

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="screen-head" style={{ marginBottom: 8 }}>
        <h3>Where the fixes landed</h3>
        {landed.length > 0 && (
          <span className="eyebrow" style={{ marginLeft: "auto" }}>
            {landed.length} {landed.length === 1 ? "release" : "releases"}
          </span>
        )}
      </div>

      {landed.length === 0 ? (
        <p className="hint">No version fixes any of what is open here.</p>
      ) : (
        <>
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>Release</th>
                  <th className="num" title="How many of what is open here that release fixed">
                    Fixed here
                  </th>
                  {ordered && (
                    <th
                      className="num"
                      title="Everything moving here closes, counting the earlier fixes too"
                    >
                      Closes
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {landed.map((each) => (
                  <tr key={each.to}>
                    <td className="id">{each.to}</td>
                    <td className="num">{each.fixed_here}</td>
                    {ordered && <td className="num">{each.reached}</td>}
                  </tr>
                ))}
                <tr>
                  <td className="hint">with a fix</td>
                  <td className="num">
                    <b>{total}</b>
                  </td>
                  {ordered && <td />}
                </tr>
              </tbody>
            </table>
          </div>
          <p className="hint" style={{ marginTop: 8 }}>
            {ordered
              ? "Furthest along first. A later release carries the earlier fixes too."
              : "Not ranked: these versions could not be put in order, so each count is what that release fixed itself."}
          </p>
        </>
      )}
    </div>
  );
}

// Promising an upgrade: the version, the releases it is for, the date, and who
// carries it.
//
// **The releases are chosen here**, ticked to the ones shipping this version,
// rather than in a column of the table below. The rest of the promise is written
// here, and a control that summons a form from somewhere else is one nobody
// finds.
function Upgrade({
  product,
  component,
  here,
  covering,
}: {
  product: string;
  component: string;
  here: Build;
  covering: Build[];
}) {
  const queries = useQueryClient();
  const landed = here.upgrades ?? [];
  const [to, setTo] = useState(landed[0]?.to ?? "");
  const [by, setBy] = useState("");
  const [because, setBecause] = useState("");
  const [holder, setHolder] = useState<Held | null>(null);
  const [said, setSaid] = useState<string | null>(null);
  // Every release shipping this version, because one bump moves all of them.
  const [chosen, setChosen] = useState<Set<string>>(
    () => new Set(covering.map((row) => keyOf(row))),
  );

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
              const [stream, variant] = each.split(APART);
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
            ? " Past the earliest deadline it covers, so it waits."
            : " In force now.") +
          (done.held ? ` Carried by ${holder?.name ?? "them"}.` : ""),
      );
      setBy("");
      setBecause("");
      setHolder(null);
      void queries.invalidateQueries({ queryKey: ["component"] });
      void queries.invalidateQueries({ queryKey: ["holdings"] });
      void queries.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  if (said) {
    return (
      <div className="alert info" style={{ marginTop: 12 }}>
        <strong>Recorded</strong>
        <span>{said}</span>
        <button type="button" className="linkish" onClick={() => setSaid(null)}>
          Schedule another
        </button>
      </div>
    );
  }

  // Nothing to move to is a state rather than an empty form: the work is a
  // judgment, and a form that cannot be filled in is one somebody tries anyway.
  if (landed.length === 0) {
    if ((here.issues ?? 0) === 0) return null;
    return (
      <div className="card stuck" style={{ marginTop: 12 }}>
        <h3>There is nothing to upgrade to</h3>
        <p className="reading">
          No version fixes any of the {here.issues} open here, so an upgrade would lapse. These need
          a decision.
        </p>
        <p style={{ marginTop: 10 }}>
          <Link className="btn" to={findingsAt(product, here, component)}>
            Decide them together
          </Link>
        </p>
      </div>
    );
  }

  const ready = to.trim() !== "" && by !== "" && because.trim() !== "" && chosen.size > 0;
  // What a fix exists for, from the scanner rather than from any comparison:
  // every issue naming a version, counted once.
  const withFix = landed.reduce((sum, each) => sum + (each.fixed_here ?? 0), 0);
  const noFix = Math.max(0, (here.issues ?? 0) - withFix);

  return (
    <div className="card act" style={{ marginTop: 12 }}>
      <h3>Schedule an upgrade</h3>
      {plan.error != null && <Failed error={plan.error} what="That could not be recorded." />}

      {/* The pair that needs no version comparison, from the scanner's own
          word on whether a fix exists at all. Read first, because the half no
          upgrade closes is the half that still needs a judgment after the work
          ships. */}
      <div className="kpis tight">
        <span className="kpi">
          <span className="l">A fix exists for</span>
          <span className="n">{withFix.toLocaleString()}</span>
          <span className="d">of the {(here.issues ?? 0).toLocaleString()} open here</span>
        </span>
        <span className="kpi">
          <span className="l">No version fixes</span>
          <span className="n">{noFix.toLocaleString()}</span>
          <span className="d">a judgment rather than an upgrade</span>
        </span>
      </div>

      <div className="filters">
        <div className="field">
          <span>Upgrade to</span>
          <input
            {...notACredential}
            type="text"
            value={to}
            placeholder="the version, as its packager writes it"
            onChange={(event) => setTo(event.target.value)}
          />
          {/* What each candidate would close, beside it. Offered in a list
              rather than a datalist, because the counts are the reason to pick
              one and a datalist shows nothing until somebody clicks into the
              box. Offered, never required: the server is what refuses a version
              it has not heard of, which is what lets somebody name one newer
              than anything reported. */}
          <ul className="tomove">
            {landed.slice(0, SHOWN).map((each, i) => (
              <li key={each.to}>
                <button
                  type="button"
                  className={each.to === to ? "on" : undefined}
                  aria-pressed={each.to === to}
                  onClick={() => setTo(each.to)}
                >
                  <span className="id">{each.to}</span>
                  <span className="why">
                    {each.ordered
                      ? `closes ${(each.reached ?? 0).toLocaleString()}`
                      : `fixed ${(each.fixed_here ?? 0).toLocaleString()} of its own`}
                    {i === 0 && each.ordered && " · furthest along"}
                  </span>
                </button>
              </li>
            ))}
            {landed.length > SHOWN && (
              <li className="hint">{landed.length - SHOWN} more, in the table beside this</li>
            )}
          </ul>
          <span className="hint">
            {landed[0]?.ordered
              ? "A later release carries the earlier fixes, so the first closes the most."
              : "These could not be put in order, so each count is what that release fixed itself."}
          </span>
        </div>

        <label className="field">
          <span>Done by</span>
          <input
            {...notACredential}
            type="date"
            value={by}
            onChange={(event) => setBy(event.target.value)}
          />
          <span className="hint">On or before the earliest deadline, nobody else is needed.</span>
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
          <span className="hint">A team queue stays unassigned until someone takes it.</span>
        </label>
      </div>

      <div className="field">
        <span>Releases this is for</span>
        <p className="variants">
          {covering.map((row) => {
            const key = keyOf(row);
            const picked = chosen.has(key);
            return (
              <button
                key={key}
                type="button"
                className={picked ? "vchip on" : "vchip"}
                aria-pressed={picked}
                onClick={() =>
                  setChosen((was) => {
                    const next = new Set(was);
                    if (picked) next.delete(key);
                    else next.add(key);
                    return next;
                  })
                }
              >
                {picked ? "✓ " : ""}
                <span className="id">{row.stream}</span> <span className="hint">{row.variant}</span>
              </button>
            );
          })}
        </p>
        <span className="hint">
          Every release shipping {here.version}, because one bump moves all of them.
        </span>
      </div>

      <Editor value={because} onChange={setBecause} placeholder="Why this is the answer here." />

      <div className="actions" style={{ marginTop: 10 }}>
        <button
          type="button"
          className="btn"
          disabled={!ready || plan.isPending}
          onClick={() => plan.mutate()}
        >
          {plan.isPending ? "Recording…" : `Schedule for ${chosen.size}`}
        </button>
      </div>
      <p className="hint" style={{ marginTop: 8 }}>
        Covers everything open on the package. The next scan says what it closed.
      </p>
    </div>
  );
}

// What each release ships, and what is open against it there.
function Ships({
  product,
  component,
  rows,
  here,
}: {
  product: string;
  component: string;
  rows: Build[];
  here: Build;
}) {
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="screen-head" style={{ marginBottom: 8 }}>
        <h3>Where it ships</h3>
        <span className="eyebrow" style={{ marginLeft: "auto" }}>
          {rows.length} {rows.length === 1 ? "release" : "releases"}
        </span>
      </div>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Release</th>
              <th>Ships</th>
              <th className="num">Open on it</th>
              <th className="num">Consumers</th>
              <th className="num">Places</th>
              <th>Due</th>
              <th>Upgrade scheduled</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={keyOf(row) + row.version}
                className={
                  keyOf(row) === keyOf(here) && row.version === here.version ? "row on" : "row"
                }
              >
                <td>
                  <span className="id">{row.stream}</span>{" "}
                  <span className="hint">{row.variant}</span>
                </td>
                <td className="id">{row.version}</td>
                <td className="num">
                  <Link to={findingsAt(product, row, component)}>
                    {(row.issues ?? 0).toLocaleString()}
                  </Link>
                </td>
                <td className="num">{(row.consumers ?? 0).toLocaleString()}</td>
                <td className="num" style={{ color: "var(--faint)" }}>
                  {(row.places ?? 0).toLocaleString()}
                </td>
                <td className="hint">{row.due_at ? on(row.due_at) : "—"}</td>
                <td>
                  {row.upgrade_to ? (
                    <>
                      <span className="id">{row.upgrade_to}</span>
                      {row.committed_to && <span className="hint"> by {on(row.committed_to)}</span>}
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
    </div>
  );
}

// Twelve weeks of what opened and closed at this package and under it.
function History({
  product,
  component,
  here,
}: {
  product: string;
  component: string;
  here: Build;
}) {
  const trend = useQuery({
    queryKey: ["component-trend", product, component, here.stream, here.variant],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/trend", {
          params: {
            query: {
              product,
              stream: here.stream ?? "",
              variant: here.variant ?? "",
              beneath: component,
              weeks: 12,
            },
          },
        }),
      ),
    retry: false,
  });
  const points = trend.data?.items ?? [];
  const moved = points.some((each) => (each.opened ?? 0) > 0 || (each.resolved ?? 0) > 0);

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="screen-head" style={{ marginBottom: 8 }}>
        <h3>Twelve weeks</h3>
        <span className="eyebrow" style={{ marginLeft: "auto" }}>
          {here.stream} · {here.variant}
        </span>
      </div>
      {trend.isError ? (
        <p className="hint">Could not be read.</p>
      ) : trend.isPending ? (
        <Loading />
      ) : !moved ? (
        <p className="hint">Nothing opened or closed in twelve weeks.</p>
      ) : (
        <Pace points={points} />
      )}
    </div>
  );
}
