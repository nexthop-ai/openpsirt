import { ROLLED } from "../ui/severities";
// The findings list's other ways of looking at the same rows.
//
// The list itself is one component with a great deal of state — a selection, a
// dozen filters, a page, what is picked across pages — and these are the parts
// that take rows and draw them: one row expanded in place, where a row sits,
// the by-component and by-bump views, the peek, and the pager. They read
// props and hold nothing, which is why they separate cleanly and why the
// component they hang off does not.

import { Loading } from "../ui/Loading";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Exploited, Severity } from "../ui/Severity";

// The bands, worst first — the order of these words is a fact about the domain
// rather than a display choice, which is why the server names the worst one
// and this only draws them. The page sizes, the orders, the filters and where
// a row goes all live beside the list rather than in it, because the finding
// screen asks the same question of the server to offer the row before and the
// row after. Fifty rows is 153 pages of one product's findings, which is not a
// list anybody assembles a day's work out of.
import { PAGE, type Row } from "./list";

// Where a component sits, as the two ends that differ between sibling rows —
// or, where the selection spans builds, which build the row is being read in.
//
// A chain belongs to one build's graph, so a row covering three builds is
// reached three ways and has no single way down. Naming the build is the
// honest thing to put in the column instead: it is what the row's link and
// its actions are about, and the count says it is one of several.
export function Sits({ row }: { row: Row }) {
  if (row.builds) {
    return (
      <span className="chain">
        {/* The way down is one thing and never breaks in the middle of
            itself; the note about the other builds is a second, and may
            take a line of its own where the column is narrow. */}
        <span className="ends">
          <span className="hop id">{row.stream}</span>
          <span className="arrow">/</span>
          <span className="hop id">{row.variant}</span>
        </span>
        {row.builds > 1 && <span className="hint">· one of {row.builds} builds</span>}
      </span>
    );
  }
  if (!row.owner && !row.parent) {
    return <span className="hint">nothing records what pulls this in</span>;
  }
  // Where the route up could not be walked the server sends what pulls this
  // in and no owner above it. Rendering it as one hop rather than as an empty
  // first hop and an arrow to nowhere: what is unknown is the way up to the
  // build, and drawing that as a blank claims something worse than not knowing.
  if (!row.owner && row.parent) {
    return (
      <span className="chain">
        <span className="hop id">{row.parent}</span>
        <span className="hint" title="The inventory does not place this under the build">
          · nothing places it under the build
        </span>
        {(row.chains ?? 0) > 1 && <span className="hint">· one of {row.chains}</span>}
      </span>
    );
  }
  const same = row.owner === row.parent;
  return (
    <span className="chain">
      <span className="ends">
        <span className="hop id">{row.owner}</span>
        {!same && (
          <>
            <span className="arrow">→</span>
            {row.middle ? (
              <>
                <span
                  className="gap"
                  title={`${row.middle} step${row.middle > 1 ? "s" : ""} collapsed — open the finding for the full chain`}
                >
                  +{row.middle}
                </span>
                <span className="arrow">→</span>
              </>
            ) : null}
            <span className="hop id">{row.parent}</span>
          </>
        )}
      </span>
      {(row.chains ?? 0) > 1 && <span className="hint">· one of {row.chains}</span>}
    </span>
  );
}

// Where the weight is, rather than what is wrong. Somebody opening a list of
// several thousand rows needs to know that one package is most of it before
// they start reading.
export function ByComponent({
  at,
  query,
  offset,
  onHide,
  onOnly,
  onSort,
  onPage,
  size,
}: {
  at: { product: string; stream?: string; variant?: string };
  query: Record<string, unknown>;
  offset: number;
  onHide: (component: string) => void;
  onOnly: (component: string) => void;
  // Which order to page in. Weight by default, because where the volume is is
  // the question this view answers; "which of these is worst" is the other
  // one somebody reads it for, and refusing to answer it sends them back to a
  // list of six thousand rows to find out.
  onSort: (key: string) => void;
  // How many a page holds, so the by-component view pages the same way.
  size: number;
  onPage: (offset: number) => void;
}) {
  const grouped = useQuery({
    queryKey: ["findings-by-component", at, query],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings/components", {
          params: {
            path: { product: at.product },
            query: {
              ...(query as Record<string, never>),
              ...(at.stream ? { stream: at.stream } : {}),
              ...(at.variant ? { variant: at.variant } : {}),
            },
          },
        }),
      ),
  });

  if (grouped.isPending) return <Loading />;
  if (grouped.isError) {
    return <Failed error={grouped.error} what="What is open could not be read by component." />;
  }

  const rows = grouped.data?.items ?? [];
  const total = grouped.data?.total ?? 0;
  if (rows.length === 0) {
    return (
      <Empty
        title="Nothing matches what you are looking at."
        detail="Everything here is below the floor you set, or outside the filter."
      />
    );
  }

  const most = rows[0]?.issues ?? 0;
  const worstFirst = (query as { sort?: string }).sort === "severity";

  return (
    <>
      <p className="hint" style={{ margin: "0 0 8px" }}>
        Ordered by issue count — <b>issues</b> is rows in the by-issue view and <b>places</b> is how
        many places those occupy in what you are looking at. Making urgency the order instead would
        reproduce the by-issue list at worse resolution, so the weight is the order and each row
        says what its weight is made of.{" "}
        {/* The same answer as a file, narrowed the same way. This is
            the shape a release meeting argues over, and taking it away meant
            copying the table out. */}
        <a href={componentsFile(at, query, "csv")}>CSV</a> ·{" "}
        <a href={componentsFile(at, query, "json")}>JSON</a>
      </p>

      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Component</th>
              <th>
                <button
                  type="button"
                  className="linkish"
                  aria-pressed={worstFirst}
                  title="Order by the worst thing open against each"
                  onClick={() => onSort(worstFirst ? "" : "severity")}
                >
                  Worst {worstFirst ? "▾" : ""}
                </button>
              </th>
              <th>Upgrade to</th>
              <th className="num">Issues</th>
              <th className="num">Places</th>
              <th style={{ width: 170 }} />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const name = row.component ?? "";
              const share = most > 0 ? Math.round(((row.issues ?? 0) / most) * 100) : 0;
              return (
                <tr key={`${name} ${row.version} ${row.ecosystem ?? ""}`} className="row">
                  <td>
                    {/* The name opens the component. It used to narrow the
                        list, with the component itself behind a small
                        "Open →" in the last column next to "Hide" — an act
                        parked away from the thing it acts on, which is the
                        shape the By fix view was deleted for. */}
                    <Link
                      className="linkish id"
                      title={`Open ${name}`}
                      to={`/products/${encodeURIComponent(at.product)}/components/${encodeURIComponent(name)}`}
                    >
                      {name}
                    </Link>
                    {row.exploited && (
                      <>
                        {" "}
                        <Exploited when />
                      </>
                    )}
                    <br />
                    <span className="id" style={{ color: "var(--faint)" }}>
                      {row.version}
                    </span>
                  </td>
                  {/* What the weight is made of. Ranking by count alone
                      answers this view's own question backwards: a package
                      with forty-four issues outranks one with three
                      criticals, and the count says nothing about which. */}
                  <td>
                    {row.worst ? <Severity word={row.worst} /> : <span className="hint">—</span>}
                    <br />
                    <span className="hint">
                      {ROLLED.filter((band) => (row.by_severity ?? {})[band]).map((band) => (
                        <span key={band} style={{ marginRight: 6 }}>
                          {band[0]?.toUpperCase()}
                          {(row.by_severity ?? {})[band]}
                        </span>
                      ))}
                    </span>
                  </td>
                  {/* Where it could go, on the package it is a bump of.
                      Listed rather than ordered: comparing two versions needs
                      a per-ecosystem ordering this does not have, so the one
                      that closes the most is offered first and "nearest" is
                      not a question this can answer. */}
                  <td>
                    {(row.upgrades ?? []).length === 0 ? (
                      <span className="hint">—</span>
                    ) : (
                      (row.upgrades ?? []).slice(0, 2).map((up, i) => (
                        <div key={up.to}>
                          <span className="id">{up.to}</span>{" "}
                          <span className="hint">
                            closes {up.issues}
                            {i === 0 && (row.upgrades ?? []).length > 2 && (
                              <> · {(row.upgrades ?? []).length - 2} more</>
                            )}
                          </span>
                        </div>
                      ))
                    )}
                  </td>
                  <td className="num">
                    {(row.issues ?? 0).toLocaleString()}
                    <span
                      aria-hidden
                      className="share"
                      style={{ width: `${Math.max(share, 2)}%` }}
                    />
                  </td>
                  <td className="num">{(row.places ?? 0).toLocaleString()}</td>
                  <td>
                    {/* The two secondary acts, where opening the component
                        used to sit. Narrowing is one of them now: the name
                        is the way to the thing itself. */}
                    <button
                      type="button"
                      className="linkish onlyit"
                      title={`What is open against ${name}`}
                      onClick={() => onOnly(name)}
                    >
                      only this
                    </button>
                    <button
                      type="button"
                      className="linkish hideit"
                      title="Hide it from both views until you put it back"
                      onClick={() => onHide(name)}
                    >
                      hide
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="filters" style={{ margin: "10px 0 0" }}>
        <span className="hint">
          Showing {rows.length.toLocaleString()} of {total.toLocaleString()} components that carry
          anything open
        </span>
        <Pager offset={offset} total={total} onGo={onPage} size={size} />
      </div>
    </>
  );
}

// One row per upstream bump, with what moving it would close.
//
// The other end of the same query the pending-upgrades screen reads: a
// coordinator reads a build and the bumps it is waiting on, and a triager
// reads a bump and the issues it closes. Keyed on the fold, so packages built
// from one source are one row — curl, libcurl4t64 and libcurl3t64 bump once.
//
// **No action column.** The view this replaces put the act in the last column,
// away from the thing it acts on, which is what it was deleted for. The
// package name opens the component, where planning the upgrade lives.
export function ByBump({
  at,
  query,
  offset,
  size,
  onPage,
  cannot,
}: {
  at: { product: string; stream?: string; variant?: string };
  query: Record<string, unknown>;
  offset: number;
  size: number;
  onPage: (offset: number) => void;
  // Filters that are set and that this view cannot apply, by the name their
  // chip carries. Named on the screen rather than dropped: a view that
  // quietly ignored them would widen the list back out while the chips above
  // went on saying they were on.
  cannot: string[];
}) {
  // A bump takes six of the list's filters. The rest ask about a place, a
  // deadline or an assignee, none of which a bump has.
  const first = (value: unknown): string =>
    Array.isArray(value) ? String(value[0] ?? "") : value == null ? "" : String(value);
  const narrowed: Record<string, unknown> = {
    limit: size,
    offset,
    ...(at.stream ? { stream: at.stream } : {}),
    ...(at.variant ? { variant: at.variant } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.exploited ? { exploited: true } : {}),
    ...(first(query.component) ? { component: first(query.component) } : {}),
    ...(query.q ? { q: query.q } : {}),
    ...(first(query.ecosystem) ? { ecosystem: first(query.ecosystem) } : {}),
    ...(first(query.state) ? { state: first(query.state) } : {}),
  };

  const bundles = useQuery({
    queryKey: ["fix-bundles", at, narrowed],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/fix-bundles", {
          params: {
            path: { product: at.product },
            query: narrowed as Record<string, never>,
          },
        }),
      ),
  });

  if (bundles.isPending) return <Loading />;
  if (bundles.isError) {
    return <Failed error={bundles.error} what="What is open could not be read by bump." />;
  }
  const rows = bundles.data?.items ?? [];
  const total = bundles.data?.total ?? 0;
  if (rows.length === 0) {
    return (
      <Empty
        title="Nothing here has a version to move to."
        detail={
          "A bump is a version to move to, so a finding upstream has released nothing " +
          "for is not in one. Everything matching is either fixed already or waiting on " +
          "upstream."
        }
      />
    );
  }

  return (
    <>
      <p className="hint" style={{ margin: "0 0 8px" }}>
        Ordered by what each bump would close. <b>Listed rather than ordered</b> — comparing two
        versions needs a per-ecosystem ordering this does not have, so one package appears once per
        version upstream released and there is no nearest and no latest.
        {cannot.length > 0 && (
          <>
            {" "}
            <span style={{ color: "var(--sev-medium)" }}>
              A bump has no place, no deadline and no assignee, so {cannot.join(", ")}{" "}
              {cannot.length === 1 ? "is" : "are"} not applied here.
            </span>
          </>
        )}
      </p>

      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Bump</th>
              <th>Moving to</th>
              <th>Packages</th>
              <th>Worst</th>
              <th className="num">Would close</th>
              <th>In</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.upstream} ${row.from} ${row.to}`} className="row">
                <td>
                  <span className="id">{row.upstream}</span> {row.exploited && <Exploited when />}
                  <br />
                  <span className="id" style={{ color: "var(--faint)" }}>
                    {row.from}
                  </span>
                </td>
                <td>
                  <span className="id">{row.to}</span>
                </td>
                {/* The packages one bump moves, each opening its own screen —
                    which is where the upgrade is planned. A source package
                    that builds three binaries is one bump and three links. */}
                <td>
                  {(row.components ?? []).map((name) => (
                    <div key={name}>
                      <Link
                        to={`/products/${encodeURIComponent(at.product)}/components/${encodeURIComponent(name)}`}
                        className="linkish id"
                      >
                        {name}
                      </Link>
                    </div>
                  ))}
                </td>
                <td>
                  {row.severity ? (
                    <Severity word={row.severity} />
                  ) : (
                    <span className="hint">—</span>
                  )}
                </td>
                <td className="num">{(row.issues ?? 0).toLocaleString()}</td>
                <td className="hint">
                  {(row.in ?? [])
                    .map((build) => `${build.stream} \u00b7 ${build.variant}`)
                    .join(", ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="filters" style={{ margin: "10px 0 0" }}>
        <span className="hint">
          Showing {rows.length.toLocaleString()} of {total.toLocaleString()} bumps that would close
          something
        </span>
        <Pager offset={offset} total={total} onGo={onPage} size={size} />
      </div>
    </>
  );
}

// Opening a row is a look, not a commitment: what the issue actually says and
// where it sits, without leaving a list of a thousand rows.
export function Peek({
  at,
  vulnerability,
  component,
  version,
  to: link,
}: {
  at: { product: string; stream: string; variant: string };
  vulnerability: string;
  component: string;
  version: string;
  to: string;
}) {
  const detail = useQuery({
    queryKey: ["finding", at, vulnerability, component, version],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}",
          { params: { path: { ...at, vulnerability, component }, query: { version } } },
        ),
      ),
  });

  if (detail.isPending) return <Loading />;
  if (detail.isError) return <Failed error={detail.error} what="This could not be read." />;
  const it = detail.data;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {it?.description ? (
        <p style={{ margin: "8px 0 0", fontSize: "var(--step--1)", maxWidth: "78ch" }}>
          {it.description.slice(0, 420)}
        </p>
      ) : (
        <p className="hint" style={{ margin: 0 }}>
          The report says nothing beyond the identifier.
        </p>
      )}
      <ul className="placelist">
        {(it?.places ?? []).slice(0, 6).map((place) => (
          <li key={place.place}>
            <span className="id">
              {place.consumer
                ? `under ${place.consumer}`
                : place.chain?.[0]?.component
                  ? `under ${place.chain[0].component}`
                  : "nothing records what pulls this in"}
            </span>
            {place.decision != null && <span className="note">decided</span>}
          </li>
        ))}
      </ul>
      <Link to={link} className="linkish">
        Open finding →
      </Link>
    </div>
  );
}

export function Pager({
  offset,
  total,
  onGo,
  size = PAGE,
}: {
  offset: number;
  total: number;
  onGo: (offset: number) => void;
  // How many a page holds, where somebody has chosen. Fifty is 153 pages of
  // one product's findings.
  size?: number;
}) {
  if (total <= size) return null;
  const upto = Math.min(offset + size, total);
  return (
    <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
      <button
        type="button"
        className="chip"
        disabled={offset === 0}
        onClick={() => onGo(Math.max(0, offset - size))}
      >
        Previous
      </button>
      <button
        type="button"
        className="chip"
        disabled={upto >= total}
        onClick={() => onGo(offset + size)}
      >
        Next
      </button>
    </span>
  );
}
// Where the by-component view comes from as a file.
//
// Built here rather than by the generated client because it is a link
// somebody follows, not a request this page makes: the browser fetches it with
// the session it already has. The filters are the ones on screen, so the file
// and the table cannot disagree about what was asked for.
export function componentsFile(
  at: { product: string; stream?: string; variant?: string },
  query: Record<string, unknown>,
  format: string,
): string {
  const asked = new URLSearchParams();
  for (const [key, value] of Object.entries({
    ...query,
    ...(at.stream ? { stream: at.stream } : {}),
    ...(at.variant ? { variant: at.variant } : {}),
  })) {
    // Only what the export takes, and never the paging: a file is every row
    // the filters admit rather than the page that happened to be on screen.
    if (key === "limit" || key === "offset" || value === undefined || value === "") continue;
    if (Array.isArray(value)) {
      for (const one of value) asked.append(key, String(one));
    } else {
      asked.set(key, String(value));
    }
  }
  const text = asked.toString();
  return (
    `/v1/products/${encodeURIComponent(at.product)}/findings/components.${format}` +
    (text ? `?${text}` : "")
  );
}
