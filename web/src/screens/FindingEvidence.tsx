// What is known about the flaw, as against what anybody has said about it.
//
// Where the component sits, what upstream has released, how the scanner
// matched it, what the published references say, and who reported it. None of
// it is a judgment; all of it is what somebody reads before making one.

import { notACredential } from "../ui/noautofill";
import { Fragment, useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { UNPLACED, type Sitting } from "../ui/Covering";

// Every place the component sits at, as the complete chain. A place is the
// component and what directly pulled it in, which is what a decision is
// recorded against.
const CHAINS = 6;

export function Places({ places, build }: { places: Sitting[]; build: string }) {
  const [all, setAll] = useState(false);
  if (places.length === 0) return null;
  const shown = all ? places : places.slice(0, CHAINS);
  return (
    <div className="evblock">
      <h4>Dependency path</h4>
      <div className="tree">
        {shown.map((place, i) => {
          const chain = place.chain ?? [];
          const bare = chain.length <= 1;
          if (bare) {
            return (
              <div key={`${place.place} ${i}`} className="node here">
                <span className="rule">└</span>
                <span className="id">{chain[chain.length - 1]?.component ?? ""}</span>
                <span className="hint">{UNPLACED}</span>
                {place.decision != null && (
                  <Link to={`/decisions/${place.decision}`} className="linkish">
                    decided
                  </Link>
                )}
              </div>
            );
          }
          return (
            <Fragment key={`${place.place} ${i}`}>
              {chain.map((step, depth) => {
                const last = depth === chain.length - 1;
                return (
                  <div
                    key={`${place.place} ${i} ${depth}`}
                    className={`node${last ? " here" : ""}`}
                    style={{ paddingLeft: depth * 18 }}
                  >
                    <span className="rule">└</span>
                    <span className="id">{step.component}</span>
                    {step.version && <span className="ver">{step.version}</span>}
                    {last && place.suppressed && (
                      <span className="state open">suppressed by the build</span>
                    )}
                    {last && place.decision != null && (
                      <Link to={`/decisions/${place.decision}`} className="linkish">
                        decided
                      </Link>
                    )}
                  </div>
                );
              })}
            </Fragment>
          );
        })}
      </div>
      {places.length > CHAINS && (
        <button type="button" className="linkish" onClick={() => setAll(!all)}>
          {all ? `Show ${CHAINS}` : `Show all ${places.length} ways down`}
        </button>
      )}
      {/* The tree is handed the whole chain, not only the name: it opens
          each step on the way down and lands on the component, so arriving
          from a finding shows where it sits rather than the root. */}
      <Link
        to={
          `${build}/components?at=${encodeURIComponent(places[0]?.chain?.at(-1)?.component ?? "")}` +
          `&path=${encodeURIComponent((places[0]?.chain ?? []).map((step) => step.component ?? "").join("\u001f"))}` +
          (places[0]?.chain?.at(-1)?.version
            ? `&version=${encodeURIComponent(places[0]?.chain?.at(-1)?.version ?? "")}`
            : "")
        }
        className="linkish"
      >
        View in dependency tree →
      </Link>
    </div>
  );
}

// Patches first: for somebody deciding whether to backport rather than
// upgrade, the change itself is the answer.
export function References({
  advisory,
  refs,
}: {
  advisory?: string;
  refs: { url?: string; kind?: string }[];
}) {
  const all = advisory ? [{ url: advisory, kind: "advisory" }, ...refs] : refs;
  if (all.length === 0) return null;
  const order: Record<string, number> = { patch: 0, advisory: 1, report: 2, other: 3 };
  const sorted = [...all].sort(
    (a, b) => (order[a.kind ?? "other"] ?? 9) - (order[b.kind ?? "other"] ?? 9),
  );
  return (
    <div className="evblock">
      <h4>References</h4>
      <ul className="refs">
        {sorted.slice(0, 12).map((ref) => (
          <li key={ref.url}>
            <span className={ref.kind === "patch" ? "kind patch" : "kind"}>{ref.kind}</span>{" "}
            <a href={ref.url} target="_blank" rel="noreferrer noopener">
              {(ref.url ?? "").replace(/^https?:\/\//, "")}
            </a>
          </li>
        ))}
      </ul>
      <p className="hint">Patches first.</p>
    </div>
  );
}

// How the scanner reached this, which is the first question anybody asks about
// a distribution's package.
//
// An advisory for the package's own ecosystem counts the release number and
// names the release that carries the fix. An identifier compared against an
// upstream version range cannot see a backported fix at all — the patch does
// not move the upstream version — so it fires whether or not whoever packages
// this has already dealt with it.
//
// The findings list marks these and the screen somebody decides on did not,
// which is the wrong way round: the list is where they are noticed and this is
// where the judgment is made. Nothing is said where the scanner said nothing,
// because unknown is not unconfirmed.
export function HowMatched({
  matched,
  from,
  version,
  inData,
  range,
}: {
  matched?: string;
  from?: string;
  version?: string;
  inData?: string;
  range?: string;
}) {
  if (matched !== "identifier" && matched !== "advisory") return null;
  return (
    <div className="evblock">
      <h4>Match evidence</h4>
      {matched === "identifier" ? (
        <p>
          <b>Not confirmed by a packager.</b> Matched by comparing a published identifier against an
          upstream version range. A distribution backports fixes without moving that version, so
          this may already be fixed in <span className="id">{version}</span> — nobody has confirmed
          either way.
        </p>
      ) : (
        <p>
          <b>Confirmed by a packager.</b> Matched through an advisory for this package's own
          ecosystem, which counts the release number and names the release that carries the fix.
        </p>
      )}
      {/* The evidence for the judgment above rather than a second way of
          making it: the range fired on, read beside the version that ships.
          Where the range names no packaging revision and the version has one,
          the argument is complete in a line and needs no explaining. */}
      {(range || inData) && (
        <p className="mono" style={{ fontSize: "var(--step--1)" }}>
          {range && (
            <>
              matched <b>{range}</b> against <b>{version}</b>
            </>
          )}
          {range && inData && " · "}
          {inData && <>from {inData}</>}
        </p>
      )}
      {from && (
        <p className="hint">
          The data behind it came from{" "}
          <a href={from} target="_blank" rel="noreferrer noopener">
            {from.replace(/^https?:\/\//, "")}
          </a>
          , which is not always where the issue is written up: one issue reached through two
          ecosystems has two answers and the issue itself can hold one.
        </p>
      )}
    </div>
  );
}

// Where to read about this, worked out from the names held here rather than
// handed over by a scanner.
//
// A scanner points at whatever its data carried, which for a package matched
// by identifier is often another distribution's write-up and need not include
// the issue's own record at all. These resolve because an identifier names a
// record and a package identifier names a package.
export function LookItUp({ links }: { links: { url?: string; name?: string }[] }) {
  if (links.length === 0) return null;
  return (
    <div className="evblock">
      <h4>Issue records</h4>
      <ul className="refs">
        {links.map((link) => (
          <li key={link.url}>
            <span className="kind">{link.name}</span>{" "}
            <a href={link.url} target="_blank" rel="noreferrer noopener">
              {(link.url ?? "").replace(/^https?:\/\//, "")}
            </a>
          </li>
        ))}
      </ul>
      <p className="hint">Worked out from the identifiers, not supplied by the scanner.</p>
    </div>
  );
}

// Who is dealing with this, and a way to change it.
//
// On the finding rather than only on the list of what nobody holds. Being able
// to record a judgment about something and not to say who is dealing with it
// is a strange half of the same job — and the screen somebody reads a finding
// on is the one they are on when they decide it needs a person.
//
// It covers every build of the product holding this component, which is what
// assigning means: the same code built several ways is one piece of work.
// Which releases this is meant to be fixed in, and what the scans say became
// of that.
//
// Nothing here is ticked off as done. A build clears when it stops holding the
// issue, which the next scan of it answers; a build chosen and still holding
// it after a scan has run is a missed target, and the scan is evidence against
// the claim rather than a reminder. A build nobody chose says so rather than
// sitting among the outstanding ones — nobody is made to answer the same
// question for six releases, but silence has to read as silence. A link to
// where the work is happening.
//
// **Shown as a link and edited in place.** It is a note rather than a field
// somebody fills in on a form: most of the time there is nothing to say, and a
// text box on every row would be a form that looks unfinished.
//
// Nothing is fetched from it, ever. What it points at is somebody else's
// system, and a tool that fetched a link a person typed would be a request
// forgery waiting for the first internal address.
export function Elsewhere({
  where,
  busy,
  onSet,
}: {
  where: string;
  busy: boolean;
  onSet: (where: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [typed, setTyped] = useState(where);

  if (!editing) {
    return (
      <>
        {" · "}
        {where ? (
          <a href={where} target="_blank" rel="noreferrer noopener" className="linkish">
            where the work is →
          </a>
        ) : null}{" "}
        <button
          type="button"
          className="linkish"
          disabled={busy}
          onClick={() => {
            setTyped(where);
            setEditing(true);
          }}
        >
          {where ? "change" : "link the work"}
        </button>
      </>
    );
  }
  return (
    <span style={{ display: "inline-flex", gap: 5, alignItems: "center" }}>
      <input
        {...notACredential}
        type="text"
        value={typed}
        placeholder="a ticket, a change"
        style={{ width: 220 }}
        aria-label="Where the work is happening"
        onChange={(event) => setTyped(event.target.value)}
      />
      <button
        type="button"
        className="linkish"
        disabled={busy}
        onClick={() => {
          onSet(typed.trim());
          setEditing(false);
        }}
      >
        Save
      </button>
      <button type="button" className="linkish" onClick={() => setEditing(false)}>
        Cancel
      </button>
    </span>
  );
}

export function FixingIn({
  at,
}: {
  at: {
    product: string;
    stream: string;
    variant: string;
    vulnerability: string;
    component: string;
  };
}) {
  const queries = useQueryClient();
  const path =
    "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/fix-targets" as const;
  const plan = useQuery({
    queryKey: ["fix-targets", at],
    queryFn: async () => unwrap(await api.GET(path, { params: { path: at } })),
  });
  const set = useMutation({
    mutationFn: async (builds: { stream: string; variant: string; elsewhere?: string }[]) =>
      unwrap(await api.PUT(path, { params: { path: at }, body: { builds } })),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["fix-targets"] });
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  const items = plan.data?.items ?? [];
  if (plan.isPending) return null;

  // The set is written whole, so a tick sends the whole list rather than one
  // build: intent spans several releases and is decided in one sitting.
  const chosen = items.filter(
    (row) => row.state === "fixing" || row.state === "missed" || row.state === "clear",
  );
  const toggle = (row: { stream?: string; variant?: string; state?: string }) => {
    const named = { stream: row.stream ?? "", variant: row.variant ?? "" };
    const now = chosen.map((each) => ({ stream: each.stream ?? "", variant: each.variant ?? "" }));
    const already = now.some(
      (each) => each.stream === named.stream && each.variant === named.variant,
    );
    set.mutate(
      already
        ? now.filter((each) => !(each.stream === named.stream && each.variant === named.variant))
        : [...now, named],
    );
  };

  const declared = plan.data?.declared ?? 0;
  const clear = plan.data?.clear ?? 0;
  const missed = plan.data?.missed ?? 0;

  return (
    <div className="card">
      <h3>Fixed in</h3>
      {set.error != null && <Failed error={set.error} what="That could not be recorded." />}
      {items.length === 0 ? (
        <p className="hint" style={{ margin: 0 }}>
          No build of this product holds this issue.
        </p>
      ) : (
        <>
          <p className="reading" style={{ marginBottom: 10 }}>
            {declared === 0
              ? "Nobody has said where this will be fixed."
              : plan.data?.resolved
                ? `Fixed in all ${declared} of the releases chosen.`
                : `${clear} of ${declared} chosen ${clear === 1 ? "release is" : "releases are"} clear` +
                  (missed > 0
                    ? `, and ${missed} ${missed === 1 ? "was" : "were"} scanned since and still hold it.`
                    : ".")}
          </p>
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th />
                  <th>Release</th>
                  <th className="num">Open</th>
                  <th>State</th>
                  <th>Chosen</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={`${row.stream}/${row.variant}`}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Fix this in ${row.stream} ${row.variant}`}
                        checked={
                          row.state === "fixing" || row.state === "missed" || row.state === "clear"
                        }
                        disabled={set.isPending || row.state === "retired" || row.state === "gone"}
                        onChange={() => toggle(row)}
                      />
                    </td>
                    <td>
                      {row.stream} <span className="hint">{row.variant}</span>
                    </td>
                    <td className="num">{row.places || "—"}</td>
                    <td>
                      <FixState state={row.state ?? ""} />
                    </td>
                    <td className="hint">
                      {row.declared_by ? `${row.declared_by}, ${on(row.declared_at)}` : "—"}
                      {/* Where the work is happening. Stored and
                          never fetched: a link has no egress at all, which is
                          what makes it available without a deployment first
                          deciding to let anything out. */}
                      {(row.state === "fixing" ||
                        row.state === "missed" ||
                        row.state === "clear") && (
                        <Elsewhere
                          where={row.elsewhere ?? ""}
                          busy={set.isPending}
                          onSet={(where) =>
                            set.mutate(
                              chosen.map((each) => ({
                                stream: each.stream ?? "",
                                variant: each.variant ?? "",
                                ...(each.stream === row.stream && each.variant === row.variant
                                  ? { elsewhere: where }
                                  : {}),
                              })),
                            )
                          }
                        />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="hint" style={{ margin: "10px 0 0" }}>
            Declared intent, not commits. A release clears when the next scan of it stops finding
            the issue &mdash; nothing here is marked done by hand, and a release it has left says so
            whether anybody planned it or not.
          </p>
        </>
      )}
    </div>
  );
}

// Where one release stands, in one word.
export function FixState({ state }: { state: string }) {
  const label: Record<string, string> = {
    missed: "Missed",
    fixing: "Fixing",
    undecided: "Not decided",
    clear: "Clear",
    gone: "Gone",
    retired: "Out of support",
  };
  const means: Record<string, string> = {
    missed: "Chosen, scanned since, and the issue is still there",
    fixing: "Chosen, and no scan has looked since",
    undecided: "Nobody has said whether it will be fixed here",
    clear: "Chosen, and the issue is gone",
    gone: "Nobody chose it, and the issue has left anyway",
    retired: "Out of support, so nothing here is a target",
  };
  const cls: Record<string, string> = {
    missed: "lapsed",
    fixing: "waiting",
    undecided: "open",
    clear: "agreed",
    gone: "agreed",
    retired: "open",
  };
  return (
    <span className={`state ${cls[state] ?? "open"}`} title={means[state]}>
      {label[state] ?? state}
    </span>
  );
}

// Who told us about a flaw, and what else it is called.
//
// **The reporter is the party the timeline is evidenced to.** Received,
// acknowledged, triaged, fixed, disclosed — and the acknowledgment is the step
// that costs nothing and is missed by being nobody's job, so it is a button
// here rather than a field somebody remembers to fill in.
//
// **Acknowledging records that it happened rather than doing it.** What
// reaches a researcher is a mail somebody sends from an address they already
// have; recording it turns "somebody probably replied" into a date.
export function WhoTold({ product, vulnerability }: { product: string; vulnerability: string }) {
  const queries = useQueryClient();
  const [alias, setAlias] = useState("");
  const told = useQuery({
    queryKey: ["report", product, vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{vulnerability}/report", {
          params: { path: { product, vulnerability } },
        }),
      ),
    // Nobody recorded a reporter, which is every flaw we found ourselves.
    retry: false,
  });
  const answered = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/report/acknowledgement", {
          params: { path: { product, vulnerability } },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["report"] }),
  });
  const alsoKnown = useMutation({
    mutationFn: async (name: string) =>
      unwrap(
        await api.PUT("/v1/products/{product}/issues/{vulnerability}/aliases/{alias}", {
          params: { path: { product, vulnerability, alias: name } },
        }),
      ),
    onSuccess: () => {
      setAlias("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  const report = told.data;
  return (
    <div className="card">
      <h3>Reported by</h3>
      {told.isPending ? (
        <Loading />
      ) : !report ? (
        <p className="reading">
          Nobody outside is recorded as having reported this, which is what a flaw we found
          ourselves looks like.
        </p>
      ) : (
        <>
          <p className="reading" style={{ marginBottom: 6 }}>
            <b>{report.reported_by || "Somebody"}</b>
            {report.contact && (
              <>
                {" "}
                · <span className="id">{report.contact}</span>
              </>
            )}
            {report.received && <> · arrived {report.received}</>}
            {report.credit && <> · credited as {report.credit}</>}
          </p>
          {report.acknowledged ? (
            <p className="hint">
              Answered {report.acknowledged.replace("T", " ").slice(0, 16)}
              {report.acknowledged_by && <> by {report.acknowledged_by}</>}.
            </p>
          ) : (
            <div className="alert" style={{ margin: "6px 0 0" }}>
              <strong>Nobody has answered them.</strong>
              <span>
                Prompt acknowledgment is the part of coordinated disclosure a reporter judges, and
                it is the step that costs nothing and is missed by being nobody&rsquo;s job. Send
                them a note, then record it here.
              </span>
              <button
                type="button"
                className="btn"
                style={{ marginLeft: "auto" }}
                disabled={answered.isPending}
                onClick={() => answered.mutate()}
              >
                Mark as answered
              </button>
            </div>
          )}
          {answered.error != null && (
            <Failed error={answered.error} what="That could not be recorded." />
          )}
        </>
      )}

      {/* A CVE assigned later is another name for the same issue.
          Nothing keyed on the issue moves; what changes is that a reader
          searching by the new name finds this, and the advisory carries it. */}
      <div className="field" style={{ marginTop: 12, marginBottom: 0 }}>
        <label htmlFor="also-known">Also known as</label>
        <div style={{ display: "flex", gap: 6 }}>
          <input
            id="also-known"
            type="text"
            value={alias}
            placeholder="CVE-2027-0001"
            onChange={(event) => setAlias(event.target.value)}
          />
          <button
            type="button"
            className="btn quiet"
            disabled={alias.trim() === "" || alsoKnown.isPending}
            onClick={() => alsoKnown.mutate(alias.trim())}
          >
            Record
          </button>
        </div>
        <span className="hint">
          A CVE assigned after we minted our own. Nothing about the finding, the decisions or the
          approvals moves — they are keyed on the issue rather than on what it is called — and the
          issue is filed under the name a reader will look for.
        </span>
        {alsoKnown.error != null && (
          <Failed error={alsoKnown.error} what="That name could not be recorded." />
        )}
      </div>
    </div>
  );
}
