// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { decisionOf, useQueueCount } from "../api/decisions";
import { useApprovable, useHeldReports } from "../api/intake";
import { unwrap } from "../api/queries";
import { counted, heldLine, holding, readsNothing, type Holding } from "../app/families";
import { useOwnWork } from "../app/ownWork";
import {
  allFindingsAt,
  codeFindingAt,
  homeAt,
  incidentsAt,
  productFindingsAt,
  reviewQueueAt,
  uploadsAt,
  type HomeFigures,
} from "../app/routes";
import { scopeQuery, useScope } from "../app/scope";
import type { Who } from "../app/session";
import { Count, known } from "../ui/Count";
import { Failed } from "../ui/Failed";
import { on } from "../ui/when";
import { DependencyFigures } from "./HomeDependencies";
import { SecurityTestingFigures, codeProducts, useCoverages } from "./HomeSecurityTesting";

// The most of a person's own decisions the "sent back" tile reads. What became of
// a decision is derived from its rows rather than stored on them, so there is no
// count to ask for — a page is read and what is on it counted, and the tile
// says so where the page was cut.
const BACK_LIMIT = 200;

// One home page, assembled from what this person holds. The work comes first
// and holds both families: what is theirs, what came back, what waits on them,
// what is in progress, what lapsed. Below it the estate's figures and trends,
// one family at a time: a tab each where the reader holds both, the one they
// hold where they hold one, the tab in the address so a link opens it again.
// The system's own state is at the foot. A reader of no finding in any product
// is shown the deployment's records in place of the estate's figures, beside
// the work they hold.
export function Home({ who }: { who: Who }) {
  const at = useScope();
  const [params] = useSearchParams();
  const counting = at.product
    ? [at.product, at.branch_or_tag, at.variant].filter(Boolean).join(" · ")
    : "all products";
  const dependencies = holding(who, "dependency", at.product);
  const code = holding(who, "code", at.product);
  const shown = figuresShown(who, params.get("figures"));
  const figures = counted(dependencies);

  return (
    <>
      <div className="screen-head">
        <h2>
          {greeting()}, {who.name.replace(/^[a-z]+:/, "")}
        </h2>
        <p>
          {holdings(who)} · counting <span className="id">{counting}</span>
        </p>
      </div>

      <WorkFigures who={who} counting={counting} />

      <div className="panels">
        {readsNothing(who) && (keepsRecords(who) || !who.collaborates) && <Records who={who} />}
        {who.collaborates && <YourCases />}
        <Pending />
        <InProgress me={who.identity} />
        {/* Lapsed decisions are on either family; the lapsed findings line
            counts dependency findings alone. */}
        {(figures || counted(code)) && <Lapsed findings={figures} />}
      </div>

      {shown.strip && (
        <div className="tabs2" role="tablist" aria-label="Figures" style={{ marginTop: 18 }}>
          {FIGURES.map((each) => (
            <Link
              key={each.figures}
              to={homeAt(each.figures)}
              replace
              role="tab"
              className="tab2"
              aria-selected={shown.figures === each.figures}
            >
              {each.label}
            </Link>
          ))}
        </div>
      )}
      {shown.figures === "dependencies" && (
        <DependencyFigures dependencies={dependencies} counting={counting} />
      )}
      {shown.figures === "security-testing" && <SecurityTestingFigures who={who} code={code} />}

      <div className="panels">
        <Status code={counted(code) ? code : undefined} who={who} />
      </div>
    </>
  );
}

const FIGURES: { figures: HomeFigures; label: string }[] = [
  { figures: "dependencies", label: "Dependencies" },
  { figures: "security-testing", label: "Security testing" },
];

// Which family's figures home draws, and whether the strip choosing between
// them is drawn. A strip is for a reader holding both families somewhere; a
// reader holding one sees that one with no strip, and a reader holding
// neither sees no figures. The address names Security testing or nothing.
export function figuresShown(
  who: Who,
  asked: string | null,
): { figures: HomeFigures | undefined; strip: boolean } {
  const dependency = holding(who, "dependency").held !== "nowhere";
  const code = holding(who, "code").held !== "nowhere";
  if (dependency && code) {
    return {
      figures: asked === "security-testing" ? "security-testing" : "dependencies",
      strip: true,
    };
  }
  if (dependency) return { figures: "dependencies", strip: false };
  if (code) return { figures: "security-testing", strip: false };
  return { figures: undefined, strip: false };
}

// The work's figures, over both families. Each names what it counts, because
// the picker narrows them — a tile reading "all products" while a product is
// picked describes the one thing it is not showing.
//
// Each carries what it would say without the scope, so the difference the
// selection makes is on screen rather than inferred. Unscoped the twin is not
// drawn: it would be the same number said twice.
function WorkFigures({ who, counting }: { who: Who; counting: string }) {
  const at = useScope();
  const scope = scopeQuery(at);
  const navigate = useNavigate();

  // Standing records that a product was attacked through an issue. The shelf
  // is unpaged and narrowed record by record, so its length is the count, and
  // the scope is applied here: a record belongs to a product and no build.
  // Asked of every reader: the server narrows it to the records each may be
  // told of, a case collaborator's own case included, and the tile draws
  // only a count above zero.
  const shelf = useQuery({
    queryKey: ["incidents"],
    queryFn: async () => unwrap(await api.GET("/v1/incidents", {})),
  });
  // This person's holdings, and what has come back to them: Home answers
  // "what do I do next" as well as "how much is there".
  // One figure per family, never their sum: a rule at a place and an
  // advisory at a component are different units.
  const own = [
    useOwnWork(who, "dependency", scope, { limit: 1, offset: 0 }),
    useOwnWork(who, "code", scope, { limit: 1, offset: 0 }),
  ];
  // The open vulnerability reports this person and their teams hold. A report
  // belongs to a product and no build, so it is counted beside the findings
  // rather than among them.
  const reports = useHeldReports({ person: "me" }, at.product);
  // Sent back is derived from a decision's rows rather than stored on them, so
  // there is no count to ask the server for: a page is read and what is on it
  // is counted, and the tile says "+" where the page was cut, as the deadline
  // tiles do for the same reason.
  const became = useQuery({
    queryKey: ["home", "became", "me"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/my-decisions", { params: { query: { limit: BACK_LIMIT } } })),
  });
  const queue = useQueueCount(at.product || undefined);
  // The same figures with the scope taken off, so a tile can show what the
  // selection costs rather than leaving somebody to guess at it. Asked only
  // where a scope narrows something: unscoped they would be the same number
  // twice.
  const widely = !!at.product;
  const rulings = useApprovable(at.product || undefined);
  const allRulings = useApprovable();
  const allQueue = useQueueCount(undefined, { enabled: widely });
  const backRows = became.data?.items ?? [];
  const sentBack = backRows.filter((row) => row.happened === "sent-back").length;
  const backCut = (became.data?.total ?? backRows.length) > backRows.length;
  const attacked = (shelf.data?.items ?? []).filter(
    (record) => record.standing && (!at.product || record.product === at.product),
  ).length;
  // The same figure without the scope. Nothing where no scope is
  // selected, because the two would be one number said twice.
  function everywhere(n: number | undefined): React.ReactNode {
    if (!widely || n === undefined) return null;
    return <span className="d">{n.toLocaleString()} all products</span>;
  }

  return (
    <div className="kpis">
      {/* Hers first. What somebody opening this most days has to decide is
          what to pick up, and a count of the estate does not answer it. */}
      {own.map(
        (work) =>
          (work.drawn || work.at.held !== "nowhere") && (
            <button
              key={work.family}
              type="button"
              className="kpi"
              onClick={() => navigate("/assignments")}
            >
              <span className="l">
                {work.family === "code" ? "Code findings" : "Dependency findings"} assigned to you ·{" "}
                {counting}
              </span>
              <span className="n">
                {work.drawn ? (
                  <Count of={work.query}>
                    {() => (work.query.data?.total ?? 0).toLocaleString()}
                  </Count>
                ) : (
                  "—"
                )}
              </span>
              <span className="d">
                {!work.drawn
                  ? heldLine(work.at)
                  : work.family === "code"
                    ? "yours and your teams’"
                    : `yours and your teams’${
                        (reports.data?.total ?? 0) > 0
                          ? `, and ${reports.data?.total?.toLocaleString()} ${reports.data?.total === 1 ? "report" : "reports"}`
                          : ""
                      }`}
              </span>
            </button>
          ),
      )}
      <button
        type="button"
        className={`kpi${sentBack > 0 ? " urgent" : ""}`}
        onClick={() => navigate(reviewQueueAt({ mine: true }))}
      >
        <span className="l">Sent back to you</span>
        <span className="n">
          <Count of={became}>
            {() => `${sentBack.toLocaleString()}${backCut && sentBack > 0 ? "+" : ""}`}
          </Count>
        </span>
        <span className="d">decisions an approver returned</span>
      </button>
      {/* A person's record that a product was attacked, as a count of its
          own beside the feed's. The feed's figure says nothing about this
          product, so the two are never one number. Drawn only where there is
          a record, and counted in records: one is against an issue and a
          product. It opens the shelf narrowed to the product it counted. */}
      {(shelf.isError || attacked > 0) && (
        <button
          type="button"
          className="kpi urgent"
          onClick={() => navigate(incidentsAt(at.product))}
        >
          <span className="l">
            <i style={{ background: "var(--sev-exploited)" }} /> Incidents
          </span>
          <span className="n">
            <Count of={shelf}>{() => attacked.toLocaleString()}</Count>
          </span>
          <span className="d">
            {at.branch_or_tag || at.variant ? `all of ${at.product}` : "recorded attacks"}
          </span>
        </button>
      )}
      <button
        type="button"
        className="kpi"
        onClick={() => navigate(reviewQueueAt({ product: at.product }))}
      >
        <span className="l">
          <i style={{ background: "var(--wait)" }} /> Pending your approval
        </span>
        <span className="n">
          <Count of={[queue, rulings]}>
            {() => ((queue.data?.total ?? 0) + (rulings.data ?? 0)).toLocaleString()}
          </Count>
        </span>
        {everywhere(
          !known([allQueue, allRulings]) || allQueue.data?.total === undefined
            ? undefined
            : allQueue.data.total + (allRulings.data ?? 0),
        ) ?? (
          <span
            className="d"
            title="A decision is made in a product and no finer, so this counts the whole product"
          >
            {at.branch_or_tag || at.variant ? `all of ${at.product}` : "waiting on a second person"}
          </span>
        )}
      </button>
    </div>
  );
}

function greeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

// Whether the reader keeps the deployment's records: an administrator or an
// auditor, whose work the Records panel opens.
function keepsRecords(who: Who): boolean {
  return who.admin || !!who.audits;
}

// The panel standing for the estate's figures for a reader holding no finding
// in any product: an auditor, an administrator with no role on a product, or
// somebody holding a capability alone and collaborating on nothing, whose
// home Your cases fills instead. The deployment's records are what they may
// open, never figures that are zero because none of them is theirs.
function Records({ who }: { who: Who }) {
  const keeps = keepsRecords(who);
  return (
    <div className="panel">
      <header>
        <h3>Records</h3>
      </header>
      <p className="reading">You don&rsquo;t read findings in any product.</p>
      {keeps && (
        <footer>
          <Link to="/audit-log" className="linkish">
            Change history →
          </Link>
          <Link to="/access" className="linkish">
            Access →
          </Link>
          <Link to="/settings" className="linkish">
            Settings →
          </Link>
        </footer>
      )}
    </div>
  );
}

// The cases the reader was brought into and the code findings they were
// granted, each opening the one thing the grant reaches. Drawn only for a
// collaborator, and only where a grant still reaches something: a code
// finding's grant ends with its flaw's disclosure.
function YourCases() {
  const own = useQuery({
    queryKey: ["session", "cases"],
    queryFn: async () => unwrap(await api.GET("/v1/session/me/cases", {})),
  });
  if (own.isPending) return null;
  if (own.isError) {
    return (
      <div className="panel">
        <header>
          <h3>Your cases</h3>
        </header>
        <Failed error={own.error} what="Your cases could not be read." />
      </div>
    );
  }
  const cases = own.data.cases ?? [];
  const codeFindings = own.data.code_findings ?? [];
  if (cases.length + codeFindings.length === 0) return null;
  return (
    <div className="panel">
      <header>
        <h3>Your cases</h3>
      </header>
      <ul>
        {cases.map((each) => (
          <li key={`case ${each.product} ${each.issue}`}>
            <Link className="id" to={productFindingsAt(each.product, { q: each.issue })}>
              {each.issue}
            </Link>{" "}
            <span className="what">in {each.product_name || each.product}</span>
          </li>
        ))}
        {codeFindings.map((each) => (
          <li key={`code ${each.product} ${each.occurrence}`}>
            <Link
              className="id"
              to={codeFindingAt(
                {
                  product: each.product,
                  branch_or_tag: each.branch_or_tag,
                  variant: each.variant,
                },
                each.occurrence,
              )}
            >
              {each.rule}
            </Link>{" "}
            <span className="what">
              code finding at {each.path}, recorded as {each.flaw} in{" "}
              {each.product_name || each.product}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// Said in what the roles let somebody do rather than what they are called.
// A product reached only to administer or audit it is not one they read.
function holdings(who: Who): string {
  if (who.admin) return "You administer this deployment";
  const reach = (who.reach ?? []).filter((each) => each.may_see);
  if (reach.length === 0) {
    return who.audits ? "You audit this deployment" : "You hold no role on a product";
  }
  const triage = reach
    .filter((each) => each.may_triage || each.triages_security_testing)
    .map((each) => each.product);
  const agree = reach.filter((each) => each.may_agree).map((each) => each.product);
  const parts: string[] = [];
  if (triage.length) parts.push(`triage on ${triage.join(", ")}`);
  if (agree.length) parts.push(`approval on ${agree.join(", ")}`);
  if (parts.length === 0) {
    return `You can read ${reach.length} product${reach.length === 1 ? "" : "s"}`;
  }
  return `You hold ${parts.join(" and ")}`;
}

function Pending() {
  const at = useScope();
  const product = at.product ? { product: at.product } : {};
  const queue = useQuery({
    queryKey: ["queue", "home", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/review-queue", { params: { query: { limit: 3, ...product } } })),
  });
  const rulings = useApprovable(at.product || undefined);
  const allRulings = useApprovable();
  const everywhere = useQueueCount(undefined, { enabled: !!at.product });
  const items = queue.data?.items ?? [];

  return (
    <div className="panel">
      <header>
        <h3>Pending your approval</h3>
        <span
          className="eyebrow"
          style={{ marginLeft: "auto" }}
          title={
            at.branch_or_tag || at.variant
              ? "A decision is made in a product and no finer, so this counts the whole product"
              : undefined
          }
        >
          {at.product ? (
            <>
              <Count of={[everywhere, allRulings]}>
                {() => ((everywhere.data?.total ?? 0) + (allRulings.data ?? 0)).toLocaleString()}
              </Count>{" "}
              all products
            </>
          ) : (
            "all products"
          )}
        </span>
        <span className="tally">
          <Count of={[queue, rulings]}>
            {() => ((queue.data?.total ?? 0) + (rulings.data ?? 0)).toLocaleString()}
          </Count>
        </span>
      </header>
      {queue.isError && <Failed error={queue.error} what="This could not be read." />}
      {known([queue, rulings]) && items.length === 0 && !(rulings.data ?? 0) && (
        <p className="reading">Nothing is pending.</p>
      )}
      {(rulings.data ?? 0) > 0 && (
        <p className="reading">
          <Link to="/review-queue#rulings">
            {rulings.data === 1
              ? "1 ruling on vulnerability reports"
              : `${(rulings.data ?? 0).toLocaleString()} rulings on vulnerability reports`}
          </Link>
        </p>
      )}
      <ul>
        {items.map((row) => {
          const decision = decisionOf(row);
          return (
            <li key={decision.key}>
              <span className="id">{decision.title}</span>
              <span className="what">
                {decision.product} · {decision.outcome}
                {decision.records > 1 ? ` · ${decision.records.toLocaleString()} records` : ""}
              </span>
              {typeof row.age_days === "number" && <span className="when">{row.age_days}d</span>}
            </li>
          );
        })}
      </ul>
      <footer>
        <Link to="/review-queue" className="linkish">
          Open the review queue →
        </Link>
      </footer>
    </div>
  );
}

// Each person's holdings. Nothing lists one person's work — only how much
// each person holds — so this is everybody rather than you.
function InProgress({ me }: { me: string }) {
  const at = useScope();
  const product = at.product ? { product: at.product } : {};
  const held = useQuery({
    queryKey: ["home", "holdings", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/assignments", { params: { query: { ...product } } })),
  });
  const everywhere = useQuery({
    queryKey: ["home", "holdings", "all"],
    enabled: !!at.product,
    queryFn: async () => unwrap(await api.GET("/v1/assignments", { params: { query: {} } })),
  });
  // The viewer's own row first, then everybody else's in the order the server
  // gave them. The panel is deliberately about how much each person holds
  // rather than about what one person holds — but reading your own row off a
  // list of colleagues, where it may be below the three this shows, is why
  // somebody who works here had to go somewhere else to find out.
  const rows = held.data?.items ?? [];
  const mine = [
    ...rows.filter((each) => !each.team && each.person === me),
    ...rows.filter((each) => each.team || each.person !== me),
  ];
  const total = mine.reduce((sum, each) => sum + (each.open ?? 0) + (each.reports ?? 0), 0);
  const overdue = mine.reduce((sum, each) => sum + (each.overdue ?? 0), 0);

  return (
    <div className="panel">
      <header>
        <h3>In progress</h3>
        <span
          className="eyebrow"
          style={{ marginLeft: "auto" }}
          title={
            at.branch_or_tag || at.variant
              ? "Work is held per product and no finer, so this counts the whole product"
              : undefined
          }
        >
          {at.product ? (
            <>
              <Count of={everywhere}>
                {() =>
                  (everywhere.data?.items ?? [])
                    .reduce((sum, each) => sum + (each.open ?? 0) + (each.reports ?? 0), 0)
                    .toLocaleString()
                }
              </Count>{" "}
              all products
            </>
          ) : (
            "all products"
          )}
        </span>
        <span className={overdue > 0 ? "tally urgent" : "tally"}>
          <Count of={held}>{() => total.toLocaleString()}</Count>
        </span>
      </header>
      {held.isError && <Failed error={held.error} what="This could not be read." />}
      {known(held) && mine.length === 0 && <p className="reading">Nothing is assigned.</p>}
      <ul>
        {mine.slice(0, 3).map((each) => (
          <li key={`${each.team ? "t" : "p"}:${each.person}`}>
            <span className="id">
              {!each.team && each.person === me ? "you" : each.person_name || each.person}
            </span>
            <span className="what">
              {each.open} open
              {(each.reports ?? 0) > 0 &&
                `, ${each.reports} ${each.reports === 1 ? "report" : "reports"}`}
            </span>
            {(each.overdue ?? 0) > 0 && <span className="when">{each.overdue} overdue</span>}
          </li>
        ))}
      </ul>
      <footer>
        <Link to="/assignments" className="linkish">
          View assignments →
        </Link>
      </footer>
    </div>
  );
}

// A decision the code moved out from under, and a deferral whose date has
// passed, are both somebody having to look again — and both disappear silently
// without somewhere that says so.
function Lapsed({ findings }: { findings: boolean }) {
  // Decisions are listed by product and no finer, so this follows the
  // product of the scope the head names and says when it is not the whole
  // of it.
  const at = useScope();
  const product = at.product ? { product: at.product } : {};
  // Lapsed and expired asked as one question rather than as two lists added
  // together. A deferral that ran out on code that then moved is in both, so
  // the sum is larger than the thing it labels.
  const stopped = useQuery({
    queryKey: ["home", "stopped", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/decision-occurrences", {
          params: { query: { stopped: true, limit: 3, ...product } },
        }),
      ),
  });
  // The two halves, for the two lines that name them. Their totals overlap and
  // are never added: each says how many of its own kind there are, and the
  // figure over the panel comes from the query above. Each is counted from the
  // list its line opens, so the number and the list cannot disagree: the
  // findings a lapsed decision left behind, and the expired deferrals the
  // review queue holds for the reader.
  // Dependency findings, asked only where the reader counts them here.
  const lapsed = useQuery({
    queryKey: ["home", "lapsed", product],
    enabled: findings,
    queryFn: async () =>
      unwrap(
        at.product
          ? await api.GET("/v1/products/{product}/findings", {
              params: { path: { product: at.product }, query: { state: ["lapsed"], limit: 1 } },
            })
          : await api.GET("/v1/findings", {
              params: { query: { state: ["lapsed"], limit: 1 } },
            }),
      ),
  });
  const expired = useQuery({
    queryKey: ["queue", "home", "expired", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/review-queue", {
          params: { query: { reason: "expired-deferral", limit: 0, ...product } },
        }),
      ),
  });

  // The same question with the scope taken off, so the panel can say what the
  // product costs. Decisions narrow by product and no finer, so a branch or tag or a
  // variant in the scope changes nothing here.
  const everywhere = useQuery({
    queryKey: ["home", "stopped", "all"],
    enabled: !!at.product,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/decision-occurrences", {
          params: { query: { stopped: true, limit: 1 } },
        }),
      ),
  });

  const stoppedTotal = stopped.data?.total ?? 0;
  const lapsedTotal = lapsed.data?.total ?? 0;
  const expiredTotal = expired.data?.total ?? 0;
  const allTotal = everywhere.data?.total ?? 0;
  // A read that did not happen is not a count of nothing, and "Nothing has
  // lapsed" over a failed read is a confident zero on the busiest screen there
  // is.
  const unread = stopped.isError || lapsed.isError || expired.isError;

  return (
    <div className="panel">
      <header>
        <h3>Lapsed decisions</h3>
        <span className="eyebrow" style={{ marginLeft: "auto" }}>
          {at.product ? (
            // The one read in this panel that is not part of `unread`,
            // because it answers a different question and a scope with no
            // product never makes it. It has its own three states.
            <>
              <Count of={everywhere}>{() => allTotal.toLocaleString()}</Count> all products
            </>
          ) : (
            "all products"
          )}
        </span>
        <span className={!unread && stoppedTotal > 0 ? "tally urgent" : "tally"}>
          <Count of={findings ? [stopped, lapsed, expired] : [stopped, expired]}>
            {() => stoppedTotal.toLocaleString()}
          </Count>
        </span>
      </header>
      {unread && (
        <Failed
          error={stopped.error ?? lapsed.error ?? expired.error}
          what="Lapsed decisions could not be read."
        />
      )}
      {known(lapsed) && lapsedTotal > 0 && (
        <div className="alert">
          <strong>
            <Link
              to={
                at.product
                  ? productFindingsAt(at.product, { state: "lapsed" })
                  : allFindingsAt({ state: "lapsed" })
              }
            >
              {lapsedTotal.toLocaleString()} {lapsedTotal === 1 ? "finding" : "findings"} with a
              lapsed decision
            </Link>
          </strong>
          <span>The versions they decided about have moved.</span>
        </div>
      )}
      {known(expired) && expiredTotal > 0 && (
        <div className="alert">
          <strong>
            <Link to={reviewQueueAt({ product: at.product, reason: "expired-deferral" })}>
              {expiredTotal.toLocaleString()} expired{" "}
              {expiredTotal === 1 ? "deferral" : "deferrals"}
            </Link>
          </strong>
          <span>The date they were put off until has passed.</span>
        </div>
      )}
      {known([stopped, lapsed, expired]) && stoppedTotal === 0 && (
        <p className="reading">Nothing has lapsed.</p>
      )}
      <footer>
        {/* A lapsed decision is its author's to re-affirm, and this is where the
            reader's own are. */}
        <Link to={reviewQueueAt({ reaffirm: true })} className="linkish">
          Yours to reaffirm →
        </Link>
      </footer>
    </div>
  );
}

// The tool's own health. A build that stops being scanned reports no new
// findings and fails nothing, so it looks healthier than one still being
// scanned; the quiet ones are named, because a name is acted on. Analyzer runs
// stand beside the inventories for a reader of code findings at the scope.
function Status({ who, code }: { who: Who; code?: Holding }) {
  const at = useScope();
  const scope = scopeQuery(at);
  const coverages = useCoverages(code ? codeProducts(who, at.product) : [], at);
  const series = coverages.flatMap((each) => each.data?.items ?? []);
  const lastRun = series.reduce<string>(
    (newest, item) =>
      item.last_arrived && item.last_arrived > newest ? item.last_arrived : newest,
    "",
  );
  const quietSeries = series.filter((item) => item.quiet).length;
  const unreadRuns = coverages.find((each) => each.isError);
  const scanning = useQuery({
    queryKey: ["home", "last-uploads", scope],
    queryFn: async () => unwrap(await api.GET("/v1/last-uploads", { params: { query: scope } })),
  });
  const builds = scanning.data?.items ?? [];
  // The rows in hand, for the three this names. The figures below come from
  // the response instead: the server counts them across the whole answer and
  // cuts the page afterwards. A build out of support or out of use belongs on
  // neither side of a coverage figure, because silence there is expected, and
  // the covered side is the server's own count of builds scanned and not
  // quiet — the figure the last upload per build report shows under the same
  // name.
  const quiet = builds.filter((b) => b.quiet);
  const unsupported = scanning.data?.unsupported ?? 0;
  const retired = scanning.data?.retired ?? 0;
  const live = (scanning.data?.total ?? 0) - unsupported - retired;
  const scanned = scanning.data?.scanned ?? 0;
  const quietTotal = scanning.data?.quiet ?? 0;
  // The most recent arrival across every build, which is what the line says.
  // The first row that has one is not it: this list is ordered longest-silent
  // first, so the first match is among the oldest.
  const last = builds.reduce<string>(
    (newest, build) =>
      build.last_received_at && build.last_received_at > newest ? build.last_received_at : newest,
    "",
  );
  const whole = !!(at.product && at.branch_or_tag && at.variant);

  return (
    <div className="panel">
      <header>
        <h3>System status</h3>
      </header>
      {scanning.isError && (
        <Failed error={scanning.error} what="The last upload per build could not be read." />
      )}
      {unreadRuns && (
        <Failed error={unreadRuns.error} what="The analyzer runs could not be read." />
      )}
      {quiet.slice(0, 3).map((build) => (
        <div
          className="alert"
          key={`${build.product}\u0000${build.branch_or_tag}\u0000${build.variant}`}
        >
          <strong>
            {build.product} · {build.branch_or_tag} · {build.variant}: no inventory
            {build.last_received_at ? ` for ${build.quiet_days} days` : " ever"}
          </strong>
          <span>
            {build.last_received_at
              ? "Nothing has failed — nothing has arrived."
              : `Declared ${build.quiet_days} days ago.`}
          </span>
        </div>
      ))}
      {quietTotal > 3 && <p className="hint">and {(quietTotal - 3).toLocaleString()} more.</p>}
      <ul>
        <li>
          <span className="what">Builds being scanned</span>
          <span className="when">
            <Count of={scanning}>
              {() => `${scanned.toLocaleString()} of ${live.toLocaleString()}`}
            </Count>
          </span>
        </li>
        <li>
          <span className="what">Last inventory received</span>
          <span className="when">
            <Count of={scanning}>{() => on(last) || "never"}</Count>
          </span>
        </li>
        <li>
          <span className="what">Quiet after</span>
          <span className="when">
            <Count of={scanning}>{() => `${scanning.data?.quiet_after_days ?? "—"} days`}</Count>
          </span>
        </li>
        {code && (
          <>
            <li>
              <span className="what">Last analyzer run received</span>
              <span className="when">
                <Count of={coverages}>{() => on(lastRun) || "never"}</Count>
              </span>
            </li>
            <li>
              <span className="what">Analyzer series gone quiet</span>
              <span className="when">
                <Count of={coverages}>{() => quietSeries.toLocaleString()}</Count>
              </span>
            </li>
          </>
        )}
      </ul>
      {whole && (
        <footer>
          <Link
            to={uploadsAt({
              product: at.product ?? "",
              branch_or_tag: at.branch_or_tag ?? "",
              variant: at.variant ?? "",
            })}
            className="linkish"
          >
            View uploads →
          </Link>
        </footer>
      )}
    </div>
  );
}
