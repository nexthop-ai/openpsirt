// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useApprovable } from "../api/intake";
import { useQueueCount } from "../api/decisions";
import { notACredential } from "../ui/noautofill";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { initials } from "../ui/initials";
import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { TO_THE_TOP, useTopOnArrival } from "./arrival";
import { findingsPath, useScope } from "./scope";
import {
  vulnerabilityReportsAt,
  uploadsAt,
  branchOrTagAt,
  componentsAt,
  productAt,
  codeFindingsAt,
  codeFindingsAcrossAt,
  issueAt,
  componentSearchAt,
  branchesAndTagsAt,
  dependenciesAt,
  plannedUpgradesAt,
  variantsAt,
} from "./routes";
import { asAsked, listQuery } from "../screens/list";
import { unownedAt, useUnowned } from "../screens/unowned";
import { folded, fold } from "./rail";
import { signedOutBy, signOut } from "./session";
import { counted, heldLine, holding, readsUndisclosed } from "./families";
import { Scope } from "./Scope";
import { codeTrendAt } from "../screens/codeTrend";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Notices } from "../ui/Notices";
import { Icon } from "../ui/Icons";
import { useReseed } from "../ui/reseed";
import { UploadDrawer } from "../ui/Upload";
import {
  LOOKS,
  applyLook,
  chosenLook,
  clearLook,
  followSystem,
  systemLook,
  type Look,
} from "./look";
import type { Who } from "./session";
import { useClickAway } from "../ui/away";

// The Dependency findings entry's badge, asked as the list itself asks it: the
// list writes narrowings of its own into a silent address, so a total counted
// without them disagrees with the list it opens.
const OPEN_QUERY = listQuery(asAsked(new URLSearchParams(), "issues"));

// The frame the restyled mockup settled on: a rail down the side carrying the
// brand and the entries grouped by workflow, a bar across the top carrying
// what you are looking at, a way to find things, a way to upload, what is
// waiting on you, and who you are; the screen in the rest.
//
// The scope is the bar's, and every entry answers for it: an entry bound to
// one build declines until one is picked, and says why.
export function Shell({ who, children }: { who: Who; children: ReactNode }) {
  const { product, branch_or_tag: branchOrTag, variant } = useScope();
  const whole = !!(product && branchOrTag && variant);
  // Reading reports and disclosure deadlines takes reading undisclosed work;
  // the server narrows both to products where the reader reads it.
  const undisclosedAnywhere = readsUndisclosed(who);
  const reportsHere = !!product && readsUndisclosed(who, product);
  // A code finding is security testing work, held as the code family.
  const codeFindingsAnywhere = holding(who, "code").held !== "nowhere";
  const codeFindingsHere = product ? holding(who, "code", product) : undefined;
  // Dependency findings, across products and at the product picked. Held
  // nowhere, the entries and the tab that open them are absent; held elsewhere,
  // the entry declines and its count is not asked, so no zero stands for work
  // the reader cannot see.
  const dependencies = holding(who, "dependency");
  const dependenciesAnywhere = dependencies.held !== "nowhere";
  const dependenciesHere = product ? holding(who, "dependency", product) : dependencies;
  // Recording a flaw is triage at the visibility it is recorded at.
  const recordsAnywhere = (who.reach ?? []).some((each) => each.may_hide || each.triages_public);
  const build = whole ? { product, branch_or_tag: branchOrTag, variant } : undefined;
  const [uploading, setUploading] = useState(false);
  // On a narrow screen the rail is a panel that opens from a menu control. The
  // tab bar carries the three places somebody reviews and responds from , and
  // everything else is one tap further rather than absent.
  const [menu, setMenu] = useState(false);
  // The groups folded away, kept in the browser like the look: it
  // changes what one person sees and nothing anybody else is shown.
  const [shut, setShut] = useState<Set<string>>(() => folded());
  function toggleGroup(name: string) {
    setShut((was) => {
      const next = new Set(was);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      fold(next);
      return next;
    });
  }
  const { pathname } = useLocation();
  // The panel is about the screen somebody is leaving, so arriving on another
  // one shuts it.
  useReseed(pathname, () => setMenu(false));
  useTopOnArrival();
  useEffect(() => {
    if (!menu) return;
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") setMenu(false);
    }
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [menu]);

  // The counts on the rail.
  const queue = useQueueCount();
  // Rulings on vulnerability reports waiting for this reader, which sit in the
  // same queue as the decisions.
  const approvable = useApprovable();
  // Work nobody holds, one badge per family, across every product a reader
  // can see, like the entry they sit beside and unlike the scoped count below:
  // what the entry opens names no product.
  const unowned = useUnowned(who);
  const unownedOpens = unownedAt(unowned);
  // Counted for whatever is selected rather than only for a whole build : the
  // entry beside this number opens the list that produced it, and a rail that
  // goes quiet the moment somebody widens the scope is one that looks broken
  // rather than one that declines.
  const open = useQuery({
    queryKey: ["findings", "count", product, branchOrTag, variant],
    enabled: !!product && counted(dependenciesHere),
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: {
            path: { product: product ?? "" },
            query: {
              ...OPEN_QUERY,
              limit: 1,
              ...(branchOrTag ? { branch_or_tag: branchOrTag } : {}),
              ...(variant ? { variant } : {}),
            },
          },
        }),
      ),
  });

  return (
    <div className="app">
      <div className="chrome">
        <button
          type="button"
          className="menubtn"
          aria-label={menu ? "Close the menu" : "Open the menu"}
          aria-expanded={menu}
          onClick={() => setMenu(!menu)}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 7h16M4 12h16M4 17h16" />
          </svg>
        </button>
        <Scope />
        <span className="spacer" />
        <Search />
        <button
          type="button"
          className="topact"
          title="Upload an inventory for any declared build"
          onClick={() => setUploading(true)}
        >
          <Icon name="upload" />
          <span>Upload</span>
        </button>
        <Notices />
        <Me who={who} />
      </div>

      {menu && <div className="railscrim" onClick={() => setMenu(false)} />}
      <nav className={menu ? "rail open" : "rail"}>
        <Link to="/" className="brand" style={{ textDecoration: "none" }}>
          {/* The horizontal lockup, rather than the mark beside the name typed
              out again. The rail is dark under both themes, so the dark
              artwork is the right one in both: the light lockup's "Open" is
              #0d2138 and all but vanishes against --side-bg.

              What the artwork says at this size: the name lands at 16.6px,
              which is where the typed version sat, and the strapline inside
              it lands near 3.7px, which is texture rather than text. No
              scaling fixes that second part — twenty-six letterspaced
              characters across 192px cap out around 6px whatever the canvas
              does — so the alt text is what carries the sentence. */}
          <img
            className="wordmark"
            src="/brand/logo-wide-dark.svg"
            alt="OpenPSIRT — Product Security Incident Response & Triage"
            width={192}
            height={66}
          />
        </Link>

        {/* The rail by workflow: the work waiting, then where somebody looks
            into it, then answering people outside, then the reports, then
            setting up. The component is the hub every screen links into, and
            no group is built around it. */}
        <Group name="work" label="Work" shut={shut} onToggle={toggleGroup} />
        {!shut.has("work") && (
          <>
            <Rail to="/" end icon="home" label="Home" />
            <Rail
              to="/review-queue"
              icon="inbox"
              label="Review queue"
              count={
                queue.data?.total === undefined
                  ? undefined
                  : queue.data.total + (approvable.data ?? 0)
              }
              unread={queue.isError || approvable.isError}
              unit="waiting for your approval"
            />
            {(dependenciesAnywhere || codeFindingsAnywhere) && (
              <Rail
                to={unownedOpens.to}
                mark={unownedOpens.mark}
                icon="nobody"
                label="Unassigned"
                counts={[
                  {
                    count: unowned.dependency.count.data?.total,
                    unread: unowned.dependency.count.isError,
                    unit: withLine(
                      "dependency findings nobody holds and nobody has decided",
                      heldLine(dependencies),
                    ),
                  },
                  {
                    count: unowned.code.count.data?.total,
                    unread: unowned.code.count.isError,
                    unit: "code findings nobody holds",
                  },
                ]}
                quiet
              />
            )}
            <Rail to="/assignments" icon="people" label="Assignments" />
          </>
        )}
        <Group name="investigate" label="Investigate" shut={shut} onToggle={toggleGroup} />
        {!shut.has("investigate") && (
          <>
            {/* The components a name matches, each opening the component
                screen where both families meet. For a reader of either
                family somewhere, since the search covers only products where
                they read one. */}
            {(dependenciesAnywhere || codeFindingsAnywhere) && (
              <Rail to={componentsAt()} icon="component" label="Components" />
            )}
            {/* An entry that opens on one build declines while none is picked,
              rather than opening on a scope that means nothing, and says why.
              Findings needs nothing: it answers for whatever the picker has
              selected, and for every product a reader can see when nothing
              is. */}
            {dependenciesAnywhere && (
              <Rail
                to={findingsPath({ product, branch_or_tag: branchOrTag, variant })}
                icon="bug"
                label="Dependency findings"
                hint="SCA"
                count={open.data?.total}
                unread={open.isError}
                unit={withLine(
                  "findings — an issue at a component, counted once per build",
                  heldLine(dependenciesHere),
                )}
                quiet
                needs={dependenciesHere.held !== "elsewhere"}
                why={heldLine(dependenciesHere)}
              />
            )}
            {/* Code findings from security testing, shown to somebody who
              reads security testing material anywhere: a product's, opening
              on the branch and variant picked where both are, and with no
              product picked, every product's they read. */}
            {codeFindingsAnywhere && (
              <Rail
                to={
                  product
                    ? codeFindingsAt(
                        product,
                        whole ? { branch_or_tag: branchOrTag, variant } : undefined,
                      )
                    : codeFindingsAcrossAt()
                }
                icon="triage"
                label="Security testing"
                needs={!codeFindingsHere || counted(codeFindingsHere)}
                why={codeFindingsHere ? heldLine(codeFindingsHere) : undefined}
              />
            )}
            <Rail
              to={build ? dependenciesAt(build) : ""}
              icon="tree"
              label="Dependencies"
              needs={whole}
            />
            {/* Reading how a product goes: its page, naming every build with
              what is open in each, or with a branch or tag picked, that
              line's own page, which for a tag is its release. The catalog's
              lists stay under Manage. */}
            <Rail
              to={
                product
                  ? branchOrTag
                    ? branchOrTagAt(product, branchOrTag)
                    : productAt(product)
                  : ""
              }
              end
              icon="release"
              label="Builds and releases"
              needs={!!product}
              why="Pick a product"
            />
            <Rail to={build ? uploadsAt(build) : ""} icon="scan" label="Uploads" needs={whole} />
            {/* What this build is waiting on, which is the product's planned
              upgrades read from the other end. */}
            <Rail
              to={build ? plannedUpgradesAt(build) : ""}
              icon="flag"
              label="Planned upgrades"
              needs={whole}
            />
          </>
        )}
        <Group name="respond" label="Respond" shut={shut} onToggle={toggleGroup} />
        {!shut.has("respond") && (
          <>
            {/* What people outside have sent a product. Only for somebody who may
              read vulnerability reports somewhere, and it needs a product
              picked because a product's reports belong to it. */}
            {undisclosedAnywhere && (
              <Rail
                to={product ? vulnerabilityReportsAt(product) : ""}
                icon="letter"
                label="Vulnerability reports"
                needs={!!product && reportsHere}
                why={
                  product
                    ? "You can't read vulnerability reports in this product"
                    : "Pick a product"
                }
              />
            )}
            {/* What is running out of embargo. The list is itself a disclosure,
              so a product somebody may not read undisclosed work in contributes
              nothing to it — the server narrows it. */}
            {undisclosedAnywhere && (
              <Rail to="/disclosure-deadlines" icon="bell" label="Disclosure deadlines" />
            )}
            {/* Incidents: the standing attacks and the response windows
              counted from each. Beside Disclosure deadlines because both are dates with
              somebody outside waiting on them, which no remediation deadline
              has. Offered to everybody: the shelf answers each reader with
              what they may be told of, a collaborator's own case included,
              which is one of the two ways a collaborator reaches their case. */}
            <Rail to="/incidents" icon="shield" label="Incidents" />
            {/* What this deployment has said about its own flaws. Beside
              Disclosure deadlines because an embargo reaching its date is one
              of the three things an advisory gets written for. */}
            <Rail to="/advisories" icon="advisory" label="Published advisories" />
            {/* Its own screen rather than an action on the findings list: what is
              being recorded is precisely what is *not* in that list, and it asks
              more than a control beside a table has room for. It needs no
              product picked, because the screen asks for one. */}
            {recordsAnywhere && <Rail to="/record-a-flaw" icon="record" label="Record a flaw" />}
          </>
        )}
        <Group name="reports" label="Reports" shut={shut} onToggle={toggleGroup} />
        {!shut.has("reports") && (
          <>
            {/* The catalog of named reports, and the one place a report is
              built by hand. A report spans whatever the picker has selected,
              up to every product a reader can see. Offered to everybody: the
              coverage reports answer what is scanned to anybody who sees a
              build, and a report counting a family the reader does not hold
              says so itself. */}
            <Rail to="/analytics" icon="chart" label="Analytics" />
            {/* Whether security testing work is shrinking, for the readers of
              it. A trend is one product's, since a series belongs to one, so
              it declines until a product is picked. */}
            {codeFindingsAnywhere && (
              <Rail
                to={product ? codeTrendAt() : ""}
                icon="pulse"
                label="Code findings over time"
                needs={!!product && (!codeFindingsHere || counted(codeFindingsHere))}
                why={
                  !product
                    ? "Pick a product"
                    : codeFindingsHere
                      ? heldLine(codeFindingsHere)
                      : undefined
                }
              />
            )}
            {/* The audit log of what was decided, asked about a period rather
              than a build. */}
            <Rail to="/audit-log" icon="ledger" label="Audit log" />
          </>
        )}
        <Group name="manage" label="Manage" shut={shut} onToggle={toggleGroup} />
        {!shut.has("manage") && (
          <>
            {/* The catalog, whole and in order: a product, then the branches and
              tags under it, then what those are built as. The two below need a
              product picked, which somebody arriving with nothing chosen picks
              in the bar above. */}
            <Rail to="/products" end icon="box" label="Products" />
            <Rail
              to={branchesAndTagsAt(product ?? "")}
              end
              icon="branch"
              label="Branches and tags"
              needs={!!product}
              why="Pick a product first"
            />
            <Rail
              to={variantsAt(product ?? "")}
              icon="layers"
              label="Variants"
              needs={!!product}
              why="Pick a product first"
            />
            {/* Who holds work as a queue rather than as a person. Beside
              users and roles because "who is here" and "who is on which team"
              are the same question asked twice, and belonging to a team grants
              nothing. */}
            {who.admin && <Rail to="/teams" icon="teams" label="Teams" />}
            {/* Who holds what, which the audit permission is largely for.
              The screen already degrades for a reader who cannot grant. */}
            {(who.admin || who.audits) && <Rail to="/access" icon="roles" label="Access" />}
            {/* Assignment without a person doing it, by an assignment rule.
              Under Manage because it is something set up once rather than worked
              at, and called what it does: the act it automates is assignment. */}
            <Rail to="/auto-assignment" icon="route" label="Auto-assignment" />
            {(who.admin || who.audits) && <Rail to="/settings" icon="gear" label="Settings" />}
            {/* What the deployment itself is doing. Beside settings because
              both are about the deployment rather than about what it found —
              and an operator's rather than an auditor's: what a worker
              reported can quote what the job was about, and a destination's
              address is a credential for two of the services it names. */}
            {who.admin && <Rail to="/system" icon="pulse" label="System" />}
          </>
        )}
      </nav>

      <main className="stage">
        {children}
        {/* Whose tool this is, at the foot of the page rather than in the
            chrome: it belongs to every screen and interrupts none of them.
            The year comes from the reader's clock, so it does not quietly
            become wrong in January. */}
        <footer className="colophon">
          <span>© {new Date().getFullYear()} Nexthop Systems Inc.</span>
          <span aria-hidden>·</span>
          {/* What is running, read from the deployment rather than from
              anything built into this page: an interface and a server that
              disagree about the version is the report nobody can act on
. */}
          <Version />
          <span aria-hidden>·</span>
          {/* An outbound link, which is the only one in the interface: nothing
              here fetches from anywhere, and a link somebody chooses to follow
              is not a fetch. */}
          <a href="https://nexthop.ai" target="_blank" rel="noreferrer noopener">
            nexthop.ai
          </a>
        </footer>
      </main>

      {/* A narrow screen has no rail. The three places somebody reviews and
          responds from are a tab bar instead, from the rail's Work and
          Investigate groups: home, the reader's findings, and the queue. The
          findings tab is the family they read, dependency findings first;
          for a reader of code findings alone it opens the Security testing
          queue, and for a reader of neither it is absent. */}
      <nav className="tabbar">
        <NavLink to="/" end>
          Home
        </NavLink>
        {dependenciesAnywhere ? (
          <NavLink to={findingsPath({ product, branch_or_tag: branchOrTag, variant })}>
            Findings
          </NavLink>
        ) : (
          codeFindingsAnywhere && (
            <NavLink
              to={
                product && (!codeFindingsHere || counted(codeFindingsHere))
                  ? codeFindingsAt(
                      product,
                      whole ? { branch_or_tag: branchOrTag, variant } : undefined,
                    )
                  : codeFindingsAcrossAt()
              }
            >
              Code findings
            </NavLink>
          )
        )}
        <NavLink to="/review-queue">Queue</NavLink>
        <button type="button" aria-expanded={menu} onClick={() => setMenu(!menu)}>
          Menu
        </button>
      </nav>

      <UploadDrawer open={uploading} onClose={() => setUploading(false)} />
    </div>
  );
}

// A badge's unit, with the line saying which findings it counts where the
// reader reads only some of them.
function withLine(unit: string, line: string): string {
  return line ? `${unit}. ${line}` : unit;
}

// One count beside a rail entry.
type Badge = { count?: number; unread?: boolean; unit?: string };

function BadgeOf({ badge: { count, unread, unit }, quiet }: { badge: Badge; quiet?: boolean }) {
  if (unread) {
    return (
      <span
        className="count quiet"
        title="This count could not be read"
        aria-label="This count could not be read"
      >
        —
      </span>
    );
  }
  if (typeof count !== "number" || count <= 0) return null;
  return (
    <span
      className={quiet ? "count quiet" : "count"}
      title={unit ? `${count.toLocaleString()} ${unit}` : undefined}
      aria-label={unit ? `${count.toLocaleString()} ${unit}` : undefined}
    >
      {count.toLocaleString()}
    </span>
  );
}

// The version running here.
function Version() {
  const version = useQuery({
    queryKey: ["version"],
    queryFn: async () => unwrap(await api.GET("/v1/version", {})),
    staleTime: 60 * 60 * 1000,
    retry: false,
  });
  if (!version.data) return null;
  return (
    <span title={version.data.commit ?? undefined}>
      <span className="id">{version.data.version}</span>
    </span>
  );
}

function Rail({
  to,
  mark,
  icon,
  label,
  hint,
  count,
  unread,
  unit,
  counts,
  quiet,
  end,
  needs = true,
  why = "Pick a product, a branch and a variant",
}: {
  to: string;
  // The filters this entry's address carries, where it carries any. The router
  // matches a path and never a query, so an entry that opens one narrowing of
  // a shared screen reads as the screen somebody is on for every other
  // narrowing of it too.
  mark?: string;
  icon: string;
  label: string;
  // What the entry is, on hover, where the label alone leaves it unclear.
  hint?: string;
  count?: number;
  // An unreadable count. A badge is gated on being above zero,
  // so a failed or refused count draws exactly like "nothing waiting" — which
  // on the review queue is the answer somebody acts on by not looking.
  unread?: boolean;
  // The thing the badge counts. The rail has room for a number and not for a
  // noun, so the unit rides on the title and on what a screen reader is given
  // — enough that "Unassigned 7,616" beside "5,803 open issues" stops being
  // two numbers that look like they should agree.
  unit?: string;
  // Several badges, one per thing counted, where an entry opens more than one
  // list: each family's count stands apart, never summed.
  counts?: Badge[];
  quiet?: boolean;
  end?: boolean;
  needs?: boolean;
  why?: string;
}) {
  const { pathname, search } = useLocation();
  if (!needs) {
    return (
      <button type="button" className="nav" disabled title={why}>
        <Icon name={icon} />
        {label}
      </button>
    );
  }
  // NavLink marks the active entry with aria-current itself, which is what the
  // rail styles key off — the state is announced to a screen reader and drawn
  // from the same fact, rather than a class that only one of them can see.
  //
  // An entry carrying filters says so for itself, because the router's answer
  // is about the path alone: `aria-current` there is the same fact, decided by
  // asking whether the address in the bar still carries what this entry asks
  // for.
  const body = (
    <>
      <Icon name={icon} />
      {label}
      {(counts ?? [{ count, unread, unit }]).map((badge, i) => (
        <BadgeOf key={i} badge={badge} quiet={quiet} />
      ))}
    </>
  );
  if (mark !== undefined) {
    const asked = new URLSearchParams(search);
    const here =
      pathname === to.split("?")[0] &&
      [...new URLSearchParams(mark)].every(([key, value]) => asked.getAll(key).includes(value));
    return (
      <Link
        to={to}
        state={TO_THE_TOP}
        className="nav"
        title={hint}
        aria-current={here ? "page" : undefined}
      >
        {body}
      </Link>
    );
  }
  return (
    <NavLink to={to} state={TO_THE_TOP} end={end} className="nav" title={hint}>
      {body}
    </NavLink>
  );
}

// Finding a component or an issue from anywhere. It is the findings list's own
// search, reached without going there first.
//
// It asks at whatever scope is chosen, which is the product as readily as a
// single build. Were it disabled unless all three were picked, the most common
// question a PSIRT is asked — where is this advisory in what we ship — could
// not be typed at all without a variant chosen first, and would answer nothing
// when it could, matching the term against component names alone.
//
// An issue name goes to the issue, wherever it sits, and needs no
// product picked: "a critical just landed in openssl — which of our products
// ship an affected version" is the question, and it spans products by
// construction. Anything else searches what is shipped, at whatever the
// picker has selected — and across every product a reader can see where it has
// selected nothing, which is the same list at its widest address.
//
// The choice between the two is decided by asking: a term that resolves to an
// issue goes to the issue page, and everything else falls through to the list.
// Guessing from the shape of the text would be a second, worse copy of the
// server's own name resolution — one that is wrong about every identifier a
// deployment mints for itself.
function Search() {
  const navigate = useNavigate();
  const [typed, setTyped] = useState("");
  const [looking, setLooking] = useState(false);
  // Said under the box when the lookup did not happen. A read that failed is
  // not "no such issue", and falling through to the component search sent
  // somebody to a narrowed findings list as though their issue did not exist.
  const [unread, setUnread] = useState(false);
  const box = useRef<HTMLInputElement>(null);

  // "/" focuses it, unless somebody is already typing somewhere.
  useEffect(() => {
    function key(event: KeyboardEvent) {
      const tag = (document.activeElement?.tagName ?? "").toUpperCase();
      if (event.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(tag)) {
        event.preventDefault();
        box.current?.focus();
      }
    }
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, []);

  return (
    <form
      className="topsearch"
      onSubmit={(event) => {
        event.preventDefault();
        const term = typed.trim();
        if (term === "" || looking) return;
        setLooking(true);
        setUnread(false);
        void api
          .GET("/v1/issues/{issue}", {
            params: { path: { issue: term }, query: { limit: 1 } },
          })
          .then((answer) => {
            setLooking(false);
            if (answer.data && answer.data.total > 0) {
              navigate(issueAt(term));
              return;
            }
            // The route answers an issue nobody here carries with an empty
            // list, so only a missing answer is a read that did not happen. A
            // 500 or a 503 treated as an absence is a wrong answer with a right
            // answer's confidence.
            if (!answer.data) {
              setUnread(true);
              return;
            }
            // Not an issue anybody here carries, so it is a component
            // search: the components it names in the picker's selection,
            // each with both families' counts, which lead to the component
            // screen. With no product picked it is every product the reader
            // reads.
            navigate(componentSearchAt(term));
          })
          .catch(() => {
            setLooking(false);
            setUnread(true);
          });
      }}
    >
      <Icon name="search" />
      {/* A lone text box inside a form is the shape a password manager guesses
          hardest at, and this one is on every screen. */}
      <input
        ref={box}
        {...notACredential}
        type="text"
        value={typed}
        placeholder="Find an issue, or a component…"
        aria-label="Find an issue, or a component"
        onChange={(event) => setTyped(event.target.value)}
      />
      <kbd>/</kbd>
      {unread && (
        <span className="hint" role="status" style={{ color: "var(--sev-high)" }}>
          could not be looked up
        </span>
      )}
    </form>
  );
}

// A heading that folds the entries under it away.
//
// A heading rather than a control was right while the rail fit; at
// twenty-four entries it does not, and something has to give. This is the
// thing that gives, because a group is the unit somebody stops using for a
// while — nobody declares a variant and grants a role in the same minute as
// they triage.
function Group({
  name,
  label,
  shut,
  onToggle,
}: {
  name: string;
  label: string;
  shut: Set<string>;
  onToggle: (name: string) => void;
}) {
  const open = !shut.has(name);
  return (
    <button
      type="button"
      className="group"
      aria-expanded={open}
      title={open ? `Fold ${label} away` : `Show ${label}`}
      onClick={() => onToggle(name)}
    >
      <span className="caret" aria-hidden>
        {open ? "\u25be" : "\u25b8"}
      </span>
      <span className="what">{label}</span>
    </button>
  );
}

// The signed-in person, with the look menu and the way out underneath.
function Me({ who }: { who: Who }) {
  const [open, setOpen] = useState(false);
  // A sign-out in flight, and one the server did not complete, which keeps
  // the page and offers it again.
  const [leaving, setLeaving] = useState(false);
  const [stuck, setStuck] = useState(false);
  // The choice made, and the machine's own answer. They differ for somebody who
  // has chosen nothing: the operating system is answering, and the menu has to
  // show which of the two that came out as while still marking the choice as
  // unmade. What is drawn is the one worked out from the two.
  const [pinned, setPinned] = useState<Look | null>(() => chosenLook());
  const [system, setSystem] = useState<Look>(() => systemLook());
  const look = pinned ?? system;
  const box = useRef<HTMLDivElement>(null);

  // While nothing is pinned, a machine that turns dark at sunset turns this
  // dark at sunset.
  useEffect(() => followSystem(setSystem), []);

  // Choosing is the only thing that moves the look, so the document is written
  // where the choice is made. The attribute is already on the element before
  // anything paints — the page stamps it — so there is nothing to apply on
  // arrival, and an effect that re-applied it was writing what was there.
  function choose(next: Look | null) {
    setPinned(next);
    if (next) applyLook(next);
    else clearLook();
  }

  useClickAway(box, open, () => setOpen(false));

  return (
    <div className="me" ref={box}>
      <span className="hint">
        <b>{who.name.replace(/^[a-z]+:/, "")}</b>
      </span>
      <button
        type="button"
        className="who"
        aria-expanded={open}
        aria-label="You"
        title={who.identity}
        onClick={() => setOpen(!open)}
      >
        {initials(who.name)}
      </button>
      {open && (
        <div className="lookmenu" role="menu">
          <h5>Look</h5>
          {/* Following the machine is the default and is offered as a choice,
              because otherwise choosing once is a door that only opens one
              way: somebody who tried dark at noon could never get back to
              having it follow their evening. */}
          <button
            type="button"
            className="opt"
            role="menuitemradio"
            aria-checked={pinned === null}
            aria-current={pinned === null ? "true" : undefined}
            onClick={() => choose(null)}
          >
            <span
              className="swatch"
              style={{ "--a": "#141a23", "--b": "#0e1117" } as React.CSSProperties}
            />
            System
            <span className="tag">
              follows this machine — {look === "dark" ? "dark" : "light"} now
            </span>
          </button>
          {LOOKS.map((each) => (
            <button
              key={each.name}
              type="button"
              className="opt"
              role="menuitemradio"
              aria-checked={pinned === each.name}
              aria-current={pinned === each.name ? "true" : undefined}
              onClick={() => choose(each.name)}
            >
              <span
                className="swatch"
                style={{ "--a": each.a, "--b": each.b } as React.CSSProperties}
              />
              {each.label}
              <span className="tag">{each.said}</span>
            </button>
          ))}
          <hr />
          {/* Their own page: what they reach, what is sent to them, and the
              tokens they hold. Here rather than in the rail because
              it is about the person rather than about the work. */}
          <Link to="/me" className="opt" role="menuitem" onClick={() => setOpen(false)}>
            Your account
            <span className="tag">tokens, digest</span>
          </Link>
          <button
            type="button"
            className="opt"
            role="menuitem"
            // The sequence lives in session.ts, where its ordering can be
            // asserted: what makes it correct is which parts run before the
            // await and outside the try, and a click handler is not somewhere
            // a test can reach that from.
            disabled={leaving}
            onClick={() => {
              setLeaving(true);
              setStuck(false);
              void signOut(
                async () => signedOutBy((await api.DELETE("/v1/session", {})).response.status),
                (where) => window.location.assign(where),
              ).then((ended) => {
                if (ended) return;
                setLeaving(false);
                setStuck(true);
              });
            }}
          >
            {stuck ? "Try signing out again" : "Sign out"}
            <span className="tag">{who.identity}</span>
          </button>
          {stuck && (
            <p className="hint" role="alert" style={{ margin: "4px 10px" }}>
              Sign-out didn&rsquo;t reach the server. You&rsquo;re still signed in here.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
