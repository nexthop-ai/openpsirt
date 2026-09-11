import { notACredential } from "../ui/noautofill";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { initials } from "../ui/initials";
import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { findingsPath, useScope, type Scoped } from "./scope";
import { folded, fold } from "./rail";
import { forgetAll } from "./drafts";
import { Scope } from "./Scope";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Notices } from "../ui/Notices";
import { Icon } from "../ui/Icons";
import { UploadDrawer } from "../ui/Upload";
import {
  LOOKS,
  applyLook,
  chosenLook,
  clearLook,
  currentLook,
  followSystem,
  type Look,
} from "./look";
import type { Who } from "./session";

// The frame the restyled mockup settled on: a rail down the side carrying the
// brand and the entries grouped by what they span, a bar across the top
// carrying what you are looking at, a way to find things, a way to upload,
// what is waiting on you, and who you are; the screen in the rest.
//
// The grouping is the point. "Across products" and a named build are different
// kinds of place, and a flat list of links hides that the findings list is
// bound to one build while the queue is not: the findings list is scoped to a
// product, and home summarizes across them.
export function Shell({ who, children }: { who: Who; children: ReactNode }) {
  const { product, stream, variant } = useScope();
  const whole = !!(product && stream && variant);
  const scope = [product ?? "all products", stream, variant].filter(Boolean).join(" · ");
  const build = whole
    ? `/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(stream)}/variants/${encodeURIComponent(variant)}`
    : "";
  const [uploading, setUploading] = useState(false);
  // On a narrow screen the rail is a panel that opens from a menu control. The
  // tab bar carries the three places somebody reviews and responds from , and
  // everything else is one tap further rather than absent.
  const [menu, setMenu] = useState(false);
  // Which groups are folded away, kept in the browser like the look: it
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
  useEffect(() => {
    setMenu(false);
    // A new screen starts at its own top. Picking an entry from the foot of
    // the rail used to leave the document where it was, so the screen that
    // arrived was already scrolled past its heading and its controls — which
    // reads as the wrong screen rather than as a scroll position.
    window.scrollTo({ top: 0 });
  }, [pathname]);
  useEffect(() => {
    if (!menu) return;
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") setMenu(false);
    }
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [menu]);

  // The counts on the rail. Asked for with a page of one, because the total
  // is what is wanted and the rows are not.
  const queue = useQuery({
    queryKey: ["queue", "count"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/review-queue", { params: { query: { limit: 1 } } })),
    refetchInterval: 60_000,
  });
  const unassigned = useQuery({
    queryKey: ["unassigned", "count", product ?? ""],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/unassigned", {
          params: { query: { limit: 1, ...(product ? { product } : {}) } },
        }),
      ),
    refetchInterval: 60_000,
  });
  // Counted for whatever is selected rather than only for a whole build : the
  // entry beside this number opens the list that produced it, and a rail that
  // goes quiet the moment somebody widens the scope is one that looks broken
  // rather than one that declines.
  const open = useQuery({
    queryKey: ["findings", "count", product, stream, variant],
    enabled: !!product,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: {
            path: { product: product ?? "" },
            query: {
              limit: 1,
              ...(stream ? { stream } : {}),
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
        <Search at={{ product, stream, variant }} />
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
          {/* The mark itself, not a stand-in for it. This drew a generic
              shield from the icon set at 16px on an accent square, which is
              neither the logo nor its colors — the brand files were already
              here, used by the sign-in screen and the favicon, and only the
              rail was drawing something else. */}
          <img className="glyph" src="/brand/mark.svg" alt="" width={30} height={30} />
          <span>
            OpenPSIRT
            {/* What the logo says, in full. "Product security" was a
                shortening that dropped the half naming what the tool is for —
                incident response and triage — which is the half somebody
                arriving is trying to work out. */}
            <small>Product Security Incident Response &amp; Triage</small>
          </span>
        </Link>

        <Group name="across" label="Across products" shut={shut} onToggle={toggleGroup} />
        {!shut.has("across") && (
          <>
            <Rail to="/" end icon="home" label="Home" />
            <Rail
              to="/review-queue"
              icon="inbox"
              label="Review queue"
              count={queue.data?.total}
              unit="claims waiting"
            />
            <Rail
              to="/unassigned"
              icon="nobody"
              label="Unassigned"
              count={unassigned.data?.total}
              unit="findings nobody holds"
              quiet
            />
            <Rail to="/work" icon="people" label="Assignments" />
            {/* The record of what was judged. Across products because that is how
              it is asked for — an auditor asks about a period, not a build. */}
            <Rail to="/audit" icon="ledger" label="The record" />
            {/* The catalog of named reports, and the one place a report is
              built by hand. Here rather than under a build because a report
              spans whatever the picker has selected, up to every product a
              reader can see. */}
            <Rail to="/reports" icon="chart" label="Reports" />
          </>
        )}
        <Group name="scope" label={scope} shut={shut} onToggle={toggleGroup} />
        {!shut.has("scope") && (
          <>
            {/* Three entries here open on one build and no other. Without one
              picked they decline rather than opening on a scope that means
              nothing, and say why. Findings is not one of them: it answers for
              whatever is selected and needs only a product. */}
            {/* One entry, because there is one list. It answers for whatever the
              picker has selected and for every product a reader can see when
              nothing is — so a second entry above meant one screen with two
              doors, and the door down here was dead whenever no product was
              picked. It needs nothing: it is the one screen in this group that
              does not. */}
            <Rail
              to={findingsPath({ product, stream, variant })}
              icon="bug"
              label="Findings"
              count={open.data?.total}
              unit="findings — an issue at a component, counted once per build"
              quiet
            />
            <Rail to={`${build}/components`} icon="tree" label="Dependencies" needs={whole} />
            <Rail to={`${build}/scans`} icon="scan" label="Inventories" needs={whole} />
            {/* What this build is waiting on, which is the fix-bundle view read
              from the other end. */}
            <Rail
              to={`${build}/pending-upgrades`}
              icon="flag"
              label="Pending upgrades"
              needs={whole}
            />
            {/* Recording a flaw is an act rather than a place, so it opens a
              drawer instead of going anywhere — the same shape as Upload. It
              lives here rather than on the findings list because it is not a
              sub-action of reading one: a flaw nobody has reported is exactly
              what is *not* in that list. */}
            {/* Its own screen rather than an action on the findings list: what is
              being recorded is precisely what is *not* in that list, and it asks
              more than a control beside a table has room for. It needs no
              product picked, because the screen asks for one. */}
            <Rail to="/record" icon="record" label="Record a flaw" />
            {/* What is running out of embargo. The list is itself a disclosure,
              so a product somebody may not read undisclosed work in contributes
              nothing to it — the server narrows it. */}
            <Rail to="/disclosing" icon="bell" label="Disclosing" />
          </>
        )}
        <Group name="manage" label="Manage" shut={shut} onToggle={toggleGroup} />
        {!shut.has("manage") && (
          <>
            <Rail to="/products" end icon="box" label="Products" />
            <Rail
              to={`/products/${encodeURIComponent(product ?? "")}/streams`}
              end
              icon="branch"
              label="Branches and tags"
              needs={!!product}
              why="Pick a product first"
            />
            <Rail
              to={`/products/${encodeURIComponent(product ?? "")}/variants`}
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
            {who.admin && <Rail to="/people" icon="roles" label="Users and roles" />}
            {/* Assignment without a person doing it, by standing rule.
              Under Manage because it is something set up once rather than worked
              at, and called what it does: the act it automates is assignment. */}
            <Rail to="/auto-assignment" icon="route" label="Auto-assignment" />
            {who.admin && <Rail to="/settings" icon="gear" label="Settings" />}
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
          responds from are a tab bar instead. */}
      <nav className="tabbar">
        <NavLink to="/" end>
          Home
        </NavLink>
        <NavLink to={findingsPath({ product, stream, variant })}>Findings</NavLink>
        <NavLink to="/review-queue">Queue</NavLink>
        <button type="button" aria-expanded={menu} onClick={() => setMenu(!menu)}>
          Menu
        </button>
      </nav>

      <UploadDrawer open={uploading} onClose={() => setUploading(false)} />
    </div>
  );
}

// What is running here.
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
  icon,
  label,
  count,
  unit,
  quiet,
  end,
  needs = true,
  why = "This screen is about one build — pick a product, a branch and a variant",
}: {
  to: string;
  icon: string;
  label: string;
  count?: number;
  // What the badge is a count of. The rail has room for a number and not for a
  // noun, so the unit rides on the title and on what a screen reader is given
  // — enough that "Unassigned 7,616" beside "5,803 open issues" stops being
  // two numbers that look like they should agree.
  unit?: string;
  quiet?: boolean;
  end?: boolean;
  needs?: boolean;
  why?: string;
}) {
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
  return (
    <NavLink to={to} end={end} className="nav">
      <Icon name={icon} />
      {label}
      {typeof count === "number" && count > 0 && (
        <span
          className={quiet ? "count quiet" : "count"}
          title={unit ? `${count.toLocaleString()} ${unit}` : undefined}
          aria-label={unit ? `${count.toLocaleString()} ${unit}` : undefined}
        >
          {count.toLocaleString()}
        </span>
      )}
    </NavLink>
  );
}

// Finding a component or an issue from anywhere. It is the findings list's own
// search, reached without going there first.
//
// It asks at whatever scope is chosen, which since the list stopped being one
// build's is the product as readily as a single build. It used to be disabled
// unless all three were picked, so the most common question a PSIRT is asked —
// where is this advisory in what we ship — could not be typed at all without
// first choosing a variant, and answered nothing when it could, because the
// term was matched against component names alone.
//
// **An issue name goes to the issue, wherever it sits**, and needs no
// product picked: "a critical just landed in openssl — which of our products
// ship an affected version" is the question, and it spans products by
// construction. Anything else searches what a product ships, which still needs
// one picked.
//
// Which of the two it is, is decided by asking: a term that resolves to an
// issue goes to the issue page, and everything else falls through to the list.
// Guessing from the shape of the text would be a second, worse copy of the
// server's own name resolution — one that is wrong about every identifier a
// deployment mints for itself.
function Search({ at }: { at: Scoped }) {
  const navigate = useNavigate();
  const [typed, setTyped] = useState("");
  const [looking, setLooking] = useState(false);
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
      title={
        at.product
          ? undefined
          : "An issue by name goes to the issue, wherever it sits. Searching components needs a product picked"
      }
      onSubmit={(event) => {
        event.preventDefault();
        const term = typed.trim();
        if (term === "" || looking) return;
        setLooking(true);
        void api
          .GET("/v1/issues/{vulnerability}", {
            params: { path: { vulnerability: term }, query: { limit: 1 } },
          })
          .then((answer) => {
            setLooking(false);
            if (answer.data) {
              navigate(`/issues/${encodeURIComponent(term)}`);
              return;
            }
            // Not an issue anybody here carries, so it is a component search,
            // and that is a question about one product's contents.
            if (!at.product) return;
            const path = findingsPath(at);
            navigate(`${path}${path.includes("?") ? "&" : "?"}q=${encodeURIComponent(term)}`);
          })
          .catch(() => setLooking(false));
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

// Who you are, with the look menu and the way out underneath.
function Me({ who }: { who: Who }) {
  const [open, setOpen] = useState(false);
  // What is drawn, and what was asked for. They differ for somebody who has
  // chosen nothing: the operating system is answering, and the menu has to
  // show which of the two that came out as while still marking the choice
  // as unmade.
  const [look, setLook] = useState<Look>(() => currentLook());
  const [pinned, setPinned] = useState<Look | null>(() => chosenLook());
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (pinned) applyLook(pinned);
    else clearLook();
    setLook(currentLook());
  }, [pinned]);

  // While nothing is pinned, a machine that turns dark at sunset turns this
  // dark at sunset.
  useEffect(() => followSystem(setLook), []);

  useEffect(() => {
    if (!open) return;
    function away(event: MouseEvent) {
      if (box.current && !box.current.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

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
            onClick={() => setPinned(null)}
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
              onClick={() => setPinned(each.name)}
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
            onClick={async () => {
              // Cleared first, and whatever the server says. Drafts hold
              // triage text, private findings included, and text that survived
              // a sign-out would be exposed in a way the application itself is
              // not. A sign-out that failed to reach the server is the case
              // where clearing matters most.
              forgetAll();
              try {
                await api.DELETE("/v1/session", {});
              } finally {
                // A full load rather than a route change: signing out has to
                // drop every cached answer, and starting again is the way to
                // be sure.
                //
                // Said in the address, because the sign-in screen forwards
                // straight to the provider where there is only one — and the
                // provider still holds its own session, so an unmarked arrival
                // here would sign them back in and make signing out
                // impossible.
                window.location.assign("/?signed-out");
              }
            }}
          >
            Sign out
            <span className="tag">{who.identity}</span>
          </button>
        </div>
      )}
    </div>
  );
}

// Two letters for the corner. A display name people set is usually a full
// name; an identity is usually not, and either has to fit in 30 pixels.
