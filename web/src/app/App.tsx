import { Suspense, lazy, useEffect, useSyncExternalStore } from "react";
import { Loading } from "../ui/Loading";
import { Failed } from "../ui/Failed";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useWho } from "./session";
import { belongTo } from "./drafts";
import { snapshot, subscribe } from "./ended";
import { Boundary } from "./Boundary";
import { Shell } from "./Shell";
import { SignIn, forgetForward } from "../screens/SignIn";
import { Component } from "../screens/Component";
import { Findings } from "../screens/Findings";
import { UNOWNED_LIST } from "../screens/list";
import { NotFound } from "../screens/NotFound";
import { Products } from "../screens/Products";
import { Product } from "../screens/Product";
import { Run } from "../screens/Run";
import { Streams } from "../screens/Streams";
import { Variants } from "../screens/Variants";

// Split by route, so a screen carries the weight of what it actually needs.
// The findings list has to stay usable against a full-size product and has no
// business downloading a charting library; the markdown renderer is only
// needed where somebody reads or writes a justification.
const Home = lazy(() => import("../screens/Home").then((m) => ({ default: m.Home })));
const Finding = lazy(() => import("../screens/Finding").then((m) => ({ default: m.Finding })));
const Tree = lazy(() => import("../screens/Tree").then((m) => ({ default: m.Tree })));
const Compare = lazy(() => import("../screens/Compare").then((m) => ({ default: m.Compare })));
const Inbox = lazy(() => import("../screens/Inbox").then((m) => ({ default: m.Inbox })));
const InboxReport = lazy(() =>
  import("../screens/InboxReport").then((m) => ({ default: m.InboxReport })),
);
const InventoryChanges = lazy(() =>
  import("../screens/InventoryChanges").then((m) => ({ default: m.InventoryChanges })),
);
const People = lazy(() => import("../screens/People").then((m) => ({ default: m.People })));
const Work = lazy(() => import("../screens/Work").then((m) => ({ default: m.Work })));
const Queue = lazy(() => import("../screens/Queue").then((m) => ({ default: m.Queue })));
const Decision = lazy(() => import("../screens/Decision").then((m) => ({ default: m.Decision })));
const Claim = lazy(() => import("../screens/Claim").then((m) => ({ default: m.Claim })));
const Together = lazy(() => import("../screens/Together").then((m) => ({ default: m.Together })));
const Me = lazy(() => import("../screens/Me").then((m) => ({ default: m.Me })));
const Issue = lazy(() => import("../screens/Issue").then((m) => ({ default: m.Issue })));
const Teams = lazy(() => import("../screens/Teams").then((m) => ({ default: m.Teams })));
const AutoAssignment = lazy(() =>
  import("../screens/AutoAssignment").then((m) => ({ default: m.AutoAssignment })),
);
const Disclosing = lazy(() =>
  import("../screens/Disclosing").then((m) => ({ default: m.Disclosing })),
);
const Upgrades = lazy(() => import("../screens/Upgrades").then((m) => ({ default: m.Upgrades })));
const Inventories = lazy(() =>
  import("../screens/Inventories").then((m) => ({ default: m.Inventories })),
);
const Settings = lazy(() => import("../screens/Settings").then((m) => ({ default: m.Settings })));
const System = lazy(() => import("../screens/System").then((m) => ({ default: m.System })));
const Audit = lazy(() => import("../screens/Audit").then((m) => ({ default: m.Audit })));
const Reports = lazy(() =>
  import("../screens/reports/Catalog").then((m) => ({ default: m.Catalog })),
);
const Report = lazy(() => import("../screens/reports/Report").then((m) => ({ default: m.Report })));
const Record = lazy(() => import("../screens/Record").then((m) => ({ default: m.Record })));
const Person = lazy(() => import("../screens/Person").then((m) => ({ default: m.Person })));
const Stream = lazy(() => import("../screens/Stream").then((m) => ({ default: m.Stream })));
const Advisories = lazy(() =>
  import("../screens/Advisories").then((m) => ({ default: m.Advisories })),
);
const Advisory = lazy(() => import("../screens/Advisory").then((m) => ({ default: m.Advisory })));

const build = "/products/:product/streams/:stream/variants/:variant";

// Every address this application answers, as the patterns the router matches.
//
// Named and read by the routes below rather than written only in the JSX, so
// that something other than a person clicking can ask whether an address built
// by hand elsewhere resolves to a screen. Eight entries in the report catalog
// compose an address from a scope and nothing pinned any of them against the
// router — a report leading nowhere redirects to the front page, silently.
export const ROUTES = {
  home: "/",
  reviewQueue: "/review-queue",
  unassigned: "/unassigned",
  findings: "/findings",
  claim: "/claims/:id",
  decision: "/decisions/:id",
  issue: "/issues/:vulnerability",
  products: "/products",
  product: "/products/:product",
  streams: "/products/:product/streams",
  stream: "/products/:product/streams/:stream",
  variants: "/products/:product/variants",
  productFindings: "/products/:product/findings",
  productComponent: "/products/:product/components/:component",
  buildFindings: `${build}/findings`,
  finding: `${build}/findings/:vulnerability/components/:component`,
  tree: `${build}/components`,
  decide: `${build}/components/:component/decide`,
  inventories: `${build}/scans`,
  inventoryChanges: `${build}/scans/:scan/changes`,
  run: `${build}/runs/:run`,
  upgrades: `${build}/pending-upgrades`,
  comparison: "/products/:product/comparison",
  inbox: "/products/:product/inbox",
  inboxReport: "/products/:product/inbox/:reference",
  me: "/me",
  people: "/people",
  person: "/people/:identity",
  teams: "/teams",
  work: "/work",
  audit: "/audit",
  reports: "/reports",
  report: "/reports/:report",
  record: "/record",
  disclosing: "/disclosing",
  advisories: "/advisories",
  advisory: "/advisories/:advisory",
  autoAssignment: "/auto-assignment",
  settings: "/settings",
  system: "/system",
} as const;

export function App() {
  const who = useWho();
  const ended = useSyncExternalStore(subscribe, snapshot, snapshot);
  // The boundary around the screens is keyed on the address, so walking away
  // from one that threw clears it. A boundary that held its error until
  // somebody pressed Try again would follow them to every other screen.
  const { pathname } = useLocation();

  // Whose drafts this page reads and writes, decided here because this is the
  // one place that knows who is signed in and every screen below it takes the
  // answer for granted. Nobody recognized means no drafts are kept at all
  // rather than drafts kept under nobody's name.
  //
  // In an effect rather than in the render body: a render that is thrown away
  // still leaves a write behind, which is harmless while the value is the
  // session's own identity and is the shape that stops being harmless the
  // moment it depends on anything a discarded render computed.
  useEffect(() => belongTo(who.data?.identity), [who.data?.identity]);

  // Somebody is signed in, so the guard that stops the sign-in screen
  // forwarding twice has done its job and the next arrival may forward again.
  useEffect(() => {
    if (who.data) forgetForward();
  }, [who.data]);

  if (who.isPending) return <Waiting />;

  // A failed read is not an answer about who is signed in.
  //
  // The identity read resolves a 401 to "nobody", so anything that reaches
  // here is a server that could not be asked. Drawing that as signed out
  // sends somebody who is signed in back through their identity provider —
  // where there is exactly one, without even a button to press — over what is
  // usually a transient failure.
  if (who.isError) {
    return (
      <div className="flex min-h-dvh items-center justify-center">
        <div style={{ maxWidth: 520 }}>
          <Failed error={who.error} what="The signed-in person could not be read." />
          <div className="actions" style={{ marginTop: 12 }}>
            <button type="button" className="btn" onClick={() => void who.refetch()}>
              Try again
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Nobody signed in. Not an error state — it is what a fresh browser looks
  // like, and the only thing to offer is a way in.
  if (!who.data) return <SignIn />;

  return (
    <>
      {ended && <Resume />}
      <Shell who={who.data}>
        {/* Inside the frame rather than around it: a screen that throws should
            leave the rail, the scope bar and the way to another screen where
            they are. The one around the whole application is in `main.tsx`,
            for the frame's own throws. */}
        <Boundary key={pathname} where={pathname} what="This screen could not be drawn.">
          <Suspense fallback={<Loading />}>
            <Routes>
              <Route path={ROUTES.home} element={<Home who={who.data} />} />
              <Route path={ROUTES.reviewQueue} element={<Queue />} />
              {/* Work nobody holds is the findings list under two filters, so
                the address stays and the screen does not. It is a route rather
                than nothing so that a bookmark, a link in an old digest and
                the sidebar entry as it was all land on the list instead of
                being swallowed by the catch-all below. */}
              <Route path={ROUTES.unassigned} element={<Navigate to={UNOWNED_LIST} replace />} />
              <Route path={ROUTES.findings} element={<Findings />} />
              {/* One claim, whole, and every act at that grain. A decision's
                address resolves to it: what a judgment says belongs to the
                action that made it, not to any one of its rows. */}
              <Route path={ROUTES.claim} element={<Claim who={who.data} />} />
              <Route path={ROUTES.decision} element={<Decision />} />
              {/* One issue, everywhere it sits. Not under a product,
                because the question it answers spans them. */}
              <Route path={ROUTES.issue} element={<Issue />} />
              <Route path={ROUTES.products} element={<Products who={who.data} />} />
              <Route path={ROUTES.product} element={<Product />} />
              <Route path={ROUTES.streams} element={<Streams />} />
              {/* A branch and a tag share this address and are different
                questions, so it resolves to whichever screen answers the one
                that line poses. */}
              <Route path={ROUTES.stream} element={<Stream />} />
              <Route path={ROUTES.variants} element={<Variants />} />
              {/* The list at whatever the picker selects, and the same screen at the
            address a build's other screens share. */}
              <Route path={ROUTES.productFindings} element={<Findings />} />
              <Route path={ROUTES.productComponent} element={<Component />} />
              <Route path={ROUTES.buildFindings} element={<Findings />} />
              <Route path={ROUTES.finding} element={<Finding />} />
              <Route path={ROUTES.tree} element={<Tree />} />
              <Route path={ROUTES.decide} element={<Together />} />
              <Route path={ROUTES.inventories} element={<Inventories />} />
              <Route path={ROUTES.inventoryChanges} element={<InventoryChanges />} />
              <Route path={ROUTES.run} element={<Run />} />
              <Route path={ROUTES.upgrades} element={<Upgrades />} />
              <Route path={ROUTES.comparison} element={<Compare />} />
              <Route path={ROUTES.inbox} element={<Inbox />} />
              <Route path={ROUTES.inboxReport} element={<InboxReport />} />
              {/* A person's own page: what they reach, what is sent to them,
                and the credentials they hold. */}
              <Route path={ROUTES.me} element={<Me />} />
              <Route path={ROUTES.people} element={<People who={who.data} />} />
              {/* One person, whole. An administrator's surface: it carries what
                somebody was told, which is the question asked after a leak. */}
              <Route path={ROUTES.person} element={<Person />} />
              <Route path={ROUTES.teams} element={<Teams />} />
              <Route path={ROUTES.work} element={<Work />} />
              <Route path={ROUTES.audit} element={<Audit />} />
              <Route path={ROUTES.reports} element={<Reports />} />
              <Route path={ROUTES.report} element={<Report />} />
              <Route path={ROUTES.record} element={<Record />} />
              <Route path={ROUTES.disclosing} element={<Disclosing />} />
              <Route path={ROUTES.advisories} element={<Advisories />} />
              <Route path={ROUTES.advisory} element={<Advisory />} />
              <Route path={ROUTES.autoAssignment} element={<AutoAssignment />} />
              <Route path={ROUTES.settings} element={<Settings who={who.data} />} />
              <Route path={ROUTES.system} element={<System />} />
              {/* An address this application does not answer. It says so, and
                keeps the address in the bar: redirecting home threw away the
                one piece of evidence a link built wrong leaves behind, which
                is the link. */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </Boundary>
      </Shell>
    </>
  );
}

// Resume offers a way back in over the screen somebody was already on.
//
// Over it rather than instead of it: the words are safe either way, because a
// draft is written as it is typed, but the finding they were reading, the
// filters they had set and the row they had open are not — and a sign-in page
// that replaced all of it would throw those away for nothing. The way in
// carries the address of this screen, so the round trip through the provider
// comes back here.
//
// It is not dismissible. The session is gone; there is nothing behind this to
// do, and a control that closed it would only hide the reason the next thing
// somebody pressed did not work.
function Resume() {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Your session ended"
      className="fixed inset-0 z-50 bg-[color-mix(in_srgb,var(--ink)_55%,transparent)] backdrop-blur-sm"
    >
      <SignIn resuming />
    </div>
  );
}

function Waiting() {
  return (
    <div className="flex min-h-dvh items-center justify-center">
      <Loading />
    </div>
  );
}
