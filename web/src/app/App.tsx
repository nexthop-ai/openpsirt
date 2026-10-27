// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Suspense, useEffect, useSyncExternalStore } from "react";
import { Loading } from "../ui/Loading";
import { Failed } from "../ui/Failed";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useWho } from "./session";
import { belongTo } from "./drafts";
import { snapshot, subscribe } from "./ended";
import { Boundary } from "./Boundary";
import { Moved, built } from "./moved";
import { retrying } from "./retrying";
import {
  ROUTES,
  analyticsReportAt,
  bulkDecisionAt,
  decisionAt,
  dependenciesAt,
  uploadsAt,
  inventoryChangesAt,
  personAt,
  incidentsAt,
  vulnerabilityReportAt,
  vulnerabilityReportsAt,
  plannedUpgradesAt,
} from "./routes";
import { Shell } from "./Shell";
import { SignIn, forgetForward } from "../screens/SignIn";
import { Component } from "../screens/Component";
import { Findings } from "../screens/Findings";
import { UNOWNED_LIST } from "../screens/list";
import { NotFound } from "../screens/NotFound";
import { Products } from "../screens/Products";
import { Product } from "../screens/Product";
import { Run } from "../screens/Run";
import { Branches } from "../screens/Branches";
import { Variants } from "../screens/Variants";

// Split by route, so a screen carries the weight of what it actually needs.
// The findings list has to stay usable against a full-size product and has no
// business downloading a charting library; the markdown renderer is only
// needed where somebody reads or writes a justification. A screen whose chunk
// failed to arrive is asked for again when the boundary around it is.
const Home = retrying(() => import("../screens/Home").then((m) => m.Home));
const Finding = retrying(() => import("../screens/Finding").then((m) => m.Finding));
const Dependencies = retrying(() => import("../screens/Dependencies").then((m) => m.Dependencies));
const Compare = retrying(() => import("../screens/Compare").then((m) => m.Compare));
const VulnerabilityReports = retrying(() =>
  import("../screens/VulnerabilityReports").then((m) => m.VulnerabilityReports),
);
const VulnerabilityReport = retrying(() =>
  import("../screens/VulnerabilityReport").then((m) => m.VulnerabilityReport),
);
const Leads = retrying(() => import("../screens/Leads").then((m) => m.Leads));
const Lead = retrying(() => import("../screens/Lead").then((m) => m.Lead));
const LeadRules = retrying(() => import("../screens/LeadRules").then((m) => m.LeadRules));
const Repositories = retrying(() => import("../screens/Repositories").then((m) => m.Repositories));
const InventoryCompare = retrying(() =>
  import("../screens/InventoryCompare").then((m) => m.InventoryCompare),
);
const InventoryChanges = retrying(() =>
  import("../screens/InventoryChanges").then((m) => m.InventoryChanges),
);
const Access = retrying(() => import("../screens/Access").then((m) => m.Access));
const Assignments = retrying(() => import("../screens/Assignments").then((m) => m.Assignments));
const Queue = retrying(() => import("../screens/Queue").then((m) => m.Queue));
const Decision = retrying(() => import("../screens/Decision").then((m) => m.Decision));
const DecisionOccurrence = retrying(() =>
  import("../screens/DecisionOccurrence").then((m) => m.DecisionOccurrence),
);
const BulkDecision = retrying(() => import("../screens/BulkDecision").then((m) => m.BulkDecision));
const Me = retrying(() => import("../screens/Me").then((m) => m.Me));
const Issue = retrying(() => import("../screens/Issue").then((m) => m.Issue));
const Teams = retrying(() => import("../screens/Teams").then((m) => m.Teams));
const AutoAssignment = retrying(() =>
  import("../screens/AutoAssignment").then((m) => m.AutoAssignment),
);
const DisclosureDeadlines = retrying(() =>
  import("../screens/DisclosureDeadlines").then((m) => m.DisclosureDeadlines),
);
const Incidents = retrying(() => import("../screens/Incidents").then((m) => m.Incidents));
const PlannedUpgrades = retrying(() =>
  import("../screens/PlannedUpgrades").then((m) => m.PlannedUpgrades),
);
const MatchCoverage = retrying(() =>
  import("../screens/MatchCoverage").then((m) => m.MatchCoverage),
);
const Uploads = retrying(() => import("../screens/Uploads").then((m) => m.Uploads));
const Settings = retrying(() => import("../screens/Settings").then((m) => m.Settings));
const System = retrying(() => import("../screens/System").then((m) => m.System));
const AuditLog = retrying(() => import("../screens/AuditLog").then((m) => m.AuditLog));
const Analytics = retrying(() => import("../screens/analytics/Catalog").then((m) => m.Catalog));
const AnalyticsReport = retrying(() => import("../screens/analytics/Report").then((m) => m.Report));
const RecordFlaw = retrying(() => import("../screens/RecordFlaw").then((m) => m.RecordFlaw));
const Person = retrying(() => import("../screens/Person").then((m) => m.Person));
const Branch = retrying(() => import("../screens/Branch").then((m) => m.Branch));
const Advisories = retrying(() => import("../screens/Advisories").then((m) => m.Advisories));
const Advisory = retrying(() => import("../screens/Advisory").then((m) => m.Advisory));
const VEX = retrying(() => import("../screens/VEX").then((m) => m.VEX));

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
  // A failed refetch keeps the identity already held, and the screen with it:
  // a person already working is not sent to a failure page over one read.
  if (who.isError && !who.data) {
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
              {/* One decision, whole, and every act at that grain. A decision
                occurrence's address resolves to it: what a decision says
                belongs to the action that made it, not to any one of its rows. */}
              <Route path={ROUTES.decision} element={<Decision who={who.data} />} />
              <Route path={ROUTES.decisionOccurrence} element={<DecisionOccurrence />} />
              {/* One issue, everywhere it sits. Not under a product,
                because the question it answers spans them. */}
              <Route path={ROUTES.issue} element={<Issue />} />
              <Route path={ROUTES.products} element={<Products who={who.data} />} />
              <Route path={ROUTES.product} element={<Product />} />
              <Route path={ROUTES.streams} element={<Branches />} />
              {/* A branch and a tag share this address and are different
                questions, so it resolves to whichever screen answers the one
                that line poses. */}
              <Route path={ROUTES.stream} element={<Branch />} />
              <Route path={ROUTES.variants} element={<Variants />} />
              {/* The list at whatever the picker selects, and the same screen at the
            address a build's other screens share. */}
              <Route path={ROUTES.productFindings} element={<Findings />} />
              <Route path={ROUTES.productComponent} element={<Component />} />
              <Route path={ROUTES.buildFindings} element={<Findings />} />
              <Route path={ROUTES.finding} element={<Finding />} />
              <Route path={ROUTES.dependencies} element={<Dependencies />} />
              <Route path={ROUTES.bulkDecision} element={<BulkDecision />} />
              <Route path={ROUTES.uploads} element={<Uploads />} />
              <Route path={ROUTES.uploadsOf} element={<Uploads />} />
              <Route path={ROUTES.inventoryChanges} element={<InventoryChanges />} />
              <Route path={ROUTES.run} element={<Run />} />
              <Route path={ROUTES.plannedUpgrades} element={<PlannedUpgrades />} />
              <Route path={ROUTES.matchCoverage} element={<MatchCoverage />} />
              <Route path={ROUTES.vex} element={<VEX />} />
              <Route path={ROUTES.comparison} element={<Compare />} />
              <Route path={ROUTES.inventoryComparison} element={<InventoryCompare />} />
              <Route path={ROUTES.vulnerabilityReports} element={<VulnerabilityReports />} />
              <Route path={ROUTES.vulnerabilityReport} element={<VulnerabilityReport />} />
              <Route path={ROUTES.leads} element={<Leads />} />
              <Route path={ROUTES.lead} element={<Lead />} />
              <Route path={ROUTES.leadRules} element={<LeadRules />} />
              <Route path={ROUTES.repositories} element={<Repositories />} />
              {/* A person's own page: what they reach, what is sent to them,
                and the credentials they hold. */}
              <Route path={ROUTES.me} element={<Me />} />
              <Route path={ROUTES.access} element={<Access who={who.data} />} />
              {/* One person, whole. An administrator's surface: it carries what
                somebody was told, which is the question asked after a leak. */}
              <Route path={ROUTES.person} element={<Person />} />
              <Route path={ROUTES.teams} element={<Teams />} />
              <Route path={ROUTES.assignments} element={<Assignments />} />
              <Route path={ROUTES.auditLog} element={<AuditLog />} />
              <Route path={ROUTES.analytics} element={<Analytics />} />
              <Route path={ROUTES.analyticsReport} element={<AnalyticsReport />} />
              <Route path={ROUTES.recordFlaw} element={<RecordFlaw />} />
              <Route path={ROUTES.disclosureDeadlines} element={<DisclosureDeadlines />} />
              <Route path={ROUTES.incidents} element={<Incidents />} />
              <Route path={ROUTES.advisories} element={<Advisories />} />
              <Route path={ROUTES.advisory} element={<Advisory />} />
              <Route path={ROUTES.autoAssignment} element={<AutoAssignment />} />
              <Route path={ROUTES.settings} element={<Settings who={who.data} />} />
              <Route path={ROUTES.settingsSection} element={<Settings who={who.data} />} />
              <Route path={ROUTES.system} element={<System />} />
              {/* The addresses these screens had before each was named after
                its rail entry. A notice in somebody's bell keeps the link it
                was sent with, so the old address forwards rather than opening
                the catch-all. */}
              <Route path={ROUTES.formerAccess} element={<Moved to={() => "/access"} />} />
              <Route
                path={ROUTES.formerPerson}
                element={<Moved to={(at) => personAt(at.identity ?? "")} />}
              />
              <Route
                path={ROUTES.formerAssignments}
                element={<Moved to={() => "/assignments"} />}
              />
              <Route
                path={ROUTES.formerExploitedHere}
                element={<Moved to={() => incidentsAt()} />}
              />
              <Route path={ROUTES.formerObligations} element={<Moved to={() => incidentsAt()} />} />
              <Route path={ROUTES.formerAudit} element={<Moved to={() => "/audit-log"} />} />
              <Route path={ROUTES.formerRecord} element={<Moved to={() => "/audit-log"} />} />
              <Route
                path={ROUTES.formerDisclosureDeadlines}
                element={<Moved to={() => "/disclosure-deadlines"} />}
              />
              <Route
                path={ROUTES.formerRecordFlaw}
                element={<Moved to={() => "/record-a-flaw"} />}
              />
              <Route path={ROUTES.formerAnalytics} element={<Moved to={() => "/analytics"} />} />
              <Route
                path={ROUTES.formerAnalyticsReport}
                element={<Moved to={(at) => analyticsReportAt(at.report ?? "")} />}
              />
              <Route
                path={ROUTES.formerVulnerabilityReports}
                element={<Moved to={(at) => vulnerabilityReportsAt(at.product ?? "")} />}
              />
              <Route
                path={ROUTES.formerVulnerabilityReport}
                element={
                  <Moved to={(at) => vulnerabilityReportAt(at.product ?? "", at.reference ?? "")} />
                }
              />
              <Route
                path={ROUTES.formerDependencies}
                element={<Moved to={(at) => dependenciesAt(built(at))} />}
              />
              <Route
                path={ROUTES.formerInventories}
                element={<Moved to={(at) => uploadsAt(built(at))} />}
              />
              <Route
                path={ROUTES.formerInventoryChanges}
                element={<Moved to={(at) => inventoryChangesAt(built(at), Number(at.scan))} />}
              />
              <Route
                path={ROUTES.formerUploads}
                element={<Moved to={(at) => uploadsAt(built(at))} />}
              />
              <Route
                path={ROUTES.formerUploadChanges}
                element={<Moved to={(at) => inventoryChangesAt(built(at), Number(at.scan))} />}
              />
              <Route
                path={ROUTES.formerDecision}
                element={<Moved to={(at) => decisionAt(Number(at.id))} />}
              />
              <Route
                path={ROUTES.formerBulkDecision}
                element={<Moved to={(at) => bulkDecisionAt(built(at), at.component ?? "")} />}
              />
              <Route
                path={ROUTES.formerPendingUpgrades}
                element={<Moved to={(at) => plannedUpgradesAt(built(at))} />}
              />
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
      className="fixed inset-0 z-[var(--z-resume)] overflow-y-auto bg-[var(--backdrop)] backdrop-blur-sm"
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
