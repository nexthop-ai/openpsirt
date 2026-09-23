// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ReactElement } from "react";
import { Navigate, useParams } from "react-router-dom";
import { Backlog } from "./Backlog";
import { Compliance } from "./Compliance";
import { Coverage } from "./Coverage";
import { Effort } from "./Effort";
import { Overview } from "./Overview";
import { Published } from "./Published";
import { Register } from "./Register";
import { Scrutiny } from "./Scrutiny";
import { Support } from "./Support";

// The page a report address draws.
//
// One route through this map rather than a route per report, so the list
// somebody reads and the addresses that answer cannot come apart: a name in
// the catalog with no page behind it is a link that goes nowhere, and a page
// no catalog entry names is a report nobody finds. A test pins both
// directions.
export const PAGES: Record<string, ReactElement> = {
  "program-overview": <Overview />,
  "scan-coverage": <Coverage />,
  "releases-out-of-support": <Support />,
  "rubber-stamp": <Scrutiny />,
  "deadline-compliance": <Compliance />,
  "disposition-register": <Register />,
  "advisories-issued": <Published />,
  "where-the-effort-went": <Effort />,
  "backlog-over-time": <Backlog />,
};

export function Report() {
  const { report = "" } = useParams();
  // A name this catalog does not hold goes back to the catalog rather than
  // home: somebody following a stale link is looking for a report, and the
  // list of them is the answer nearest to what they asked for.
  return PAGES[report] ?? <Navigate to="/reports" replace />;
}
