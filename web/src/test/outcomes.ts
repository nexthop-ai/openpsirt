// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Claims } from "../ui/outcomes";
import published from "./outcomes.json";

// What the server publishes about each outcome, as a session answer carries
// it, for a test standing in for the server. A server test compares the file
// with the session answer and rewrites it on request. A JSON import widens
// every word to a string, so the server test is what holds the words.
export const PUBLISHED = published as Claims[];
