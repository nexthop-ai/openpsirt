// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The schemes a rendered link may name once attachment and issue references
// have been rewritten into paths. A web test holds this to the list the
// server's submission check reads, in testdata/link-schemes.json.
export const LINK_SCHEMES = ["http", "https", "mailto"] as const;
