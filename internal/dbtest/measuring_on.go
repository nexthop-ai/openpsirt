// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package dbtest

// measuring is whether this binary holds measurements, which empty a server
// database to the layout a fresh load leaves rather than by deleting.
const measuring = true
