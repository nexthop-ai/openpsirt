// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build tools

// Package tools requires govulncheck, so that its version is a requirement of a
// module and the dependency updates read it.
package tools

import _ "golang.org/x/vuln/cmd/govulncheck"
