// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build tools

// Package tools requires cyclonedx-gomod, so that its version is a requirement of a
// module and the dependency updates read it.
package tools

import _ "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod"
