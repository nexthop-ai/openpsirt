// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import "github.com/nexthop-ai/openpsirt/internal/finding"

// KindOf is what a reference is labelled, for the tests.
//
// Exported for the test alone: the labelling is not something another package
// asks for, and the alternative is a test in this package that reaches past
// what the parse returns.
func KindOf(address string) finding.ReferenceKind { return kindOf(address) }
