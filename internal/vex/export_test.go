// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

// Between runs fn after the document is generated and before the write that
// records it, which is the window a second person recording lands in.
func Between(s *Store, fn func()) { s.generated = fn }
