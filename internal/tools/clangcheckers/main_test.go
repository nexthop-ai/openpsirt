// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"testing"
)

const help = `OVERVIEW: Clang Static Analyzer Checkers List

USAGE: -analyzer-checker <CHECKER or PACKAGE,...>

CHECKERS:
  core.DivideZero               Check for division by zero
  core.UndefinedBinaryOperatorResult
                                Check for undefined results of binary operators
  alpha.security.ArrayBoundV2   Warn about buffer overflows
  osx.API                       Check for proper uses of various Apple APIs
  unix.Malloc                   Check for memory leaks, double free, and use-after-free problems
`

func TestTheCheckersForCAreReadAndNoOther(t *testing.T) {
	got := checkers(help)
	want := []string{"core.DivideZero", "core.UndefinedBinaryOperatorResult", "unix.Malloc"}
	if !slices.Equal(got, want) {
		t.Errorf("the checkers read are %v; want %v", got, want)
	}
}

func TestACheckerTheTableLacksIsNamed(t *testing.T) {
	got := missing([]string{"core.DivideZero", "unix.Malloc"}, []string{"unix.Malloc", "core.NullDereference"})
	if !slices.Equal(got, []string{"core.DivideZero"}) {
		t.Errorf("missing is %v; want core.DivideZero alone", got)
	}
}
