// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package boundtest_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/bound/boundtest"
)

var errTooMany = errors.New("too many")

// recorder is a testing.TB whose failures are counted rather than reported,
// so the helper's own refusals can be watched.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper() {}
func (r *recorder) Fatalf(string, ...any) {
	r.failed = true
	panic(r)
}

func run(limit int, feed func(int) error) (failed bool) {
	r := &recorder{}
	defer func() {
		if p := recover(); p != nil && p != r {
			panic(p)
		}
		failed = r.failed
	}()
	boundtest.Edges(r, limit, feed, func(err error) bool { return errors.Is(err, errTooMany) })
	return r.failed
}

func bounded(most int) func(int) error {
	return func(n int) error {
		if n > most {
			return errTooMany
		}
		return nil
	}
}

func TestABoundAtItsLimitPassesFromBothSides(t *testing.T) {
	if run(3, bounded(3)) {
		t.Fatal("a bound of exactly the limit was reported")
	}
}

func TestABoundOffByOneEitherWayIsReported(t *testing.T) {
	if !run(3, bounded(4)) {
		t.Fatal("a bound one too generous passed")
	}
	if !run(3, bounded(2)) {
		t.Fatal("a bound one too strict passed")
	}
}

func TestARefusalForAnotherReasonIsReported(t *testing.T) {
	other := func(n int) error {
		if n > 3 {
			return errors.New("malformed")
		}
		return nil
	}
	if !run(3, other) {
		t.Fatal("a refusal the bound did not make passed")
	}
}

func TestALimitOfNoneIsReported(t *testing.T) {
	if !run(0, bounded(0)) {
		t.Fatal("a limit of zero was taken as a test")
	}
}
