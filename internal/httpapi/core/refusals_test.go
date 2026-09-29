// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"io"
	"log/slog"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

// mappers is what each refusal mapper in this package answers err with.
func mappers(err error) map[string]error {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	in := Deps{Logger: quiet}
	nowhere := func() error { return huma.Error404NotFound("nothing goes by that") }
	return map[string]error{
		"Asked":              Asked(quiet, err),
		"Refused":            Refused(quiet, err, "that could not be recorded"),
		"RefusedDecision":    RefusedDecision(quiet, err),
		"DeclineDeclaration": DeclineDeclaration(quiet, err),
		"RefusedFinding":     RefusedFinding(in, err),
		"Absent":             Absent(quiet, err, "that could not be looked up", nowhere),
		"WentWrong":          WentWrong(quiet, "that could not be read", err),
		"NotRecorded":        NotRecorded(quiet, err),
		"AmbiguousOrMissing": AmbiguousOrMissing(quiet, err),
		"Undeclared":         Undeclared(quiet, err, "that could not be looked up"),
	}
}

// A lost connection is a fault in every mapper, and the address the driver
// tried is not published.
func TestALostConnectionIsAFaultInEveryRefusalMapper(t *testing.T) {
	mapped := mappers(refusaltest.Lost())
	refusaltest.Faults(t, mapped, refusaltest.LostAddress)
	refusaltest.CoversEveryMapper(t, mapped, nil)
}

// An error nothing classified is a fault in every mapper, and its text is
// withheld.
func TestAnUnclassifiedErrorIsAFaultInEveryRefusalMapper(t *testing.T) {
	mapped := mappers(refusaltest.Unclassified())
	refusaltest.Faults(t, mapped, refusaltest.UnclassifiedText...)
	refusaltest.CoversEveryMapper(t, mapped, nil)
}

// A store's own sentence reaches the caller in its own words through each
// mapper that has no arm for it, however the store wrapped it.
func TestAStoresRefusalIsPublishedByTheCatchAllMappers(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	said := refusaltest.Said()
	refusaltest.Publishes(t, map[string]error{
		"Asked":              Asked(quiet, said),
		"RefusedDecision":    RefusedDecision(quiet, said),
		"DeclineDeclaration": DeclineDeclaration(quiet, said),
	})
}
