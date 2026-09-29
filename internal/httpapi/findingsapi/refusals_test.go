// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"io"
	"log/slog"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

// mappers is what each refusal mapper in this package answers err with.
func mappers(err error) map[string]error {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	in := core.Deps{Logger: quiet}
	return map[string]error{
		"refusedNote":     refusedNote(quiet, err),
		"refusedReport":   refusedReport(in, err, "that could not be read"),
		"refusedMovement": refusedMovement(in, err),
		"refusedRuling":   refusedRuling(in, err, "that could not be read"),
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

// A store's own sentence reaches the caller in its own words through a note's
// mapper, which has no arm for it.
func TestAStoresRefusalIsPublishedByTheCatchAllMappers(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	refusaltest.Publishes(t, map[string]error{
		"refusedNote": refusedNote(quiet, refusaltest.Said()),
	})
}
