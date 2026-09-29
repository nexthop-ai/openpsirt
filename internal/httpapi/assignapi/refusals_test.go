// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"io"
	"log/slog"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

// mappers is what each refusal mapper in this package answers err with.
func mappers(err error) map[string]error {
	in := core.Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return map[string]error{
		"oneVersion": oneVersion(err, func(err error) error {
			return core.RefusedFinding(in, err)
		}),
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
