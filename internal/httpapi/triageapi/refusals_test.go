// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"io"
	"log/slog"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

// exempt is the mappers reached only with an error something has already
// classified, so a lost connection never arrives at them.
var exempt = map[string]string{
	"aboutBuild": "a refusal already answered as a status, prefixed with the build",
}

// mappers is what each refusal mapper in this package answers err with.
func mappers(err error) map[string]error {
	in := core.Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return map[string]error{
		"refusedWindow": refusedWindow(in, err),
	}
}

// A lost connection is a fault in every mapper, and the address the driver
// tried is not published.
func TestALostConnectionIsAFaultInEveryRefusalMapper(t *testing.T) {
	mapped := mappers(refusaltest.Lost())
	refusaltest.Faults(t, mapped, refusaltest.LostAddress)
	refusaltest.CoversEveryMapper(t, mapped, exempt)
}

// An error nothing classified is a fault in every mapper, and its text is
// withheld.
func TestAnUnclassifiedErrorIsAFaultInEveryRefusalMapper(t *testing.T) {
	mapped := mappers(refusaltest.Unclassified())
	refusaltest.Faults(t, mapped, refusaltest.UnclassifiedText...)
	refusaltest.CoversEveryMapper(t, mapped, exempt)
}
