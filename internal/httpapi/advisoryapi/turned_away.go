// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// turnedAway records that a document uploaded to a product was refused, as
// far as it had been read, where the answer is a refusal.
//
// Only a refusal is recorded. An answer of 500 or above is this deployment
// failing rather than the document being turned away.
//
// Best-effort, as a scan refusal is: a note about something that already
// failed, where failing the failure would turn a refusal the sender needs to
// read into a fault they cannot.
func turnedAway(ctx context.Context, in core.Deps, by access.Subject, productID int64, from finding.Supplied,
	answer error) {

	var said huma.StatusError
	if !errors.As(answer, &said) || said.GetStatus() >= http.StatusInternalServerError {
		return
	}
	if err := finding.NewStore(in.DB.DB).TurnedAway(ctx, by, productID, from, answer.Error()); err != nil {
		in.Log().ErrorContext(ctx, "could not record that a document upload was refused",
			"error", err, "product", productID)
	}
}

// turnedAwayBeforeReading records a document the form bound refused before
// the operation ran, against the product it names. Nothing of the document
// was read, so the record names the kind and the sender alone.
func turnedAwayBeforeReading(in core.Deps, source string) func(huma.Context, string) {
	return func(hctx huma.Context, reason string) {
		ctx := hctx.Context()
		if core.Administrating(ctx) != nil {
			return
		}
		by, err := core.Reading(ctx)
		if err != nil {
			return
		}
		product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, hctx.Param("product"))
		if err != nil {
			return
		}
		if err := finding.NewStore(in.DB.DB).TurnedAway(ctx, by, product.ID, finding.Supplied{
			Source: source, Arrived: &finding.Arrival{},
		}, reason); err != nil {
			in.Log().ErrorContext(ctx, "could not record that a document upload was refused",
				"error", err, "product", product.Name)
		}
	}
}
