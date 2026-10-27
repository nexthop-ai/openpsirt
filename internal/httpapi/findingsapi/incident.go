// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"errors"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/incident"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// incidentAt is every record kept about one issue in one product, as a
// finding shows them.
//
// Empty where there are none, which is the ordinary answer and not a fault:
// the finding screen asks this of everything it shows, and almost nothing has
// one.
func incidentAt(ctx context.Context, in core.Deps, subject access.Subject,
	productID, vulnerabilityID int64, identifier string) ([]core.IncidentBody, error) {

	store := triage.NewStore(in.DB.DB)
	kept, err := store.IncidentAt(ctx, subject, productID, vulnerabilityID)
	if err != nil {
		// A reader who may not be told of the issue is answered as one with no
		// record, because they have already been shown the finding: the read
		// that got them here asked the same question and allowed it.
		if errors.Is(err, triage.ErrNoSuchIncident) {
			return nil, nil
		}
		return nil, err
	}
	if len(kept) == 0 {
		return nil, nil
	}
	ids := make([]int64, 0, len(kept))
	for _, record := range kept {
		ids = append(ids, record.ID)
	}
	notices := incident.NewStore(in.DB.DB)
	told, err := notices.ToldAbout(ctx, subject, ids)
	if err != nil {
		return nil, err
	}
	named, err := notices.WindowsNamed(ctx, subject, told)
	if err != nil {
		return nil, err
	}
	fixes, err := notices.FixesOf(ctx, subject, ids)
	if err != nil {
		return nil, err
	}
	people, err := store.PeopleNamed(ctx, core.WhoToldOrTouched(kept, told, fixes))
	if err != nil {
		return nil, err
	}
	bodies := make([]core.IncidentBody, 0, len(kept))
	for _, record := range kept {
		body := core.IncidentBodyOf(record, identifier, people)
		body.Told = core.ToldBodies(told[record.ID], named, people)
		body.Fixes = core.FixBodies(fixes[record.ID], people)
		bodies = append(bodies, body)
	}
	return bodies, nil
}
