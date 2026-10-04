// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// FixNamed is what a caller supplies to name a release carrying the fix.
type FixNamed struct {
	Release string `json:"release" minLength:"1" maxLength:"191" doc:"A tag of the record's product, by the name scans use for it. One declared before any scan of it is accepted"`
}

func registerFixes(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "name-fix-release", Method: http.MethodPost,
		Path:    "/v1/exploited-here/{id}/fixes",
		Summary: "Name a release carrying the fix",
		Description: "Records that a tag of the record's product carries the fix for the " +
			"attack. Name each tag as it is cut; a tag declared before any scan of it is " +
			"the ordinary case. Recorded in the administrative trail.\n\n" +
			"A window starting from the fix starts at the earliest release date stated for " +
			"a tag the record names. A tag with no stated release date starts nothing.\n\n" +
			"A branch, a retired tag and a cleared record are refused with 422, a tag the " +
			"product does not have with 422, and a tag the record already names with 409.",
		Tags: []string{"Obligations"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "The product is the record's own, not one in the path.",
		core.TriageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body FixNamed
	}) (*struct{ Body core.FixBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		store := obligation.NewStore(in.DB.DB)
		fix, err := store.NameFix(ctx, subject, input.ID, input.Body.Release)
		if err != nil {
			return nil, refusedFix(in, err)
		}
		people, err := triage.NewStore(in.DB.DB).PeopleNamed(ctx, []int64{fix.NamedBy})
		if err != nil {
			return nil, core.WentWrong(in.Logger, "who named this could not be read", err)
		}
		// Read back as the record's fixes are, so the state of the tag's
		// scans is answered the same way here as on the record.
		fixes, err := store.FixesOf(ctx, subject, []int64{fix.ExploitedHereID})
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the release could not be read back", err)
		}
		for _, one := range fixes[fix.ExploitedHereID] {
			if one.ID == fix.ID {
				*fix = one
			}
		}
		return &struct{ Body core.FixBody }{Body: core.FixBodies([]obligation.Fix{*fix}, people)[0]}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "withdraw-fix-release", Method: http.MethodDelete,
		Path:    "/v1/exploited-here/{id}/fixes/{fix}",
		Summary: "Withdraw a release named as carrying the fix",
		Description: "Takes back a tag named in error. The naming stays readable with who " +
			"withdrew it and when, and the tag may be named again. A window starting from " +
			"the fix moves to the earliest release date the record still names, or stops " +
			"where none is stated. Recorded in the administrative trail.\n\n" +
			"A naming already withdrawn, or never made, answers 404. A cleared record is " +
			"refused with 422.",
		Tags: []string{"Obligations"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "The product is the record's own, not one in the path.",
		core.TriageRights()...), func(ctx context.Context, input *struct {
		ID  int64 `path:"id"`
		Fix int64 `path:"fix"`
	}) (*struct{}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		if err := obligation.NewStore(in.DB.DB).WithdrawFix(ctx, subject, input.ID,
			input.Fix); err != nil {
			return nil, refusedFix(in, err)
		}
		return &struct{}{}, nil
	})
}

// refusedFix answers a store's refusal to name or withdraw a fix release.
func refusedFix(in core.Deps, err error) error {
	switch {
	case errors.Is(err, obligation.ErrNoSuchRecord):
		return noSuchExploitedHere()
	case errors.Is(err, obligation.ErrNoSuchFix):
		return huma.Error404NotFound("this record names no such release as carrying the fix")
	case errors.Is(err, obligation.ErrFixNamed):
		return huma.Error409Conflict("this record already names that release as carrying the fix")
	}
	return core.RefusedDecision(in.Logger, err)
}
