// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// AdvisoryReleaseBody is one release of one issue an advisory covers, and what the
// document states about it.
type AdvisoryReleaseBody struct {
	Product       string `json:"product"`
	ProductName   string `json:"product_name,omitempty" doc:"The product's display name, or its name where it has none"`
	Vulnerability string `json:"vulnerability"`
	Stream        string `json:"stream"`
	Variant       string `json:"variant"`
	Status        string `json:"status" enum:"known_affected,known_not_affected,fixed" doc:"What the document states about the release"`
	// Decided is where the decisions put it, which differs from the status
	// only where the release is marked affected.
	Decided string               `json:"decided" enum:"known_affected,known_not_affected,fixed" doc:"Where the release's decisions put it, before any mark"`
	Marked  bool                 `json:"marked" doc:"Whether the release is marked affected whatever its decisions say"`
	Changed bool                 `json:"changed" doc:"Whether the status differs from what an agreement standing on what the advisory says now saw. The agreement stands"`
	Covered *ReleaseCoveringBody `json:"covered,omitempty" doc:"The decision every open place of the issue in the release stands under. Absent where no one outcome covers them all"`
}

// ReleaseCoveringBody is the decision a release stands under.
type ReleaseCoveringBody struct {
	Decision   int64    `json:"decision" doc:"The earliest decision covering the release"`
	Outcome    string   `json:"outcome"`
	Reason     string   `json:"reason,omitempty" doc:"The decision's justification, which the document states as the reason the release is not affected"`
	Mitigation string   `json:"mitigation,omitempty" doc:"What stops the flaw, where the decision named it. The document states it as the impact"`
	DecidedIn  []string `json:"decided_in" doc:"The variants the decision's place was open in when it was proposed. A release in another variant is one the decision reached by matching versions"`
}

func registerReleases(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-advisory-releases", Method: http.MethodGet,
		Path:    "/v1/advisories/{advisory}/releases",
		Summary: "List what an advisory states about each release",
		Description: "Every release of every issue this advisory covers, with the status its " +
			"document states and the decision behind it.\n\n" +
			"A release whose every open place is covered by approved, live decisions with " +
			"one outcome names the earliest of them, with the variants it was made on. " +
			"`changed` is true where the status differs from what an agreement standing on " +
			"what the advisory says now saw; the agreement stands.\n\n" +
			"An advisory covering a product you hold nothing on answers as one that does " +
			"not exist.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory" doc:"The identifier the advisory is tracked by"`
	}) (*core.ListOutput[AdvisoryReleaseBody], error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		rows, err := advisory.NewStore(in.DB.DB).Releases(ctx, subject, input.Advisory)
		if err != nil {
			return nil, advisoryRefused(in, err, "the releases could not be read")
		}
		out := &core.ListOutput[AdvisoryReleaseBody]{}
		out.Body.Total = len(rows)
		out.Body.Items = make([]AdvisoryReleaseBody, 0, len(rows))
		for _, one := range rows {
			body := AdvisoryReleaseBody{
				Product: one.Covered.Product, ProductName: one.Covered.ProductName,
				Vulnerability: one.Covered.Issue, Stream: one.Stream, Variant: one.Variant,
				Status: one.Status, Decided: one.Decided(),
				Marked: one.Overridden, Changed: one.Changed,
			}
			if one.Grounds != nil {
				body.Covered = &ReleaseCoveringBody{
					Decision: one.Grounds.Decision, Outcome: one.Grounds.Outcome,
					Reason: one.Grounds.Reason, Mitigation: one.Grounds.Mitigation,
					DecidedIn: one.Grounds.DecidedIn,
				}
				if body.Covered.DecidedIn == nil {
					body.Covered.DecidedIn = []string{}
				}
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "mark-advisory-release", Method: http.MethodPut,
		Path:    "/v1/advisories/{advisory}/marked",
		Summary: "Mark a release affected",
		Description: "Marks one release of one issue this advisory covers as affected whatever " +
			"its decisions say, or clears the mark where `affected` is false.\n\n" +
			"A decision reaches every build whose versions match, so one made on another " +
			"variant can cover a release it was never about. The document states a marked " +
			"release as known affected.\n\n" +
			"A change opens a new edition and takes back every agreement standing, as " +
			"retitling does. Asking for what already stands changes nothing.\n\n" +
			"A release the issue is not in answers 404.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.AnyPerson, changesWhatItSays, core.TriageRights()...), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
		Body     struct {
			Product       string `json:"product" minLength:"1"`
			Vulnerability string `json:"vulnerability" minLength:"1" doc:"The identifier the issue is filed under"`
			Stream        string `json:"stream" minLength:"1"`
			Variant       string `json:"variant" minLength:"1"`
			Affected      bool   `json:"affected" doc:"True marks the release affected, false clears the mark"`
		}
	}) (*struct{}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		if err := advisory.NewStore(in.DB.DB).MarkAffected(ctx, subject, input.Advisory,
			input.Body.Product, input.Body.Vulnerability, input.Body.Stream,
			input.Body.Variant, input.Body.Affected); err != nil {
			return nil, advisoryRefused(in, err, "the release could not be marked")
		}
		return &struct{}{}, nil
	})
}
