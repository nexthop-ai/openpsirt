// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// FlawLeadBuild is one build a hand-off proposed a flaw against.
type FlawLeadBuild struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	Seen    bool   `json:"seen" doc:"Whether the lead was seen in it. Otherwise it holds the chosen component and the lead's series never analyzed it"`
}

// FlawUnseenBody is a build the flaw is open on whose lead a comparable run
// no longer sees.
type FlawUnseenBody struct {
	Stream  string       `json:"stream"`
	Variant string       `json:"variant"`
	NotSeen LeadRunBody  `json:"not_seen" doc:"The first run on the build that did not see the lead"`
	Fixed   *LeadRunBody `json:"fixed,omitempty" doc:"The build a person stated fixed the lead, where they closed it as fixed"`
}

// FlawLeadBody is the lead a flaw was recorded from.
type FlawLeadBody struct {
	Place     string           `json:"place" doc:"The lead's place identity"`
	Stream    string           `json:"stream" doc:"The branch or tag of the build its newest finding you read is on"`
	Variant   string           `json:"variant" doc:"The variant of that build"`
	Rule      string           `json:"rule" doc:"The analyzer's rule, as <tool>/<rule>"`
	Path      string           `json:"path" doc:"Where the lead is, relative to the top of the checkout"`
	Line      int              `json:"line,omitempty" doc:"The line it starts at"`
	State     LeadState        `json:"state" doc:"Where the lead stands on that build"`
	Suggested SuggestionBody   `json:"suggested" doc:"The component the hand-off's offer ranked first, which the person may have turned down. Absent for the build itself"`
	Proposed  []FlawLeadBuild  `json:"proposed" doc:"The builds the hand-off proposed the flaw against"`
	HandedBy  string           `json:"handed_by" doc:"The person who handed it off, by sign-in identity"`
	HandedAt  string           `json:"handed_at" format:"date-time"`
	UndoneBy  string           `json:"undone_by,omitempty" doc:"The person who undid the hand-off, by sign-in identity"`
	UndoneAt  string           `json:"undone_at,omitempty" format:"date-time" doc:"When the hand-off was undone. Absent while it stands"`
	Because   string           `json:"because,omitempty" doc:"Why the hand-off was undone, in markdown"`
	FixedIn   []FlawUnseenBody `json:"fixed_in" doc:"Each build the flaw is still open on whose lead a comparable run no longer sees, which a person may close the flaw as fixed in. Empty once the hand-off is undone"`
}

func registerFlawLead(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-flaw-lead", Method: http.MethodGet,
		Path:    "/v1/products/{product}/issues/{vulnerability}/lead",
		Summary: "Get the lead a flaw was recorded from",
		Description: "Returns the static analysis lead a flaw recorded here was handed off from, with " +
			"the component its hand-off was offered first, the builds it proposed, and whether the " +
			"hand-off was undone.\n\n" +
			"`fixed_in` lists each build the flaw is still open on where the lead is not reproduced, " +
			"with the first run that did not see it. Closing the flaw as fixed there is `POST " +
			".../findings/{vulnerability}/resolve`, which a person does.\n\n" +
			"A flaw recorded from no lead, and a lead you do not read in full, answer 404.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers where you may read a finding of this issue in this product and read "+
		"its lead in full. Anywhere else it answers as a flaw recorded from no lead."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The flaw, by any name it is known under"`
	}) (*struct{ Body FlawLeadBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductForIssue(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		issue, err := core.IssueHere(ctx, in, subject, product.ID, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		origin, err := analysis.OriginOf(ctx, in.DB.DB, subject, product.ID, issue)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the lead this flaw came from could not be read", err)
		}
		if origin == nil {
			return nil, huma.Error404NotFound("this flaw was recorded from no lead you read")
		}
		people := []int64{origin.HandedBy}
		if origin.UndoneBy != nil {
			people = append(people, *origin.UndoneBy)
		}
		who, err := core.WhoSigned(ctx, in.DB.DB, people)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the lead this flaw came from could not be read", err)
		}
		body := FlawLeadBody{
			Place: origin.Place, Stream: origin.Build.Stream, Variant: origin.Build.Variant,
			Rule: origin.Rule, Path: origin.Path, Line: origin.Line, State: LeadState(origin.State),
			Suggested: SuggestionBody{Component: origin.Suggested.Component, Ecosystem: origin.Suggested.Ecosystem,
				Namespace: origin.Suggested.Namespace, From: HandoffSource(origin.Suggested.From),
				Lacking: []LeadBuild{}, Unanalyzed: []LeadBuild{}},
			Proposed: make([]FlawLeadBuild, 0, len(origin.Proposed)),
			HandedBy: who.Identity(origin.HandedBy), HandedAt: core.Stamp(origin.HandedAt),
			UndoneAt: core.StampAt(origin.UndoneAt), Because: origin.UndoneNote,
			FixedIn: make([]FlawUnseenBody, 0, len(origin.FixedIn)),
		}
		if origin.UndoneBy != nil {
			body.UndoneBy = who.Identity(*origin.UndoneBy)
		}
		for _, b := range origin.Proposed {
			body.Proposed = append(body.Proposed, FlawLeadBuild{Stream: b.Stream, Variant: b.Variant, Seen: b.Seen})
		}
		for _, u := range origin.FixedIn {
			not := leadRunBody(&u.NotSeen)
			body.FixedIn = append(body.FixedIn, FlawUnseenBody{Stream: u.Stream, Variant: u.Variant,
				NotSeen: *not, Fixed: leadRunBody(u.Fixed)})
		}
		return &struct{ Body FlawLeadBody }{Body: body}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "undo-lead-handoff", Method: http.MethodPost, Path: leadPath + "/hand-off/withdrawal",
		Summary: "Undo a lead's hand-off",
		Description: "Undoes the hand-off of a lead while its flaw is undisclosed, with every lead linked " +
			"to the same flaw. Each is confirmed again and internal, its collaborators' grants end, and " +
			"the flaw is taken back out of every build it was recorded against, closed as `invalid` for " +
			"the reason given. The flaw keeps the record of the lead it was recorded from, marked " +
			"undone.\n\n" +
			"`because` is required. Recorded in the administration trail. A lead not handed off, or one " +
			"whose flaw is disclosed, is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
		Body    struct {
			Because string `json:"because" minLength:"1" doc:"Why the hand-off is undone, in markdown"`
		}
	}) (*struct{}, error) {
		at, err := locateLead(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		err = analysis.UndoHandOff(ctx, in.DB.DB, at.subject, at.named.ProductID, input.Place,
			input.Body.Because, time.Now())
		var faults markdown.Faults
		switch {
		case err == nil:
		case errors.Is(err, analysis.ErrNoUndoReason):
			return nil, core.Asked(in.Logger, err)
		case errors.As(err, &faults):
			return nil, core.RefusedText(faults)
		default:
			return nil, refusedHandoff(in, err)
		}
		return &struct{}{}, nil
	})
}
