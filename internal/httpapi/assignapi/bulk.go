// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// AtComponentBody is one issue open against a component, as something to
// select.
type AtComponentBody struct {
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity,omitempty" doc:"The severity the report gives it"`
	Occurrences   int    `json:"occurrences" doc:"The number of occurrences of it in this build"`
	FixedIn       string `json:"fixed_in,omitempty" doc:"The version the report says fixes it, where it names one"`
	// Summary is the text one decision is made on. Deciding in bulk on
	// less than deciding singly is the wrong way round, and this list
	// narrows by the description while showing none of it.
	Summary    string  `json:"summary,omitempty" doc:"The first line of what the issue says about itself, cut to fit a row"`
	Exploited  bool    `json:"exploited,omitempty" doc:"Somebody is known to be exploiting this"`
	Incident   bool    `json:"incident,omitempty" doc:"Whether an incident stands in this product through it. A decision over several issues that sets this one aside or puts it off is refused"`
	Likelihood float64 `json:"likelihood,omitempty" doc:"Published estimate that this will be exploited, 0 to 1"`
	Due        string  `json:"due,omitempty" doc:"The date it runs out. The earliest among its occurrences here, which is the one that makes it late"`
}

func registerBulk(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-issues-at-component", Method: http.MethodGet,
		Path: "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}" +
			"/components/{component}/issues",
		Summary: "List the issues open against one component",
		Description: "Returns the distinct issues open against this component in this build, " +
			"most urgent first, with how many occurrences each has, the version that fixes " +
			"it where the report names one, and what one decision about it would be made " +
			"on: what the issue says about itself, whether anybody is known to be " +
			"exploiting it, the published estimate, and the earliest deadline among its " +
			"occurrences here.\n\n" +
			"`contains` matches the text of a report. It narrows a list; it is not part of any " +
			"decision made afterwards.",
		Tags: []string{"Triage"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Component   string `path:"component"`
		core.ComponentQuery
		Contains string `query:"contains" maxLength:"200" doc:"Match the text of the report"`
		Limit    int    `query:"limit" default:"50" minimum:"1" maximum:"500"`
		Offset   int    `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []AtComponentBody `json:"items"`
			Total int               `json:"total"`
			// Findings is how many rows the whole narrowed set
			// holds. The two limits are what sizing an answer needs:
			// how many issues one action may answer, and how many
			// findings it may write.
			Findings        int `json:"findings"`
			IssueLimit      int `json:"issue_limit" doc:"The number of issues one answer here may cover"`
			OccurrenceLimit int `json:"occurrence_limit" doc:"The number of findings one answer here may write"`
		}
	}, error) {
		subject, _, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		_, build, err := core.Browsing(ctx, in, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		component, err := graph.NewStore(in.DB.DB).ComponentAs(ctx, build, input.Component,
			input.Choice())
		if err != nil {
			return nil, core.AmbiguousOrMissing(in.Logger, err)
		}

		// One call, which counts both. Two calls run the whole narrowing again
		// for a number the first has in hand.
		at, total, reaching, err := finding.NewStore(in.DB.DB).AtComponent(ctx, subject,
			build, component, input.Contains, input.Limit, input.Offset)
		if err != nil {
			return nil, core.RefusedFinding(in, err)
		}
		bounds, err := triage.Limits(ctx, in.DB.DB)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the limits on one action could not be read", err)
		}

		issues := make([]int64, 0, len(at))
		for _, each := range at {
			issues = append(issues, each.VulnerabilityID)
		}
		named, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what these issues are called could not be read", err)
		}

		out := &struct {
			Body struct {
				Items           []AtComponentBody `json:"items"`
				Total           int               `json:"total"`
				Findings        int               `json:"findings"`
				IssueLimit      int               `json:"issue_limit" doc:"The number of issues one answer here may cover"`
				OccurrenceLimit int               `json:"occurrence_limit" doc:"The number of findings one answer here may write"`
			}
		}{}
		out.Body.Findings = reaching
		out.Body.IssueLimit, out.Body.OccurrenceLimit = bounds.Review, bounds.Occurrences
		// One row per issue. AtComponent returns every occurrence, because that
		// is what a decision is written against; this list is what somebody
		// picks from, and the occurrence count is the useful part of it.
		out.Body.Items = make([]AtComponentBody, 0, len(at))
		// The deadline is the earliest among the occurrences, which is the one
		// that makes the issue late — so the rows are walked for it rather
		// than the first occurrence being taken as the answer.
		soonest := map[int64]*time.Time{}
		for _, each := range at {
			if each.DueAt == nil {
				continue
			}
			if was := soonest[each.VulnerabilityID]; was == nil || each.DueAt.Before(*was) {
				soonest[each.VulnerabilityID] = each.DueAt
			}
		}
		seen := map[int64]bool{}
		for _, each := range at {
			if seen[each.VulnerabilityID] {
				continue
			}
			seen[each.VulnerabilityID] = true
			row := AtComponentBody{
				Vulnerability: named[each.VulnerabilityID],
				Severity:      finding.SeverityWord(each.SeverityCenti),
				Occurrences:   each.Occurrences, FixedIn: each.FixedIn,
				Summary:   each.Summary,
				Exploited: each.Exploited, Incident: each.Incident,
				Likelihood: float64(each.LikelihoodPPM) / 1_000_000,
			}
			if due := soonest[each.VulnerabilityID]; due != nil {
				row.Due = due.UTC().Format(time.DateOnly)
			}
			out.Body.Items = append(out.Body.Items, row)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "decide-in-bulk", Method: http.MethodPost,
		Path: "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}" +
			"/components/{component}/bulk-decision",
		Summary: "Record a bulk decision",
		Description: "Records the same decision against every issue you name: one outcome, one " +
			"justification, one reasoning, applied separately at every occurrence of each " +
			"issue, each keyed and expiring on its own.\n\n" +
			"You name the issues; the occurrences are resolved here. `selected_by` says how you " +
			"narrowed the list and is recorded with the decision, so \"how were these chosen\" " +
			"has an answer later — but it is never the decision. The reasoning has to hold for " +
			"every issue in the list, since \"these matched a word\" is not a defense anybody " +
			"would accept.\n\n" +
			"`contains` is the same question an approver can re-run. Send the text you " +
			"narrowed the candidate list by; the decision records how many issues that narrowing " +
			"reaches, read here, against how many you named. Equal, the decision is exactly what " +
			"that narrowing returns; far apart, the sentence does not describe the set.\n\n" +
			"Always needs a second person to agree, whatever the outcome.\n\n" +
			"An occurrence a live decision already covers refuses the whole request, naming that " +
			"decision. Send `skip_decided` to leave those occurrences out instead; `skipped` lists " +
			"each one with the decision standing there. Where every occurrence is covered, nothing " +
			"is recorded and the request is refused.\n\n" +
			"Bounded twice, over what the names resolve to: by how many issues one answer may " +
			"cover, set under `triage.review-issues`, and by how many findings it may write, " +
			"set under `triage.write-ceiling`. At most 2000 names per request.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Component   string `path:"component"`
		core.ComponentQuery
		Body struct {
			Vulnerabilities []string           `json:"vulnerabilities" minItems:"1" maxItems:"2000" doc:"The issues this decision covers, by name"`
			SelectedBy      string             `json:"selected_by" minLength:"1" maxLength:"500" doc:"The narrowing, in your own words. Recorded, and never part of the decision"`
			Contains        string             `json:"contains,omitempty" maxLength:"200" doc:"The text you narrowed the candidate list by, if any. Re-run here rather than believed: what is recorded beside your sentence is how many issues that narrowing reaches against how many you named, so an approver can check the two"`
			Outcome         core.OutcomeInBulk `json:"outcome"`
			Justification   core.Justification `json:"justification,omitempty" doc:"Required when it does not apply"`
			DeferredUntil   string             `json:"deferred_until,omitempty" doc:"Required when it is deferred. A date, as 2026-03-31"`
			FixedVersion    string             `json:"fixed_version,omitempty" doc:"Required when the outcome is already-fixed. The package version whoever packages this states the fix arrived in — which must be one release carrying the fix for every issue named, since the decision has to hold for all of them"`
			Reasoning       string             `json:"reasoning" minLength:"1" doc:"The reasoning, holding for every issue named"`
			SkipDecided     bool               `json:"skip_decided,omitempty" doc:"Leave out every occurrence a live decision already covers, and list them in the response. Left out, a selection covering one is refused, naming the decision"`
		}
	}) (*struct {
		Body struct {
			DecisionID int64         `json:"decision_id" doc:"The decision this action made, which is what the review queue lists and what is approved"`
			Recorded   int           `json:"recorded"`
			IDs        []int64       `json:"ids"`
			Skipped    []SkippedBody `json:"skipped,omitempty" doc:"The occurrences left out because a live decision already covers them, where skip_decided was sent"`
		}
	}, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		_, build, err := core.Browsing(ctx, in, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		component, err := graph.NewStore(in.DB.DB).ComponentAs(ctx, build, input.Component,
			input.Choice())
		if err != nil {
			return nil, core.AmbiguousOrMissing(in.Logger, err)
		}

		until, err := deferredUntil(string(input.Body.Outcome), input.Body.DeferredUntil)
		if err != nil {
			return nil, err
		}

		// Resolved in one statement per batch. One lookup per name is fine for
		// three names and is two thousand round trips for the case this
		// exists for. A name filed only where this person may not look is
		// answered as a name nobody filed.
		productID, err := catalog.NewStore(in.DB.DB).ProductOf(ctx, build)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "which product this is could not be read", err)
		}
		found, unknown, err := core.IssuesHere(ctx, in, subject, productID, input.Body.Vulnerabilities)
		if err != nil {
			return nil, err
		}
		issues := make([]int64, 0, len(input.Body.Vulnerabilities))
		seen := map[int64]bool{}
		for _, name := range input.Body.Vulnerabilities {
			id, ok := found[name]
			if !ok {
				continue
			}
			if seen[id] {
				// The same issue named twice, or named once by each of two
				// aliases. Both count once.
				continue
			}
			seen[id] = true
			issues = append(issues, id)
		}
		if len(unknown) > 0 {
			// Named individually, because a person who pasted a list wants to
			// fix the list rather than bisect it.
			return nil, huma.Error404NotFound(
				"no issue is filed under " + strings.Join(clipped(unknown), ", "))
		}

		// The occurrences are resolved inside the write, not here. Reading
		// them first and passing them in would authorize this against
		// rows as they stood before the transaction, and would let a
		// caller's selection decide which occurrences a decision lands on.
		decisionID, recorded, skipped, err := store.BulkDecision(ctx, subject, triage.BulkDecisionAt{
			BuildID: build, ComponentID: component, VulnerabilityIDs: issues,
			Contains: input.Body.Contains, SkipDecided: input.Body.SkipDecided,
		}, triage.Proposal{
			Outcome:       triage.Outcome(input.Body.Outcome),
			Justification: triage.Justification(input.Body.Justification),
			DeferredUntil: until,
			FixedVersion:  input.Body.FixedVersion,
			Reasoning:     input.Body.Reasoning,
			SelectedBy:    input.Body.SelectedBy,
			By:            subject.ID,
			// Always. One person answering hundreds of findings in one action
			// is the case a second pair of eyes exists for, and the short
			// deferral that stands on its own is a decision about one finding.
			NeedsApproval: true,
		}, triage.Bounds{})
		if err != nil {
			if errors.Is(err, triage.ErrNothingOpen) {
				return nil, huma.Error404NotFound(
					"none of those are open against that component any more")
			}
			return nil, core.RefusedDecision(in.Logger, err)
		}

		out := &struct {
			Body struct {
				DecisionID int64         `json:"decision_id" doc:"The decision this action made, which is what the review queue lists and what is approved"`
				Recorded   int           `json:"recorded"`
				IDs        []int64       `json:"ids"`
				Skipped    []SkippedBody `json:"skipped,omitempty" doc:"The occurrences left out because a live decision already covers them, where skip_decided was sent"`
			}
		}{}
		out.Body.DecisionID = decisionID
		out.Body.Recorded = len(recorded)
		out.Body.IDs = recorded
		if out.Body.Skipped, err = skippedBodies(ctx, in, skipped); err != nil {
			return nil, err
		}
		return out, nil
	})
}

// SkippedBody is an occurrence a bulk decision left out, and the decision
// that already covers it.
type SkippedBody struct {
	Vulnerability      string             `json:"vulnerability"`
	Occurrence         string             `json:"occurrence" doc:"Where it sits, as the decision names it"`
	DecisionOccurrence int64              `json:"decision_occurrence" doc:"The decision occurrence standing there"`
	State              core.DecisionState `json:"state" doc:"How far that decision has got"`
}

// skippedBodies names what a bulk decision left out, by the issues' names.
func skippedBodies(ctx context.Context, in core.Deps, skipped []triage.Skipped) ([]SkippedBody, error) {
	if len(skipped) == 0 {
		return nil, nil
	}
	issues := make([]int64, 0, len(skipped))
	for _, each := range skipped {
		issues = append(issues, each.VulnerabilityID)
	}
	named, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, core.WentWrong(in.Logger, "what the skipped issues are called could not be read", err)
	}
	out := make([]SkippedBody, 0, len(skipped))
	for _, each := range skipped {
		out = append(out, SkippedBody{
			Vulnerability: named[each.VulnerabilityID], Occurrence: each.OccurrenceIdentity,
			DecisionOccurrence: each.DecisionOccurrenceID, State: core.DecisionState(each.State),
		})
	}
	return out, nil
}

// deferredUntil reads the date a postponement runs to.
//
// Required when something is deferred, and refused otherwise. Offered as an
// outcome with nowhere to say until when, a deferral records a postponement
// with no end — the one thing a deferral has to have, since the threshold that
// decides whether a second person must agree is measured against it.
func deferredUntil(outcome, stated string) (*time.Time, error) {
	if outcome != string(triage.Deferred) {
		if stated != "" {
			return nil, huma.Error422UnprocessableEntity(
				"a date to defer until only means something when the outcome is deferred")
		}
		return nil, nil
	}
	if stated == "" {
		return nil, huma.Error422UnprocessableEntity(
			"deferring needs a date to defer until — write it as 2026-03-31")
	}
	parsed, err := dateOnly(stated, "that is not a date — write it as 2026-03-31")
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// dateOnly reads a date a caller states, as the start of that day in UTC, and
// refuses anything else in the words given.
func dateOnly(stated, refusal string) (time.Time, error) {
	parsed, err := time.Parse(time.DateOnly, stated)
	if err != nil {
		return time.Time{}, huma.Error422UnprocessableEntity(refusal)
	}
	return parsed.UTC(), nil
}

// clipped shortens a list of names for an error message.
//
// A person who pasted two thousand names does not want two thousand back, and
// an error body that large is its own problem.
func clipped(names []string) []string {
	const most = 10
	if len(names) <= most {
		return names
	}
	return append(append([]string{}, names[:most]...), "and more")
}
