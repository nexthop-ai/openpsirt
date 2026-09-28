// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// AtComponentBody is one issue open against a component, as something to
// select.
type AtComponentBody struct {
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity,omitempty" doc:"The severity the report gives it"`
	Places        int    `json:"places" doc:"The number of places in this build it sits at"`
	FixedIn       string `json:"fixed_in,omitempty" doc:"The version the report says fixes it, where it names one"`
	// Summary is the text one judgment is made on. Deciding in bulk on
	// less than deciding singly is the wrong way round, and this list
	// narrows by the description while showing none of it.
	Summary       string  `json:"summary,omitempty" doc:"The first line of what the issue says about itself, cut to fit a row"`
	Exploited     bool    `json:"exploited,omitempty" doc:"Somebody is known to be exploiting this"`
	ExploitedHere bool    `json:"exploited_here,omitempty" doc:"This product records being exploited through it. A judgment over several issues that sets this one aside or puts it off is refused"`
	Likelihood    float64 `json:"likelihood,omitempty" doc:"Published estimate that this will be exploited, 0 to 1"`
	Due           string  `json:"due,omitempty" doc:"The date it runs out. The earliest among its places here, which is the one that makes it late"`
}

func registerBulk(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-issues-at-component", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/components/{component}/issues",
		Summary: "List the issues open against one component",
		Description: "Returns the distinct issues open against this component in this build, " +
			"most urgent first, with how many places each sits at, the version that fixes " +
			"it where the report names one, and what one judgment about it would be made " +
			"on: what the issue says about itself, whether anybody is known to be " +
			"exploiting it, the published estimate, and the earliest deadline among its " +
			"places here.\n\n" +
			"`contains` matches the text of a report. It narrows a list; it is not part of any " +
			"claim made afterwards.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Stream    string `path:"stream"`
		Variant   string `path:"variant"`
		Component string `path:"component"`
		ComponentQuery
		Contains string `query:"contains" doc:"Match the text of the report"`
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
			Findings   int `json:"findings"`
			IssueLimit int `json:"issue_limit" doc:"The number of issues one answer here may cover"`
			PlaceLimit int `json:"place_limit" doc:"The number of findings one answer here may write"`
		}
	}, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		_, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		component, err := graph.NewStore(in.DB.DB).ComponentAs(ctx, target, input.Component,
			input.choice())
		if err != nil {
			return nil, ambiguousOrMissing(in.Logger, err)
		}

		// One call, which counts both. Two calls run the whole narrowing again
		// for a number the first has in hand.
		at, total, reaching, err := finding.NewStore(in.DB.DB).AtComponent(ctx, subject,
			target, component, input.Contains, input.Limit, input.Offset)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		bounds, err := boundsFor(ctx, in)
		if err != nil {
			return nil, err
		}

		issues := make([]int64, 0, len(at))
		for _, each := range at {
			issues = append(issues, each.VulnerabilityID)
		}
		named, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
		if err != nil {
			return nil, wentWrong(in.Logger, "what these issues are called could not be read", err)
		}

		out := &struct {
			Body struct {
				Items      []AtComponentBody `json:"items"`
				Total      int               `json:"total"`
				Findings   int               `json:"findings"`
				IssueLimit int               `json:"issue_limit" doc:"The number of issues one answer here may cover"`
				PlaceLimit int               `json:"place_limit" doc:"The number of findings one answer here may write"`
			}
		}{}
		out.Body.Findings = reaching
		out.Body.IssueLimit, out.Body.PlaceLimit = bounds.Review, bounds.Places
		// One row per issue. AtComponent returns every place, because that is
		// what a decision is written against; this list is what somebody picks
		// from, and the place count is the useful part of it.
		out.Body.Items = make([]AtComponentBody, 0, len(at))
		// The deadline is the earliest among the places, which is the one
		// that makes the issue late — so the rows are walked for it rather
		// than the first place being taken as the answer.
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
				Places:        each.Places, FixedIn: each.FixedIn,
				Summary:   each.Summary,
				Exploited: each.Exploited, ExploitedHere: each.ExploitedHere,
				Likelihood: float64(each.LikelihoodPPM) / 1_000_000,
			}
			if due := soonest[each.VulnerabilityID]; due != nil {
				row.Due = due.Format(time.DateOnly)
			}
			out.Body.Items = append(out.Body.Items, row)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "decide-together", Method: http.MethodPost,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/components/{component}/decisions",
		Summary: "Record one judgment about several issues at once",
		Description: "Records the same claim against every issue you name: one outcome, one " +
			"justification, one reasoning, and a separate decision for every place each issue " +
			"sits at, each keyed and expiring on its own.\n\n" +
			"You name the issues; the places are resolved here. `selected_by` says how you " +
			"narrowed the list and is recorded with every claim, so \"how were these chosen\" " +
			"has an answer later — but it is never the claim. The reasoning has to hold for " +
			"every issue in the list, since \"these matched a word\" is not a defense anybody " +
			"would accept.\n\n" +
			"`contains` is the same question an approver can re-run. Send the text you " +
			"narrowed the candidate list by; the claim records how many issues that narrowing " +
			"reaches, read here, against how many you named. Equal, the claim is exactly what " +
			"that narrowing returns; far apart, the sentence does not describe the set.\n\n" +
			"Always needs a second person to agree, whatever the outcome.\n\n" +
			"A place a live decision already covers refuses the whole claim, naming that " +
			"decision. Send `skip_decided` to leave those places out instead; `skipped` lists " +
			"each one with the decision standing there. Where every place is covered, nothing " +
			"is recorded and the request is refused.\n\n" +
			"Bounded twice, over what the names resolve to: by how many issues one answer may " +
			"cover, set under `triage.review-issues`, and by how many findings it may write, " +
			"set under `triage.write-ceiling`. At most 2000 names per request.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Stream    string `path:"stream"`
		Variant   string `path:"variant"`
		Component string `path:"component"`
		ComponentQuery
		Body struct {
			Vulnerabilities []string      `json:"vulnerabilities" minItems:"1" maxItems:"2000" doc:"The issues this claim covers, by name"`
			SelectedBy      string        `json:"selected_by" minLength:"1" maxLength:"500" doc:"The narrowing, in your own words. Recorded, and never part of the claim"`
			Contains        string        `json:"contains,omitempty" maxLength:"200" doc:"The text you narrowed the candidate list by, if any. Re-run here rather than believed: what is recorded beside your sentence is how many issues that narrowing reaches against how many you named, so an approver can check the two"`
			Outcome         outcomeInBulk `json:"outcome"`
			Justification   justification `json:"justification,omitempty" doc:"Required when it does not apply"`
			DeferredUntil   string        `json:"deferred_until,omitempty" doc:"Required when it is deferred. A date, as 2026-03-31"`
			FixedVersion    string        `json:"fixed_version,omitempty" doc:"Required when the outcome is already-fixed. The package version whoever packages this states the fix arrived in — which must be one release carrying the fix for every issue named, since the claim has to hold for all of them"`
			Reasoning       string        `json:"reasoning" minLength:"1" doc:"The reasoning, holding for every issue named"`
			SkipDecided     bool          `json:"skip_decided,omitempty" doc:"Leave out every place a live decision already covers, and list them in the response. Left out, a selection covering one is refused, naming the decision"`
		}
	}) (*struct {
		Body struct {
			ClaimID  int64         `json:"claim_id" doc:"The claim this action made, which is what the review queue lists and what is approved"`
			Recorded int           `json:"recorded"`
			IDs      []int64       `json:"ids"`
			Skipped  []SkippedBody `json:"skipped,omitempty" doc:"The places left out because a live decision already covers them, where skip_decided was sent"`
		}
	}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		_, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		component, err := graph.NewStore(in.DB.DB).ComponentAs(ctx, target, input.Component,
			input.choice())
		if err != nil {
			return nil, ambiguousOrMissing(in.Logger, err)
		}

		until, err := deferredUntil(string(input.Body.Outcome), input.Body.DeferredUntil)
		if err != nil {
			return nil, err
		}

		// Resolved in one statement. One lookup per name is fine for three
		// names and is two thousand round trips for the case this exists for.
		found, err := finding.NewVulnerabilities(in.DB.DB).
			IDsByName(ctx, input.Body.Vulnerabilities)
		if err != nil {
			return nil, wentWrong(in.Logger, "which issues these are could not be read", err)
		}
		issues := make([]int64, 0, len(input.Body.Vulnerabilities))
		unknown := make([]string, 0)
		seen := map[int64]bool{}
		for _, name := range input.Body.Vulnerabilities {
			id, ok := found[name]
			if !ok {
				unknown = append(unknown, name)
				continue
			}
			if seen[id] {
				// The same issue named twice, or named once by each of two
				// aliases. Both are one claim.
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

		// The places are resolved inside the write, not here. Reading
		// them first and passing them in would authorize this against
		// rows as they stood before the transaction, and would let a
		// caller's selection decide which places a decision lands on.
		claimID, recorded, skipped, err := store.Together(ctx, subject, triage.TogetherAt{
			TargetID: target, ComponentID: component, VulnerabilityIDs: issues,
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
			// deferral that stands on its own is a claim about one finding.
			NeedsApproval: true,
		}, triage.Bounds{})
		if err != nil {
			if errors.Is(err, triage.ErrNothingOpen) {
				return nil, huma.Error404NotFound(
					"none of those are open against that component any more")
			}
			return nil, refusedDecision(in.Logger, err)
		}

		out := &struct {
			Body struct {
				ClaimID  int64         `json:"claim_id" doc:"The claim this action made, which is what the review queue lists and what is approved"`
				Recorded int           `json:"recorded"`
				IDs      []int64       `json:"ids"`
				Skipped  []SkippedBody `json:"skipped,omitempty" doc:"The places left out because a live decision already covers them, where skip_decided was sent"`
			}
		}{}
		out.Body.ClaimID = claimID
		out.Body.Recorded = len(recorded)
		out.Body.IDs = recorded
		if out.Body.Skipped, err = skippedBodies(ctx, in, skipped); err != nil {
			return nil, err
		}
		return out, nil
	})
}

// SkippedBody is a place a bulk judgment left out, and the decision that
// already covers it.
type SkippedBody struct {
	Vulnerability string `json:"vulnerability"`
	Place         string `json:"place" doc:"Where it sits, as the decision names it"`
	Decision      int64  `json:"decision" doc:"The decision standing there"`
	State         string `json:"state" doc:"How far that decision has got"`
}

// skippedBodies names what a bulk judgment left out, by the issues' names.
func skippedBodies(ctx context.Context, in Ingest, skipped []triage.Skipped) ([]SkippedBody, error) {
	if len(skipped) == 0 {
		return nil, nil
	}
	issues := make([]int64, 0, len(skipped))
	for _, each := range skipped {
		issues = append(issues, each.VulnerabilityID)
	}
	named, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, wentWrong(in.Logger, "what the skipped issues are called could not be read", err)
	}
	out := make([]SkippedBody, 0, len(skipped))
	for _, each := range skipped {
		out = append(out, SkippedBody{
			Vulnerability: named[each.VulnerabilityID], Place: each.PlaceIdentity,
			Decision: each.DecisionID, State: string(each.State),
		})
	}
	return out, nil
}

// boundsFor reads the limits on an act answering many issues at once, as the
// deployment sets them.
func boundsFor(ctx context.Context, in Ingest) (triage.Bounds, error) {
	settings := setting.NewStore(in.DB.DB)
	var b triage.Bounds
	for _, each := range []struct {
		key      string
		fallback int
		into     *int
	}{
		{setting.ReviewIssues, setting.DefaultReviewIssues, &b.Review},
		{setting.AgreedIssues, setting.DefaultAgreedIssues, &b.Agreed},
		{setting.WriteCeiling, setting.DefaultWriteCeiling, &b.Places},
	} {
		n, err := settings.Count(ctx, each.key, each.fallback)
		if err != nil {
			return b, wentWrong(in.Logger, "the limits on one action could not be read", err)
		}
		*each.into = n
	}
	return b, nil
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
	parsed, err := time.Parse(time.DateOnly, stated)
	if err != nil {
		return nil, huma.Error422UnprocessableEntity(
			"that is not a date — write it as 2026-03-31")
	}
	parsed = parsed.UTC()
	return &parsed, nil
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
