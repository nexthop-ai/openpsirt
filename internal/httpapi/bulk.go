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
	Severity      string `json:"severity,omitempty" doc:"How bad the report rates it"`
	Places        int    `json:"places" doc:"How many places in this build it sits at"`
	FixedIn       string `json:"fixed_in,omitempty" doc:"The version the report says fixes it, where it names one"`
}

func registerBulk(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-issues-at-component", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/components/{component}/issues",
		Summary: "List the issues open against one component",
		Description: "Returns the distinct issues open against this component in this build, " +
			"most urgent first, with how many places each sits at and the version that fixes " +
			"it where the report names one.\n\n" +
			"`contains` matches the text of a report. It narrows a list; it is not part of any " +
			"claim made afterwards.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Stream    string `path:"stream"`
		Variant   string `path:"variant"`
		Component string `path:"component"`
		Contains  string `query:"contains" doc:"Match the text of the report"`
		Limit     int    `query:"limit" default:"50" minimum:"1" maximum:"500"`
		Offset    int    `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []AtComponentBody `json:"items"`
			Total int               `json:"total"`
			// Findings is how many rows the whole narrowed set
			// holds, and Cap how many one action may write. The
			// two are what sizing a claim needs and what counting
			// issues cannot say: a bound on rows written means a
			// screen counting issues reports 44 where the answer
			// is 2,000.
			Findings int `json:"findings"`
			Cap      int `json:"cap"`
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
		component, err := graph.NewStore(in.DB.DB).ComponentAt(ctx, target, input.Component)
		if err != nil {
			return nil, noSuchFinding()
		}

		at, total, err := finding.NewStore(in.DB.DB).AtComponent(ctx, subject, target, component,
			input.Contains, input.Limit, input.Offset)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		_, reaching, err := finding.NewStore(in.DB.DB).SizeAtComponent(ctx, subject, target,
			component, input.Contains)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		limit, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
			triage.DefaultTogetherCap)
		if err != nil {
			return nil, wentWrong(in.Logger, "the limit on one action could not be read", err)
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
				Items    []AtComponentBody `json:"items"`
				Total    int               `json:"total"`
				Findings int               `json:"findings"`
				Cap      int               `json:"cap"`
			}
		}{}
		out.Body.Findings, out.Body.Cap = reaching, limit
		// One row per issue. AtComponent returns every place, because that is
		// what a decision is written against; this list is what somebody picks
		// from, and the place count is the useful part of it.
		out.Body.Items = make([]AtComponentBody, 0, len(at))
		seen := map[int64]bool{}
		for _, each := range at {
			if seen[each.VulnerabilityID] {
				continue
			}
			seen[each.VulnerabilityID] = true
			out.Body.Items = append(out.Body.Items, AtComponentBody{
				Vulnerability: named[each.VulnerabilityID],
				Severity:      finding.SeverityWord(each.SeverityCenti),
				Places:        each.Places, FixedIn: each.FixedIn,
			})
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
			"Always needs a second person to agree, whatever the outcome.\n\n" +
			"Bounded. At most 2000 names per request, and a limit on how many findings one " +
			"action may write, set under `triage.together-cap`. The limit is checked against " +
			"the findings this resolves to, which is more than the number of names.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Stream    string `path:"stream"`
		Variant   string `path:"variant"`
		Component string `path:"component"`
		Body      struct {
			Vulnerabilities []string      `json:"vulnerabilities" minItems:"1" maxItems:"2000" doc:"The issues this claim covers, by name"`
			SelectedBy      string        `json:"selected_by" minLength:"1" maxLength:"500" doc:"How you narrowed this set. Recorded, and never part of the claim"`
			Outcome         outcomeInBulk `json:"outcome"`
			Justification   justification `json:"justification,omitempty" doc:"Required when it does not apply"`
			DeferredUntil   string        `json:"deferred_until,omitempty" doc:"Required when it is deferred. A date, as 2026-03-31"`
			FixedVersion    string        `json:"fixed_version,omitempty" doc:"Required when the outcome is already-fixed. The package version whoever packages this states the fix arrived in — which must be one release carrying the fix for every issue named, since the claim has to hold for all of them"`
			Reasoning       string        `json:"reasoning" minLength:"1" doc:"Why this holds for every issue named"`
		}
	}) (*struct {
		Body struct {
			ClaimID  int64   `json:"claim_id" doc:"The claim this action made, which is what the review queue lists and what is approved"`
			Recorded int     `json:"recorded"`
			IDs      []int64 `json:"ids"`
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
		component, err := graph.NewStore(in.DB.DB).ComponentAt(ctx, target, input.Component)
		if err != nil {
			return nil, noSuchFinding()
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
			// Which ones, because a person who pasted a list wants to fix the
			// list rather than bisect it.
			return nil, huma.Error404NotFound(
				"no issue is filed under " + strings.Join(clipped(unknown), ", "))
		}

		cap, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
			triage.DefaultTogetherCap)
		if err != nil {
			return nil, wentWrong(in.Logger, "the limit on one action could not be read", err)
		}

		// The places are resolved inside the write, not here. Reading
		// them first and passing them in would authorize this against
		// rows as they stood before the transaction, and would let a
		// caller's selection decide which places a decision lands on.
		claimID, recorded, err := store.Together(ctx, subject, triage.TogetherAt{
			TargetID: target, ComponentID: component, VulnerabilityIDs: issues,
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
		}, cap)
		if err != nil {
			if errors.Is(err, triage.ErrNothingOpen) {
				return nil, huma.Error404NotFound(
					"none of those are open against that component any more")
			}
			return nil, refusedDecision(in.Logger, err)
		}

		out := &struct {
			Body struct {
				ClaimID  int64   `json:"claim_id" doc:"The claim this action made, which is what the review queue lists and what is approved"`
				Recorded int     `json:"recorded"`
				IDs      []int64 `json:"ids"`
			}
		}{}
		out.Body.ClaimID = claimID
		out.Body.Recorded = len(recorded)
		out.Body.IDs = recorded
		return out, nil
	})
}

// deferredUntil reads the date a postponement runs to.
//
// Required when something is deferred, and refused otherwise. "Deferred" was
// offered as an outcome here with nowhere to say until when, which recorded a
// postponement with no end — the one thing a deferral has to have, since the
// threshold that decides whether a second person must agree is measured
// against it.
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
