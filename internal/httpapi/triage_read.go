// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// DecisionDetail is a decision with everything needed to understand it without
// asking again: where it applies, what it says, and how far it has got.
type DecisionDetail struct {
	Decision DecisionBody `json:"decision"`
	Place    PlaceBody    `json:"place"`
	// Finding is the decision's subject, where an open finding still sits at
	// its place. Absent where none does.
	Finding        *FindingRefBody `json:"finding,omitempty" doc:"The decision's subject — build, issue, component, where it sits — read from the open finding at its place. Absent where none is open there"`
	Reasoning      string          `json:"reasoning" doc:"The justification as it currently stands, in markdown"`
	ProposedBy     string          `json:"proposed_by" doc:"The person who made the claim, by sign-in identity"`
	ProposedByName string          `json:"proposed_by_name,omitempty" doc:"Their display name, where they have one"`
	ProposedAt     string          `json:"proposed_at" doc:"The moment the claim was made"`
	AgeDays        int             `json:"age_days" doc:"The age of the claim. An old judgment should look like one"`
}

// ClaimDetail is one claim, whole: its argument, its landing place, its
// present reach, and its fate.
//
// Everything on it is at claim scope. A claim is one argument, and a page
// built on a representative row reports the row's state as the claim's — one
// row approved beside forty-three sent back reading as approved, which is the
// defect the claim grain exists to prevent.
type ClaimDetail struct {
	Claim ClaimBody `json:"claim" doc:"The actor, the moment, the sort of action, the narrowing behind a bulk set, and where the work is happening"`
	// Argument is the claim's own words, reasoning included. It names no
	// decision and carries no state: those belong to rows, and nothing here
	// acts on one.
	Argument DecisionBody `json:"argument" doc:"The claim's contents: the outcome, the reason, the dates, the version an upgrade moves to, and the justification as it currently stands"`
	// Place is where a representative row sits — the earliest — and Finding is
	// its subject, so the page has somewhere to link to.
	Place   PlaceBody       `json:"place"`
	Finding *FindingRefBody `json:"finding,omitempty" doc:"A representative row's subject — build, issue, component, where it sits. Absent where no open finding sits at its place"`
	AgeDays int             `json:"age_days" doc:"The age of the claim. An old judgment should look like one"`
	// Happened is the claim's fate, read from its rows.
	Happened string `json:"happened" enum:"waiting,sent-back,approved,withdrawn,lapsed,undone,mixed" doc:"The claim's outcome. mixed is a claim whose rows did not all end the same way"`
	When     string `json:"when,omitempty" doc:"The moment it became that. Absent while it is waiting: nothing has happened to it"`
	By       string `json:"by,omitempty" doc:"The person who did it, where a person did, by sign-in identity"`
	ByName   string `json:"by_name,omitempty" doc:"Their display name, where they have one"`
	// PreviouslyApproved says this was agreed to before and came back —
	// revised under the approval, or the code moved.
	PreviouslyApproved bool `json:"previously_approved,omitempty" doc:"This was agreed to before and came back"`
	// Rows is the decisions the claim wrote.
	Rows   int `json:"rows" doc:"The number of decisions the claim wrote"`
	Issues int `json:"issues" doc:"The number of distinct issues it covers"`
	Places int `json:"places" doc:"The number of distinct places it wrote at. The bulk cap is measured against this"`
	// Folds is its present reach. A claim reaches by matching, so this grows
	// as builds appear with nobody acting; the reach an approver agreed to is
	// on the approval.
	Folds     int      `json:"folds" doc:"The number of things to decide about"`
	Packages  int      `json:"packages" doc:"The number of binaries those fold together"`
	Consumers int      `json:"consumers" doc:"The number of things pulling them in"`
	Findings  int      `json:"findings" doc:"The number of findings underneath, which is what the disposition register expands to"`
	Builds    []string `json:"builds" doc:"Every build the claim currently covers, as stream and variant"`
	// Outliers is the rows of a bulk set that do not look like the rest.
	Outliers *OutliersBody `json:"outliers,omitempty" doc:"For a claim over many issues: the rows that do not look like the rest, and how many there are"`
	// Undisclosed says at least one row is about a finding nobody has
	// announced. A screen uses it to offer the right people to name: the set
	// that may be mentioned follows the visibility of what is being discussed,
	// and a claim is as careful as its most careful row.
	Undisclosed bool `json:"undisclosed,omitempty" doc:"At least one row is about a finding nobody has announced"`
}

// claimArgument renders what a claim says, with the reasoning it currently
// rests on.
//
// The argument fields of a decision and none of the row ones. A decision's
// identifier and its state belong to the row, and a claim page that carried
// either would be offering an act at the wrong grain.
func claimArgument(c triage.Claim, reasoning string) DecisionBody {
	body := DecisionBody{ClaimID: c.ID, Outcome: outcome(c.Outcome), Reasoning: reasoning}
	if c.Justification != nil {
		body.Justification = justification(*c.Justification)
	}
	if c.Mitigation != nil {
		body.Mitigation = *c.Mitigation
	}
	if c.FixedVersion != nil {
		body.FixedVersion = *c.FixedVersion
	}
	if c.DeferredUntil != nil {
		body.DeferredUntil = c.DeferredUntil.Format(time.DateOnly)
	}
	if c.CommittedTo != nil {
		body.CommittedTo = c.CommittedTo.Format(time.DateOnly)
	}
	if c.UpgradeTo != nil {
		body.UpgradeTo = *c.UpgradeTo
	}
	return body
}

// RevisionBody is one statement of a justification.
type RevisionBody struct {
	ID            int64  `json:"id" doc:"The identifier an approval names when it says which words were agreed to"`
	Ordinal       int64  `json:"ordinal" doc:"The revision number, counting from one"`
	Body          string `json:"body" doc:"The justification text, in markdown"`
	WrittenBy     string `json:"written_by" doc:"The author, by sign-in identity"`
	WrittenByName string `json:"written_by_name,omitempty" doc:"Their display name, where they have one"`
	WrittenAt     string `json:"written_at"`
}

// ApprovalBody is one person agreeing to one revision of a justification.
type ApprovalBody struct {
	ID             int64  `json:"id"`
	RevisionID     int64  `json:"revision_id" doc:"The revision of the justification that was agreed to"`
	ApprovedBy     string `json:"approved_by" doc:"The person who agreed, by sign-in identity"`
	ApprovedByName string `json:"approved_by_name,omitempty" doc:"Their display name, where they have one"`
	ApprovedAt     string `json:"approved_at"`
	WithdrawnAt    string `json:"withdrawn_at,omitempty" doc:"The moment this approval was taken back, if it was"`
	Batch          string `json:"batch,omitempty" doc:"The batch it was approved under, if it was a bulk approval"`
	// Covered is how many findings the claim covered when this approval was
	// given. A decision reaches by matching, so it covers more as builds
	// appear — and against the present reach it states the growth: agreed
	// covering six, now covering sixty-one.
	Covered int `json:"covered,omitempty" doc:"Findings this covered when it was agreed to"`
	// CarriedFrom names the agreement this one was carried forward from,
	// where a re-affirmation stood on the agreement its predecessor had. The
	// approver named here read that claim's reasoning rather than this one's.
	CarriedFrom int64 `json:"carried_from,omitempty" doc:"The approval this was carried forward from, where a re-affirmation stood on an earlier agreement rather than a fresh one"`
}

// CommentBody is one remark on a decision.
type CommentBody struct {
	ID            int64  `json:"id"`
	Body          string `json:"body" doc:"The comment text, in markdown"`
	WrittenBy     string `json:"written_by" doc:"The author, by sign-in identity"`
	WrittenByName string `json:"written_by_name,omitempty" doc:"Their display name, where they have one"`
	WrittenAt     string `json:"written_at"`
	EditedAt      string `json:"edited_at,omitempty" doc:"The moment the author last changed it, if they did"`
}

func registerTriageReading(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-decisions", Method: http.MethodGet, Path: "/v1/decisions",
		Summary: "List triage decisions",
		Description: "Returns triage decisions on products you may triage, newest first, with " +
			"the justification text for each.\n\n" +
			"Filter by `outcome` to list dismissals (`not-applicable`, `mismatched`, " +
			"`wont-fix`, `already-fixed`) or " +
			"postponements (`deferred`), by `state` to separate what is approved from what is " +
			"still waiting or has been withdrawn, and by `product` to limit to one product.\n\n" +
			"Set `expired=true` to list deferrals whose date has passed — the findings that have " +
			"come back and need judging again.\n\n" +
			"Set `stopped=true` for everything that has stopped standing — lapsed decisions and " +
			"expired deferrals as one list. A decision can be both, so asking the two separately " +
			"and adding the totals counts some of them twice.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string  `query:"product" doc:"Limit to one product, by name"`
		Outcome outcome `query:"outcome" doc:"Limit to one outcome"`
		State   string  `query:"state" enum:"proposed,approved,withdrawn,lapsed" doc:"Limit to one state"`
		Expired bool    `query:"expired" doc:"Only deferrals whose date has passed"`
		Stopped bool    `query:"stopped" doc:"Lapsed decisions and expired deferrals as one list. A decision can be both, so the two asked separately do not add up"`
		Limit   int     `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset  int     `query:"offset" minimum:"0"`
	}) (*DecisionsOutput, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}

		filter := triage.Filter{Expired: input.Expired, Stopped: input.Stopped}
		if input.Outcome != "" {
			filter.Outcomes = []triage.Outcome{triage.Outcome(input.Outcome)}
		}
		if input.State != "" {
			filter.States = []triage.State{triage.State(input.State)}
		}
		if input.Product != "" {
			// Visible rather than merely declared. Resolving the
			// name first and narrowing the rows afterwards answers
			// 200 with nothing for a product somebody holds
			// nothing on and 404 for a name nobody ever declared,
			// which is a way to read the deployment's product list
			// one guess at a time.
			product, err := catalog.NewStore(in.DB.DB).
				VisibleProduct(ctx, subject, input.Product)
			if err != nil {
				return nil, noSuchProduct()
			}
			filter.ProductIDs = []int64{product.ID}
		}

		decisions, reasoning, total, err := store.List(ctx, subject, filter, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what was decided could not be read", err)
		}
		details, err := describeDecisions(ctx, in, store, decisions, reasoning)
		if err != nil {
			return nil, wentWrong(in.Logger, "what was decided could not be read", err)
		}
		out := &DecisionsOutput{}
		out.Body.Items = details
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-decision", Method: http.MethodGet, Path: "/v1/decisions/{id}",
		Summary: "Get a triage decision",
		Description: "Returns one decision with the justification as it currently stands, where " +
			"it applies, who proposed it and how long it has stood.\n\n" +
			"What it says — the outcome, the justification, the dates — belongs to the claim " +
			"it is one row of, at `claim_id`. For the earlier justifications see " +
			"`GET /v1/claims/{id}/revisions`, and for who agreed to which of them see " +
			"`GET /v1/claims/{id}/approvals`.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{ Body DecisionDetail }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		decision, reasoning, err := store.Read(ctx, subject, input.ID)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		details, err := describeDecisions(ctx, in, store, []triage.Decision{*decision},
			map[int64]string{decision.ID: reasoning})
		if err != nil || len(details) == 0 {
			return nil, wentWrong(in.Logger, "that decision could not be read", err)
		}
		return &struct{ Body DecisionDetail }{Body: details[0]}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-claim", Method: http.MethodGet, Path: "/v1/claims/{id}",
		Summary: "Get a claim",
		Description: "Returns one claim whole: what it says, where it lands, what it covers " +
			"now, and what became of it.\n\n" +
			"A claim is one proposer's action however many decisions it wrote, so the " +
			"outcome, the reason, the dates and the version are the claim's rather than any " +
			"row's. `happened` reads the claim as a whole — `mixed` where its rows did not " +
			"all end the same way — and `argument` names no decision, because nothing here " +
			"acts on one.\n\n" +
			"`rows`, `issues` and `places` are what it wrote. `folds`, `packages`, " +
			"`consumers` and `findings` are what it covers now, which grows as builds " +
			"appear with nobody acting; what somebody consented to is on the approval, at " +
			"`GET /v1/claims/{id}/approvals`.\n\n" +
			"For the earlier justifications see `GET /v1/claims/{id}/revisions` and for the " +
			"discussion `GET /v1/claims/{id}/comments`.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only claims you may read every row of."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{ Body ClaimDetail }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		whole, err := store.Whole(ctx, subject, input.ID)
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, wentWrong(in.Logger, "that claim could not be read", err)
		}
		described, err := describeDecisions(ctx, in, store, []triage.Decision{whole.Decision},
			map[int64]string{whole.Decision.ID: whole.Reasoning})
		if err != nil || len(described) == 0 {
			return nil, wentWrong(in.Logger, "that claim could not be read", err)
		}
		about := described[0]

		body := ClaimDetail{
			Claim:              claimBody(whole.Claim, about.ProposedBy, about.ProposedByName),
			Argument:           claimArgument(whole.Claim, whole.Reasoning),
			Place:              about.Place,
			Finding:            about.Finding,
			AgeDays:            about.AgeDays,
			Happened:           string(whole.Happened),
			PreviouslyApproved: whole.PreviouslyApproved,
			Rows:               whole.Rows,
			Issues:             whole.Issues,
			Places:             whole.Places,
			Folds:              whole.Reach.Folds,
			Packages:           whole.Reach.Packages,
			Consumers:          whole.Reach.Consumers,
			Findings:           whole.Reach.Findings,
			Builds:             whole.Builds,
			Undisclosed:        whole.Undisclosed,
		}
		if whole.When != nil {
			body.When = whole.When.UTC().Format(time.RFC3339)
		}
		if whole.By != 0 {
			who, err := whoSigned(ctx, in.DB.DB, []int64{whole.By})
			if err != nil {
				return nil, wentWrong(in.Logger, "that claim could not be read", err)
			}
			body.By, body.ByName = who.identity(whole.By), who.label(whole.By)
		}
		if whole.Outliers != nil {
			body.Outliers = outliersBody(*whole.Outliers)
		}
		return &struct{ Body ClaimDetail }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-claim-revisions", Method: http.MethodGet,
		Path:    "/v1/claims/{id}/revisions",
		Summary: "List a claim's justification history",
		Description: "Returns every revision of the justification, oldest first, with who wrote " +
			"each and when.\n\n" +
			"A claim is one argument however many places it covers, so its reasoning is one text " +
			"with one history. An approval names the specific revision that was agreed to, so " +
			"this is how to read what an approver actually saw rather than what the text says " +
			"now.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*listOutput[RevisionBody], error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		revisions, err := store.Revisions(ctx, subject, input.ID)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}

		authors := make([]int64, 0, len(revisions))
		for _, revision := range revisions {
			authors = append(authors, revision.WrittenBy)
		}
		who, err := whoSigned(ctx, in.DB.DB, authors)
		if err != nil {
			return nil, wentWrong(in.Logger, "the reasoning could not be read", err)
		}

		out := &listOutput[RevisionBody]{}
		out.Body.Items = make([]RevisionBody, 0, len(revisions))
		for _, revision := range revisions {
			out.Body.Items = append(out.Body.Items, RevisionBody{
				ID: revision.ID, Ordinal: revision.Ordinal, Body: revision.Body,
				WrittenBy:     who.identity(revision.WrittenBy),
				WrittenByName: who.label(revision.WrittenBy),
				WrittenAt:     revision.WrittenAt.Format(time.RFC3339),
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-claim-approvals", Method: http.MethodGet,
		Path:    "/v1/claims/{id}/approvals",
		Summary: "List who approved a claim",
		Description: "Returns every approval recorded against this claim, including ones later " +
			"withdrawn, each naming the revision of the justification it was given for.\n\n" +
			"An approval carrying `carried_from` was not given for this claim. A " +
			"re-affirmation states its own reasoning and stands on the agreement its " +
			"predecessor had, so the person named agreed to the earlier claim's words; " +
			"`carried_from` is the approval where those are.\n\n" +
			"A withdrawn approval is kept rather than deleted: who agreed to what, and when it " +
			"stopped counting, is part of the record.\n\n" +
			"`covered` is how many findings the claim covered when it was agreed to. A claim " +
			"applies to every build running the same versions, so it covers more as builds " +
			"appear — with nobody acting, and nobody having agreed to the larger number. " +
			"Comparing this against what it covers now is the point of keeping it.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*listOutput[ApprovalBody], error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		approvals, err := store.Approvals(ctx, subject, input.ID)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}

		approvers := make([]int64, 0, len(approvals))
		for _, approval := range approvals {
			approvers = append(approvers, approval.ApprovedBy)
		}
		who, err := whoSigned(ctx, in.DB.DB, approvers)
		if err != nil {
			return nil, wentWrong(in.Logger, "who agreed could not be read", err)
		}

		out := &listOutput[ApprovalBody]{}
		out.Body.Items = make([]ApprovalBody, 0, len(approvals))
		for _, approval := range approvals {
			body := ApprovalBody{
				ID: approval.ID, RevisionID: approval.RevisionID,
				ApprovedBy:     who.identity(approval.ApprovedBy),
				ApprovedByName: who.label(approval.ApprovedBy),
				ApprovedAt:     approval.ApprovedAt.Format(time.RFC3339),
			}
			if approval.WithdrawnAt != nil {
				body.WithdrawnAt = approval.WithdrawnAt.Format(time.RFC3339)
			}
			if approval.Batch != nil {
				body.Batch = *approval.Batch
			}
			if approval.Covered != nil {
				body.Covered = *approval.Covered
			}
			if approval.CarriedFrom != nil {
				body.CarriedFrom = *approval.CarriedFrom
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}

// describeDecisions fills in the names a decision refers to by identifier.
//
// A row saying product 4, issue 91 is a row somebody has to make two more
// requests to understand, and the lists this feeds are exactly where that
// happens fifty times.
func describeDecisions(ctx context.Context, in Ingest, store *triage.Store,
	decisions []triage.Decision, reasoning map[int64]string) ([]DecisionDetail, error) {

	people := make([]int64, 0, len(decisions))
	products := make([]int64, 0, len(decisions))
	issues := make([]int64, 0, len(decisions))
	for _, decision := range decisions {
		people = append(people, decision.ProposedBy)
		products = append(products, decision.ProductID)
		issues = append(issues, decision.VulnerabilityID)
	}

	who, err := whoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return nil, err
	}
	productNames, err := catalog.NewStore(in.DB.DB).ProductNames(ctx, products)
	if err != nil {
		return nil, err
	}
	issueNames, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, err
	}
	subject, err := reading(ctx)
	if err != nil {
		return nil, err
	}
	described, err := store.Describe(ctx, subject, decisions)
	if err != nil {
		return nil, err
	}

	details := make([]DecisionDetail, 0, len(decisions))
	for _, decision := range decisions {
		details = append(details, DecisionDetail{
			Finding:  findingRef(described, decision.ID),
			Decision: decisionBody(decision),
			Place: PlaceBody{
				Product:       productNames[decision.ProductID],
				Vulnerability: issueNames[decision.VulnerabilityID],
				Place:         decision.PlaceIdentity,
			},
			Reasoning:      reasoning[decision.ID],
			ProposedBy:     who.identity(decision.ProposedBy),
			ProposedByName: who.label(decision.ProposedBy),
			ProposedAt:     decision.ProposedAt.Format(time.RFC3339),
			AgeDays:        int(store.Age(&decision).Hours() / 24),
		})
	}
	return details, nil
}

// findingRef renders a decision's subject, where an open finding sits at its
// place.
func findingRef(described map[int64]triage.Described, decisionID int64) *FindingRefBody {
	d, ok := described[decisionID]
	if !ok {
		return nil
	}
	body := &FindingRefBody{
		Product: d.Product, Stream: d.Stream, Variant: d.Variant,
		Vulnerability: d.Issue.Identifier, Component: d.Component, Version: d.Version,
		Severity: d.Issue.InForce(), Exploited: d.Issue.Exploited,
		FixState: d.FixState, FixedIn: d.FixedIn,
		Description: excerpt(d.Issue.Description, 400),
		Owner:       d.Owner, Parent: d.Parent,
		Places: d.Places, Decided: d.Decided,
	}
	if d.Issue.ScoreCenti != nil {
		// The scheme with the number. Two are scorable and their numbers are
		// not comparable, so a card carrying one without the other invites
		// somebody approving a claim to weigh it against the last one.
		body.Score = float64(*d.Issue.ScoreCenti) / 100
		body.ScoreVersion = d.Issue.ScoreVersion
	}
	return body
}

// excerpt shortens text to n characters on a rune boundary.
func excerpt(text string, n int) string {
	runes := []rune(text)
	if len(runes) <= n {
		return text
	}
	return string(runes[:n]) + "\u2026"
}

// StandingBody is the decision in force at a place, and the ones before it.
type StandingBody struct {
	// Standing is the decision suppressing this finding, absent where nothing
	// is. Absent is the ordinary answer for a finding nobody has judged.
	Standing *DecisionDetail `json:"standing,omitempty"`
	// Previously is the decisions made here before, newest first: claims that
	// were withdrawn, and claims the code moved out from under. It is what
	// makes re-deciding a re-reading rather than a blank page.
	Previously []DecisionDetail `json:"previously"`
}

func registerPlaceDecisions(api huma.API, in Ingest) {
	const at = "/v1/products/{product}/streams/{stream}/variants/{variant}" +
		"/findings/{vulnerability}/places/{place}/decision"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-finding-decision", Method: http.MethodGet, Path: at,
		Summary: "Get what has been decided about a finding",
		Description: "Returns the decision currently suppressing this finding, if any, together " +
			"with everything decided here before — withdrawn claims, and claims that stopped " +
			"applying when an upstream version changed.\n\n" +
			"`standing` is absent when nothing has been decided, or when a claim is still waiting " +
			"for approval: a claim nobody has agreed to suppresses nothing.\n\n" +
			"Read `previously` before deciding again. A claim that lapsed on a version upgrade is " +
			"usually still the right answer, and re-affirming it is a different request from " +
			"making a new one.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Place         string `path:"place" doc:"The place, as the findings list gives it"`
	}) (*struct{ Body StandingBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		where, _, err := decidingAbout(ctx, in, subject, input.Product, input.Stream, input.Variant,
			input.Vulnerability, input.Place)
		if err != nil {
			return nil, err
		}
		place := triage.Place{
			ProductID: where.ProductID, VulnerabilityID: where.VulnerabilityID,
			PlaceIdentity: where.PlaceIdentity, Visibility: where.Visibility,
			ComponentUpstream: where.ComponentUpstream, ConsumerUpstream: where.ConsumerUpstream,
		}

		standing, err := store.Applying(ctx, place)
		if err != nil {
			return nil, wentWrong(in.Logger, "what applies here could not be read", err)
		}
		previously, err := store.PreviouslyAt(ctx, subject, place)
		if err != nil {
			return nil, wentWrong(in.Logger, "what was decided here could not be read", err)
		}

		all := previously
		if standing != nil {
			all = append([]triage.Decision{*standing}, previously...)
		}
		reasoning, err := store.ReasoningFor(ctx, all)
		if err != nil {
			return nil, wentWrong(in.Logger, "the reasoning could not be read", err)
		}
		details, err := describeDecisions(ctx, in, store, all, reasoning)
		if err != nil {
			return nil, wentWrong(in.Logger, "what was decided here could not be read", err)
		}

		body := StandingBody{Previously: []DecisionDetail{}}
		if standing != nil {
			body.Standing = &details[0]
			details = details[1:]
		}
		body.Previously = append(body.Previously, details...)
		return &struct{ Body StandingBody }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "reaffirm-decision", Method: http.MethodPost, Path: at + "/reaffirmation",
		Summary: "Re-affirm a decision after an upstream version changed",
		Description: "Re-makes a decision that stopped applying because an upstream version " +
			"moved, at the versions this finding has now. `previous` is the decision being " +
			"re-made, from `previously` in `GET .../decision`.\n\n" +
			"Only the person who made the original may do this, and it normally needs no second " +
			"approver: two people already agreed to the claim, and a version upgrade is a prompt to " +
			"re-check rather than a new claim.\n\n" +
			"It does need approval again if the vulnerability's severity has risen since the " +
			"original was agreed to, or if nothing was ever agreed to. What was agreed was " +
			"that this did not matter much, which is not an agreement about what it has " +
			"become. The response says whether a second person is needed.\n\n" +
			"Where no second person is needed, the earlier agreement is carried onto the new " +
			"claim and recorded as carried. The approver named agreed to the previous " +
			"claim's reasoning, not to what is written here.\n\n" +
			"`reasoning` is required. \"Still true\" with nothing behind it is what a " +
			"re-affirmation becomes when it is made too easy.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Place         string `path:"place"`
		Body          struct {
			Previous  int64  `json:"previous" doc:"The decision being re-made"`
			Reasoning string `json:"reasoning" minLength:"1" doc:"The reason it still holds, in markdown"`
		}
	}) (*struct{ Body DecisionBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		where, _, err := decidingAbout(ctx, in, subject, input.Product, input.Stream, input.Variant,
			input.Vulnerability, input.Place)
		if err != nil {
			return nil, err
		}

		made, err := store.Reaffirm(ctx, subject, triage.Reaffirmation{
			PreviousID: input.Body.Previous,
			Place: triage.Place{
				ProductID: where.ProductID, VulnerabilityID: where.VulnerabilityID,
				PlaceIdentity: where.PlaceIdentity, Visibility: where.Visibility,
				ComponentUpstream: where.ComponentUpstream, ConsumerUpstream: where.ConsumerUpstream,
			},
			Reasoning: input.Body.Reasoning,
			By:        subject.ID,
		})
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}

		body := decisionBody(*made)
		body.Reasoning = input.Body.Reasoning
		body.NeedsApproval = made.NeedsApproval
		return &struct{ Body DecisionBody }{Body: body}, nil
	})
}
