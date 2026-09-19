package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// ClaimApprovalBody is the body of an approval.
type ClaimApprovalBody struct {
	// Bounded to what the column holds. A name is compared for equality and
	// never read back on its own, so it shares the width of a hash.
	Batch string `json:"batch,omitempty" maxLength:"64" doc:"Name a batch to agree to several claims under one name, so they can be undone together. At most 64 characters"`
	// Except sets rows aside. The remainder is approved as one claim; these go
	// back to the proposer as a claim of their own, with the reason.
	Except  []int64 `json:"except,omitempty" maxItems:"2000" doc:"Decisions in this claim to set aside rather than approve. They return to the proposer as a claim of their own, carrying the reason given in because"`
	Because string  `json:"because,omitempty" doc:"The reason the rows in except are set aside, in markdown. Required when any are"`
}

// ClaimApprovedBody is the record of an approval.
type ClaimApprovedBody struct {
	Approved      int   `json:"approved" doc:"The number of decisions agreed to"`
	ReturnedClaim int64 `json:"returned_claim,omitempty" doc:"The claim the rows set aside went into, where any were"`
}

func registerClaims(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "approve-claim", Method: http.MethodPost, Path: "/v1/claims/{id}/approval",
		Summary: "Approve a claim",
		Description: "Approves every waiting decision in a claim as one action, under the same " +
			"rules each decision is approved under: not by the person who proposed it, and " +
			"against the revision of the reasoning that stands now.\n\n" +
			"Name decisions in `except` to set them aside. The rest is approved; those are " +
			"moved into a claim of their own, marked sent back, and `because` is recorded on " +
			"each as a comment — the same way sending back records a reason. The response " +
			"names that claim.\n\n" +
			"Pass `batch` to approve several claims under one name, undone together with " +
			"`DELETE /v1/approval-batches/{batch}`.\n\n" +
			"Returns 404 for a claim you may not act on every row of, and 409 if you proposed it.",
		Tags: []string{"Triage"},
	}, perProduct, "The proposer may not approve their own.", approveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body ClaimApprovalBody
	}) (*struct{ Body ClaimApprovedBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		done, err := store.ApproveClaim(ctx, subject, input.ID, input.Body.Batch,
			input.Body.Except, input.Body.Because)
		switch {
		case errors.Is(err, triage.ErrSamePerson):
			return nil, huma.Error409Conflict(
				"the person who proposed a claim may not be the one who agrees to it")
		case errors.Is(err, triage.ErrNotTheirs):
			return nil, noSuchClaim()
		case err != nil:
			return nil, refusedDecision(in.Logger, err)
		}

		out := &struct{ Body ClaimApprovedBody }{}
		out.Body.Approved = done.Approved
		if done.Returned != nil {
			out.Body.ReturnedClaim = done.Returned.ID
			// The rows go back to whoever proposed them, and
			// they should hear rather than find out. Logged on
			// failure: the rows are returned either way.
			tell(ctx, in, "could not say that rows were set aside", notify.Telling{
				PersonID: done.Returned.ProposedBy, Kind: notify.SentBack,
				Body: "Part of a claim of yours was set aside: " + input.Body.Because,
				Link: "/review-queue",
				// A claim covers many findings and this path
				// holds the claim rather than any of them, so
				// the disclosure of any one of them cannot be
				// answered from here. Treated as though one
				// is undisclosed: the direction to be wrong in is a link
				// somebody has to follow, not an approver's
				// words about an embargo landing in a mail
				// server.
				Private: true,
				// The product the returned rows are in, which
				// is what a later read narrows by.
				ProductID: &done.ReturnedIn,
			}, "claim", input.ID)
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "send-claim-back", Method: http.MethodPost, Path: "/v1/claims/{id}/send-back",
		Summary: "Send a claim back for more",
		Description: "Asks the author for more before agreeing to any of a claim. Every waiting " +
			"decision in it leaves the review queue together and comes back when the author " +
			"revises.\n\n" +
			"`because` is required and is recorded as a comment on each decision. Needs no " +
			"approval of its own. You cannot send back a claim whose words are your own.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "The proposer may not approve their own.", approveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Because string `json:"because" minLength:"1" doc:"The change being asked for, in markdown"`
		}
	}) (*struct{}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		back, err := store.SendBackClaim(ctx, subject, input.ID, input.Body.Because)
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, refusedDecision(in.Logger, err)
		}
		// Everybody whose words went back is told, and sent to the finding
		// the claim is about: that is where the words are revised, where the
		// review queue lists what waits on an approver and leaves out what
		// waits on its author. The decision itself stands in where no open
		// finding the sender may read describes it any more.
		link := "/decisions/" + strconv.FormatInt(back.Decision.ID, 10)
		if described, err := store.Describe(ctx, subject, []triage.Decision{back.Decision}); err == nil {
			if d, ok := described[back.Decision.ID]; ok {
				link = findingPath(d.ProductName, d.StreamName, d.VariantName,
					d.Issue.Identifier, d.Component) + "?version=" + url.QueryEscape(d.Version)
			}
		} else if err != nil {
			in.logger().Error("could not say which finding a sent-back claim is about",
				"error", err, "claim", input.ID)
		}
		{
			author := back.Author
			tell(ctx, in, "could not say that a claim was sent back", notify.Telling{
				PersonID: author, Kind: notify.SentBack,
				Body: "A claim of yours was sent back: " + input.Body.Because,
				Link: link,
				// The words an approver wrote are about the
				// findings, so they are as private as the most
				// careful of them. Read off the claim rather
				// than off its representative row: that row is
				// chosen by identifier and a claim's rows need
				// not agree.
				Private: back.Undisclosed,
				// Off the representative row, which is a row of
				// this claim and so names its product and its
				// issue.
				ProductID:       &back.Decision.ProductID,
				VulnerabilityID: &back.Decision.VulnerabilityID,
			}, "claim", input.ID, "person", author)
		}
		return &struct{}{}, nil
	})
}

// registerClaimLink is where a claim's work is happening.
func registerClaimLink(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "point-claim-elsewhere", Method: http.MethodPut,
		Path:    "/v1/claims/{id}/elsewhere",
		Summary: "Record where this claim's work is happening",
		Description: "Stores a link to a ticket, a thread or a change — and sends nothing to " +
			"it. A stored link has no egress at all, which is what makes it available to a " +
			"deployment that has not decided to let anything out; the half that *sends* is a " +
			"separate thing a deployment configures.\n\n" +
			"Anybody who may argue about the claim may set it: a link is a note about where " +
			"the conversation is rather than a judgment, and needing a second person for it " +
			"would leave it unset.\n\n" +
			"Sent empty it is cleared. A stale link is worse than none — it sends somebody to " +
			"a ticket that closed for a different reason.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Elsewhere string `json:"elsewhere" maxLength:"1000" doc:"The place the work is happening. Empty clears it"`
		}
	}) (*struct{}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		if err := store.PointAt(ctx, subject, input.ID, input.Body.Elsewhere); err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, refusedDecision(in.Logger, err)
		}
		return &struct{}{}, nil
	})
}

// noSuchClaim is the one answer for a claim that is not there or not yours.
func noSuchClaim() error {
	return huma.Error404NotFound("no such claim")
}

// ReaffirmedBody is the record of one bulk re-affirmation.
type ReaffirmedBody struct {
	ClaimID   int64   `json:"claim_id" doc:"The claim this action made, which is what a second person agrees to where one is needed"`
	Decisions []int64 `json:"decisions"`
	Places    int     `json:"places" doc:"The number of distinct places it covers. A place at two versions in two builds is two decisions, because the versions are what a decision expires on"`
	Waiting   bool    `json:"waiting" doc:"Whether a second person has to agree"`
}

// registerReaffirmClaim re-makes everything one action claimed.
func registerReaffirmClaim(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "reaffirm-claim", Method: http.MethodPost,
		Path:    "/v1/claims/{id}/reaffirmation",
		Summary: "Re-affirm everything one action claimed",
		Description: "Re-makes every row of this claim that stopped applying because an " +
			"upstream version moved, at the versions each place has now, as one act with one " +
			"reasoning.\n\n" +
			"Deciding is bulk-capable and re-deciding was not. A team answering one kernel " +
			"issue writes a decision at each of its places in one action; when the kernel " +
			"moves, those lapse, and restoring them was one request each with a separately " +
			"typed justification.\n\n" +
			"Only the person who made the original may do this. It normally needs no second " +
			"approver, for the reason the single form does not: two people already agreed, and " +
			"a version upgrade is a prompt to re-check rather than a new claim.\n\n" +
			"One act, one approval. Where any row would need approval again — the " +
			"severity has risen since it was agreed to, or nothing was ever agreed to — the " +
			"whole act does. An approver works at the unit the proposer acted at, and agreeing " +
			"to part of an argument they were shown whole is not review.\n\n" +
			"Bounded like the judgment it re-makes. The outcome comes from the claim, so " +
			"re-affirming a bulk dismissal is a bulk judgment and is held to " +
			"`triage.together-cap`; only a promise to upgrade goes through unbounded, because " +
			"the next scan re-checks it.\n\n" +
			"A place that is open nowhere any more is not re-made, which is a finding that " +
			"closed rather than a fault. `reasoning` is required.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, anyPerson, "", triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Reasoning string `json:"reasoning" minLength:"1" doc:"The reason every one of them still holds, in markdown"`
		}
	}) (*struct{ Body ReaffirmedBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		// The bound a bulk judgment is held to, read the way every other bulk
		// path reads it. Only a promise goes through unbounded, and which of
		// the two this is comes from the claim being re-made rather than from
		// the request.
		cap, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
			triage.DefaultTogetherCap)
		if err != nil {
			return nil, wentWrong(in.Logger, "the limit on one action could not be read", err)
		}
		made, err := store.ReaffirmClaim(ctx, subject, triage.ReaffirmingClaim{
			PreviousClaimID: input.ID,
			Reasoning:       input.Body.Reasoning,
			By:              subject.ID,
			Cap:             cap,
		})
		if err != nil {
			if errors.Is(err, triage.ErrNotTheirs) {
				return nil, noSuchClaim()
			}
			return nil, refusedDecision(in.Logger, err)
		}
		return &struct{ Body ReaffirmedBody }{Body: ReaffirmedBody{
			ClaimID: made.ClaimID, Decisions: made.Decisions,
			Places: made.Places, Waiting: made.Waiting,
		}}, nil
	})
}

func claimBody(c triage.Claim, proposedBy string) ClaimBody {
	body := ClaimBody{
		ID: c.ID, Kind: string(c.Kind), ProposedBy: proposedBy,
		ProposedAt: c.ProposedAt.Format(time.RFC3339),
		Elsewhere:  c.Elsewhere,
	}
	if c.DerivedFrom != nil {
		body.DerivedFrom = *c.DerivedFrom
	}
	if c.SelectedBy != nil {
		body.SelectedBy = *c.SelectedBy
	}
	if c.SelectedMatched != nil && c.SelectedNamed != nil {
		body.Selection = &SelectionBody{
			Matched: *c.SelectedMatched, Named: *c.SelectedNamed,
		}
		if c.SelectedWhere != nil {
			body.Selection.Contains = *c.SelectedWhere
		}
	}
	return body
}

func outliersBody(o triage.Outliers) *OutliersBody {
	body := &OutliersBody{
		Exploited: o.Exploited, Severe: o.Severe, Fixable: o.Fixable, Unmatched: o.Unmatched,
		Rows: make([]OutlierBody, 0, len(o.Rows)),
	}
	for _, row := range o.Rows {
		body.Rows = append(body.Rows, OutlierBody{
			DecisionID: row.DecisionID, Vulnerability: row.Vulnerability,
			Severity: row.Severity, Exploited: row.Exploited, FixedIn: row.FixedIn,
			Description: row.Description, Why: row.Why,
		})
	}
	return body
}

// StandingClaimBody is a live claim covering some of a finding's places.
type StandingClaimBody struct {
	ClaimID    int64  `json:"claim_id"`
	Kind       string `json:"kind" enum:"finding,together,extension,returned"`
	DecisionID int64  `json:"decision_id" doc:"A representative row of the claim at this finding"`
	// State is the claim's as a whole, not a representative row's: approved
	// only where every live row here is.
	State string           `json:"state" enum:"proposed,approved" doc:"The claim's state as a whole: approved only when every live row here is approved, otherwise proposed"`
	Rows  RowsStandingBody `json:"rows" doc:"The state of the claim's rows here"`
	// SentBackAt is the last time an approver asked for more, where rows were
	// sent back.
	SentBackAt      string        `json:"sent_back_at,omitempty" doc:"The last time rows were sent back to the author"`
	SentBackBecause string        `json:"sent_back_because,omitempty" doc:"The reason given when they were, in markdown"`
	Outcome         outcome       `json:"outcome"`
	Justification   justification `json:"justification,omitempty"`
	// FixedVersion is the evidence for a claim that the fix is already here,
	// on the screen the claim is read from. Carried by the audit trail alone,
	// the checkable part of the claim is everywhere except where somebody
	// reads the claim.
	FixedVersion  string   `json:"fixed_version,omitempty" doc:"The package version the claim says the fix arrived in, where it claims one has"`
	NeedsApproval bool     `json:"needs_approval,omitempty"`
	ProposedBy    string   `json:"proposed_by"`
	ProposedAt    string   `json:"proposed_at"`
	Places        int      `json:"places" doc:"The number of this finding's places the claim covers"`
	Builds        []string `json:"builds" doc:"Every build the claim currently covers, as stream and variant"`
	ApprovedBy    string   `json:"approved_by,omitempty"`
	ApprovedAt    string   `json:"approved_at,omitempty"`
	// Elsewhere is where this is being worked on outside here.
	Elsewhere string `json:"elsewhere,omitempty" doc:"A ticket, a thread or a change. Stored and never fetched"`
}

// RowsStandingBody counts a claim's live rows by where they stand.
type RowsStandingBody struct {
	Proposed int `json:"proposed" doc:"Waiting for a second person"`
	SentBack int `json:"sent_back" doc:"Returned to the author for more"`
	Approved int `json:"approved" doc:"Agreed to and in force"`
}

// EarlierBody is a decision once made here that no longer applies.
type EarlierBody struct {
	DecisionID    int64         `json:"decision_id"`
	ClaimID       int64         `json:"claim_id"`
	Outcome       outcome       `json:"outcome"`
	Justification justification `json:"justification,omitempty"`
	DeferredUntil string        `json:"deferred_until,omitempty"`
	// FixedVersion is the evidence an approver checks the already-fixed claim
	// against. Agreeing to a claim of fact without being shown the fact is
	// the failure this outcome is most exposed to.
	FixedVersion string `json:"fixed_version,omitempty" doc:"The package version the claim says the fix arrived in, where it claims one has"`
	ProposedBy   string `json:"proposed_by"`
	ProposedAt   string `json:"proposed_at"`
	Ended        string `json:"ended" enum:"lapsed,withdrawn" doc:"The reason it stopped applying"`
	EndedAt      string `json:"ended_at,omitempty"`
	About        string `json:"about,omitempty" doc:"The component upstream version it was a claim about"`
	Reasoning    string `json:"reasoning" doc:"The reasoning as it last stood, in markdown, offered back rather than thrown away"`
	ApprovedBy   string `json:"approved_by,omitempty" doc:"The person who last agreed to it, where anybody did"`
}

// SimilarBody is an approved claim at the same places about another issue,
// which may reach this one.
type SimilarBody struct {
	ClaimID       int64         `json:"claim_id" doc:"Pass as extends when deciding to carry it to this issue"`
	DecisionID    int64         `json:"decision_id"`
	Justification justification `json:"justification,omitempty"`
	Reasoning     string        `json:"reasoning"`
	ApprovedBy    string        `json:"approved_by,omitempty"`
	ApprovedAt    string        `json:"approved_at,omitempty"`
	Issues        int           `json:"issues" doc:"The number of distinct issues the claim covers"`
}

// ElsewhereBody is an approved claim about this same issue at this same place,
// in another product.
//
// Evidence, never an outcome. Offered the way a supplier's VEX statement is:
// something to read and to quote, prefilling a reasoning where somebody asks
// for it and deciding nothing. Another team's judgment about their product is
// not a judgment about this one — the software shipped around the component
// differs, which is why a place is a component at a position rather than a
// component.
type ElsewhereBody struct {
	Product       string        `json:"product" doc:"The product it was decided in"`
	ClaimID       int64         `json:"claim_id"`
	DecisionID    int64         `json:"decision_id"`
	Outcome       outcome       `json:"outcome"`
	Justification justification `json:"justification,omitempty"`
	Reasoning     string        `json:"reasoning"`
	ApprovedBy    string        `json:"approved_by,omitempty"`
	ApprovedAt    string        `json:"approved_at,omitempty"`
}

// decidedAbout gathers what has been decided at a finding's places: what
// stands, what stood before, what was argued about other issues at the same
// places, and what another product decided about this same issue there.
func decidedAbout(ctx context.Context, in Ingest, subject access.Subject, productID, issueID int64,
	at []finding.Deciding) ([]StandingClaimBody, []EarlierBody, []SimilarBody,
	[]ElsewhereBody, error) {

	store := triage.NewStore(in.DB.DB)
	// A standing claim is matched by key — the place and the versions this
	// build ships there — so a decision written against another version of the
	// same place is not reported as standing here. The lapsed and the
	// carryable are asked by place: a lapsed decision no longer matches the
	// versions by definition, and a similar claim is one about other issues at
	// the same place.
	places := make([]string, 0, len(at))
	for _, place := range at {
		places = append(places, place.PlaceIdentity)
	}
	standing, err := store.StandingAt(ctx, subject, productID, issueID, at)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	earlier, err := store.EarlierAt(ctx, subject, productID, issueID, places)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	similar, err := store.SimilarAt(ctx, subject, productID, issueID, places)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// The same issue at the same place in another product. A place identity
	// carries no product, deliberately, so that a place is recognized across
	// variants — and the same key recognizes it across products.
	elsewhere, err := store.DecidedElsewhere(ctx, subject, productID, issueID, places)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	people := []int64{}
	for _, one := range standing {
		people = append(people, one.Claim.ProposedBy, one.ApprovedBy)
	}
	for _, one := range earlier {
		people = append(people, one.Decision.ProposedBy, one.ApprovedBy)
	}
	for _, one := range similar {
		people = append(people, one.ApprovedBy)
	}
	for _, one := range elsewhere {
		people = append(people, one.ApprovedBy)
	}
	names, err := access.NewStore(in.DB.DB).Names(ctx, people)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	standingOut := make([]StandingClaimBody, 0, len(standing))
	for _, one := range standing {
		body := StandingClaimBody{
			ClaimID: one.Claim.ID, Kind: string(one.Claim.Kind), DecisionID: one.Decision.ID,
			State: string(one.State), Outcome: outcome(one.Claim.Outcome),
			Rows: RowsStandingBody{
				Proposed: one.Rows.Proposed, SentBack: one.Rows.SentBack, Approved: one.Rows.Approved,
			},
			SentBackBecause: one.SentBackBecause,
			Justification:   justification(orBlank(one.Claim.Justification)),
			FixedVersion:    orBlank(one.Claim.FixedVersion),
			NeedsApproval:   one.Decision.NeedsApproval,
			ProposedBy:      names[one.Claim.ProposedBy],
			ProposedAt:      one.Claim.ProposedAt.Format(time.RFC3339),
			Places:          one.Places, Builds: one.Builds,
			Elsewhere: one.Claim.Elsewhere,
		}
		if body.Builds == nil {
			body.Builds = []string{}
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy = names[one.ApprovedBy]
			body.ApprovedAt = one.ApprovedAt.Format(time.RFC3339)
		}
		if one.SentBackAt != nil {
			body.SentBackAt = one.SentBackAt.Format(time.RFC3339)
		}
		standingOut = append(standingOut, body)
	}

	earlierOut := make([]EarlierBody, 0, len(earlier))
	for _, one := range earlier {
		d := one.Decision
		// The words are the claim's; the landing place is the row's.
		said := d.Claim
		body := EarlierBody{
			DecisionID: d.ID, ClaimID: d.ClaimID, Outcome: outcome(said.Outcome),
			Justification: justification(orBlank(said.Justification)),
			ProposedBy:    names[d.ProposedBy], ProposedAt: d.ProposedAt.Format(time.RFC3339),
			Ended:     string(d.State),
			About:     orBlank(d.ComponentUpstreamVersion),
			Reasoning: one.Reasoning,
		}
		if said.FixedVersion != nil {
			body.FixedVersion = *said.FixedVersion
		}
		if said.DeferredUntil != nil {
			body.DeferredUntil = said.DeferredUntil.Format(time.DateOnly)
		}
		if d.EndedAt != nil {
			body.EndedAt = d.EndedAt.Format(time.RFC3339)
		}
		if one.ApprovedBy != 0 {
			body.ApprovedBy = names[one.ApprovedBy]
		}
		earlierOut = append(earlierOut, body)
	}

	similarOut := make([]SimilarBody, 0, len(similar))
	for _, one := range similar {
		body := SimilarBody{
			ClaimID: one.Claim.ID, DecisionID: one.Decision.ID,
			Justification: justification(orBlank(one.Claim.Justification)),
			Reasoning:     one.Reasoning, Issues: one.Issues,
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy = names[one.ApprovedBy]
			body.ApprovedAt = one.ApprovedAt.Format(time.RFC3339)
		}
		similarOut = append(similarOut, body)
	}
	products, err := productsDecidedIn(ctx, in, elsewhere)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	elsewhereOut := make([]ElsewhereBody, 0, len(elsewhere))
	for _, one := range elsewhere {
		body := ElsewhereBody{
			Product:       products[one.ProductID],
			ClaimID:       one.Claim.ID,
			DecisionID:    one.Decision.ID,
			Outcome:       outcome(one.Claim.Outcome),
			Justification: justification(orBlank(one.Claim.Justification)),
			Reasoning:     one.Reasoning,
		}
		if one.ApprovedAt != nil {
			body.ApprovedBy = names[one.ApprovedBy]
			body.ApprovedAt = one.ApprovedAt.Format(time.RFC3339)
		}
		elsewhereOut = append(elsewhereOut, body)
	}

	return standingOut, earlierOut, similarOut, elsewhereOut, nil
}

// productsDecidedIn is the names of the products a set of judgments were made
// in, by identifier.
//
// Resolved here rather than carried on the judgment: a name is a fact about the
// catalog, and the read that found the judgments is narrowed by what the
// subject may see — so a name only ever reaches a reader who could already read
// the judgment it belongs to.
func productsDecidedIn(ctx context.Context, in Ingest, rows []triage.Elsewhere) (map[int64]string, error) {
	named := map[int64]string{}
	if len(rows) == 0 {
		return named, nil
	}
	ids := make([]int64, 0, len(rows))
	for _, one := range rows {
		ids = append(ids, one.ProductID)
	}
	var products []catalog.Product
	if err := in.DB.DB.NewSelect().Model(&products).
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which products these were decided in: %w", err)
	}
	for _, product := range products {
		named[product.ID] = product.Name
	}
	return named, nil
}

func orBlank(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
