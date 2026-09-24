// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// DecisionBody is a claim about a finding.
type DecisionBody struct {
	ID int64 `json:"id,omitempty" doc:"The name for this decision in a later request"`
	// ClaimID is the action this row was written by. The review queue lists
	// claims and approval works on them; a decision is one row of one.
	ClaimID int64   `json:"claim_id,omitempty" doc:"The claim this decision is one row of: the action that wrote it, which is what the review queue lists and what is approved"`
	Outcome outcome `json:"outcome" doc:"The outcome"`
	// Justification is required for not-applicable and meaningless elsewhere:
	// the claim that something does not affect us names one of the recognized
	// reasons.
	Justification justification `json:"justification,omitempty" doc:"The reason it does not apply. Required when it does not"`
	// Mitigation is the one claim here that rests on configuration rather
	// than on code, so it is the one thing nothing will notice going away.
	// Naming it does not fix that; it makes the claim checkable.
	Mitigation    string `json:"mitigation,omitempty" maxLength:"65536" doc:"The mitigation that stops it — the rule, the setting, the service that is not exposed. Required when the reason is that mitigations already exist, optional when the outcome is that this will not be fixed, and refused otherwise"`
	DeferredUntil string `json:"deferred_until,omitempty" doc:"The date a deferral returns. Required for a deferral"`
	// FixedVersion makes the already-fixed claim checkable against whoever
	// packages the component, rather than something taken on trust.
	FixedVersion string `json:"fixed_version,omitempty" doc:"The package version whoever packages this states the fix arrived in. Required when the outcome is already-fixed, and refused with any other. Recorded and never compared against the version shipping"`
	// CommittedTo is when the work an outcome promises will be done, for
	// the two that promise work. Without it there is nothing to gate
	// against and nothing to lapse.
	CommittedTo string `json:"committed_to,omitempty" doc:"The date the promised work lands. Required for patch-needed and upgrade-needed, and refused with any other"`
	// UpgradeTo is the version an upgrade moves to. Written by the component
	// screen rather than here: a bump answers a component, not one finding.
	UpgradeTo string `json:"upgrade_to,omitempty" doc:"The version an upgrade moves to. Carried on an upgrade-needed decision, which is recorded from a component rather than from one finding"`
	Reasoning string `json:"reasoning" minLength:"1" doc:"The reasoning, in markdown. Somebody else has to agree with this"`
	// FromStatement cites a VEX statement this was started from. A citation
	// and never an application: their statement is not this claim, and the
	// citation is what lets a later revision be noticed.
	FromStatement int64  `json:"from_statement,omitempty" doc:"A VEX statement this was started from, by its identifier. Recorded as a citation so a later revision to it raises an alert. It is never what the claim rests on"`
	State         string `json:"state,omitempty" enum:"proposed,approved,withdrawn,lapsed" doc:"The state it has reached"`
	// NeedsApproval says whether this is waiting for a second person. A short
	// deferral is not.
	NeedsApproval bool `json:"needs_approval,omitempty" doc:"Whether a second person has to agree before it takes effect"`
	// Places is how many findings this one judgment covers. A kernel issue
	// reaches dozens of modules and the answer is usually the same for all of
	// them, so whoever is deciding is told the size of what they are deciding.
	Places int `json:"places,omitempty" doc:"The number of findings this decision covers"`
	// Versions is how many distinct versions sit at this place. More than one
	// means a single decision cannot honestly cover all of them.
	Versions int `json:"versions,omitempty" doc:"The number of versions of the component here. More than one needs care"`
	// SentBackAt is when an approver last asked for more before they would
	// agree. Reported, because otherwise the only trace of it is a comment,
	// and the author's own list cannot tell a claim waiting on somebody else
	// from one waiting on them.
	SentBackAt string `json:"sent_back_at,omitempty" doc:"The last time an approver asked for more. Empty means nobody has"`
	// SelectedBy is the narrowing behind the set, where this claim was one of
	// many recorded in a single action. Reported so the choice of set has an
	// answer months later.
	SelectedBy string `json:"selected_by,omitempty" doc:"The narrowing behind a claim recorded as one of many. Never part of the claim itself"`
}

// FindingRefBody is the subject of a decision, as the findings list shows it:
// the build to link to, the issue, the component and where it sits.
type FindingRefBody struct {
	Product       string  `json:"product" doc:"The build to link to, by product, branch or tag, and variant. The product by the name that addresses it"`
	ProductName   string  `json:"product_name,omitempty" doc:"The product's display name, where it has one"`
	Stream        string  `json:"stream"`
	StreamName    string  `json:"stream_name,omitempty" doc:"The branch or tag as it was spelled, where that differs from its name"`
	Variant       string  `json:"variant"`
	VariantName   string  `json:"variant_name,omitempty" doc:"The variant as it was spelled, where that differs from its name"`
	Vulnerability string  `json:"vulnerability" doc:"The issue, under the name it is most widely known by"`
	Component     string  `json:"component"`
	Version       string  `json:"version" doc:"The version that ships"`
	Severity      string  `json:"severity,omitempty" doc:"Our rating where one stands, else as published"`
	Score         float64 `json:"score,omitempty"`
	ScoreVersion  string  `json:"score_version,omitempty" doc:"The scoring system the number is on"`
	Exploited     bool    `json:"exploited,omitempty"`
	FixState      string  `json:"fix_state,omitempty" enum:"fixed,none,wont-fix,unknown,mixed"`
	FixedIn       string  `json:"fixed_in,omitempty"`
	Description   string  `json:"description,omitempty" doc:"The first four hundred characters of what the report says, as plain text"`
	Owner         string  `json:"owner,omitempty" doc:"The part of the product this belongs to"`
	Parent        string  `json:"parent,omitempty" doc:"The component that directly pulls it in, which is what the decision is about"`
	Places        int     `json:"places" doc:"The number of places the issue sits at in that component in that build"`
	Decided       int     `json:"decided" doc:"The number of those this claim covers"`
}

// PlaceBody names what a decision is about.
//
// Stated by the caller and checked against what is stored, rather than taken
// on trust: it is assembled from a finding, and a caller that could name a
// place freely would be choosing which decisions apply where.
type PlaceBody struct {
	Product       string `json:"product" minLength:"1" doc:"The product, by the name that addresses it"`
	ProductName   string `json:"product_name,omitempty" readOnly:"true" doc:"The product's display name, where it has one"`
	Vulnerability string `json:"vulnerability" minLength:"1" doc:"The issue, by any name it is known under"`
	Place         string `json:"place" minLength:"1" doc:"The place in the build, as the findings list gives it"`
}

// SelectionBody is the narrowing behind a bulk claim, re-run when the claim was
// written.
//
// Two counts rather than a sentence. A claim reading "drivers this image
// does not build" over a set chosen by ticking everything is indistinguishable
// in the record from an honest one. Equal counts mean the claim is exactly what
// that narrowing returns; far apart, the sentence does not describe the set.
type SelectionBody struct {
	Contains string `json:"contains,omitempty" doc:"The text the candidate list was narrowed by. Absent where it was not narrowed, which means every issue at the component was on the page"`
	Matched  int    `json:"matched" doc:"The number of issues that narrowing reached when the claim was written, read here rather than taken from the caller"`
	Named    int    `json:"named" doc:"The number the claim was then made about"`
}

// ClaimBody is one proposer's action: what the review queue lists and what an
// approver agrees to.
type ClaimBody struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind" enum:"finding,together,extension,returned" doc:"The sort of action: one judgment about a finding, one about many issues at a component, an approved claim carried to a new issue, or rows set aside from a larger claim — by an approver agreeing to the rest, or by the author holding them back"`
	DerivedFrom int64  `json:"derived_from,omitempty" doc:"The claim this one came from, for an extension or a returned set"`
	ProposedBy  string `json:"proposed_by" doc:"The person who took it, by sign-in identity"`
	// ProposedByName is the label beside the identity.
	ProposedByName string `json:"proposed_by_name,omitempty" doc:"Their display name, where they have one"`
	ProposedAt     string `json:"proposed_at" doc:"The moment the action was taken"`
	SelectedBy     string `json:"selected_by,omitempty" doc:"The narrowing behind a bulk set. Never part of the claim itself"`
	// Selection is the same claim in a form an approver can re-run. Prose
	// alone cannot be checked, and a decision rests on how the set was
	// chosen.
	Selection *SelectionBody `json:"selection,omitempty" doc:"The narrowing behind a bulk claim, as something you can re-run. Absent on a claim that was not one"`
	// Elsewhere is where this is being worked on outside here. Stored and
	// never fetched.
	Elsewhere string `json:"elsewhere,omitempty" doc:"A ticket, a thread or a change. Stored and never fetched"`
}

// WaitingBody is one entry of the review queue: one claim, with what an
// approver needs to judge it.
type WaitingBody struct {
	Claim ClaimBody `json:"claim"`
	// Decision is a representative row of the claim — the earliest — and
	// Place is where it sits. A claim over many issues has many; the counts
	// below say how many.
	Decision DecisionBody `json:"decision"`
	Place    PlaceBody    `json:"place"`
	// Everything an approver needs to judge without opening it. A list where
	// judging a row means opening it is a list that gets approved unread.
	Reasoning          string `json:"reasoning"`
	PreviouslyApproved bool   `json:"previously_approved,omitempty" doc:"This was agreed to before and came back"`
	DeferredDays       int    `json:"deferred_days,omitempty" doc:"The total this finding has been put off for"`
	ProposedBy         string `json:"proposed_by" doc:"The person who made the claim, by sign-in identity"`
	ProposedByName     string `json:"proposed_by_name,omitempty" doc:"Their display name, where they have one"`
	AgeDays            int    `json:"age_days" doc:"The age of the claim. An old judgment should look like one"`
	Decisions          int    `json:"decisions" doc:"The number of rows the claim wrote"`
	Issues             int    `json:"issues" doc:"The number of distinct issues it covers"`
	Places             int    `json:"places" doc:"The number of distinct places it covers"`
	// Builds is every build the claim's rows currently cover, by matching.
	Builds []string `json:"builds" doc:"Every build the claim currently covers, as stream and variant"`
	// Outliers is the rows of a bulk set that do not look like the rest. Only
	// for a claim over many issues.
	Outliers *OutliersBody `json:"outliers,omitempty" doc:"For a claim over many issues: the rows that do not look like the rest, and how many there are"`
	// Counter is the case against agreeing.
	Counter *CounterBody `json:"counter,omitempty" doc:"The context a careful reader looks up: what was decided about this issue elsewhere, and how much else at the same place nobody has answered"`
	// Finding is the subject of the representative decision: the build to
	// link to, the issue, the component and where it sits. For a claim
	// over many issues it describes the component and the build, with the
	// representative issue.
	Finding *FindingRefBody `json:"finding,omitempty" doc:"The representative decision's subject — build, issue, component, where it sits — so the card can be judged without opening it. Absent where no open finding sits at its place"`
}

// CounterBody is what would make an approver disagree.
//
// Two counts and no argument. It does not say a claim is wrong — nothing
// here can know that — it says what a careful reader would go and look up, so
// that not looking is a choice rather than an omission.
type CounterBody struct {
	// Elsewhere is what has already been agreed about this same issue at other
	// places, by outcome. A dismissal here where six places called it affected
	// is the case worth a second look.
	Elsewhere map[string]int `json:"elsewhere,omitempty" doc:"Approved claims about this issue at other places, counted by outcome"`
	// Undecided is how many other issues sit undecided at the same place. A
	// claim in a run of forty is usually right, and it is also how a run gets
	// waved through.
	Undecided int `json:"undecided,omitempty" doc:"Other issues at the same place nobody has answered"`
}

// OutliersBody is what an approver of a bulk claim checks instead of reading
// every row.
type OutliersBody struct {
	ExploitedHere int           `json:"exploited_here" doc:"Issues this product records being attacked through. Agreeing to the claim is refused while any is in it; set them aside"`
	Exploited     int           `json:"exploited" doc:"Issues in the set known to be exploited"`
	Severe        int           `json:"severe" doc:"Issues rated critical or high"`
	Fixable       int           `json:"fixable" doc:"Issues a fix is available for"`
	Unmatched     int           `json:"unmatched" doc:"Issues whose description does not carry the term the set was narrowed by"`
	Rows          []OutlierBody `json:"rows" doc:"The issues that stood out: attacked here first, then exploited, then by severity. At most twenty, except that every issue this product was attacked through is listed"`
}

// OutlierBody is one issue in a bulk claim that does not look like the rest.
type OutlierBody struct {
	DecisionID    int64    `json:"decision_id" doc:"A representative row of the claim about this issue"`
	DecisionIDs   []int64  `json:"decision_ids" doc:"Every row of the claim about this issue, one per place. Name all of them to set the issue aside when approving"`
	ExploitedHere bool     `json:"exploited_here,omitempty" doc:"This product records being attacked through it"`
	Vulnerability string   `json:"vulnerability"`
	Severity      string   `json:"severity,omitempty"`
	Exploited     bool     `json:"exploited,omitempty"`
	FixedIn       string   `json:"fixed_in,omitempty"`
	Description   string   `json:"description,omitempty" doc:"The first two hundred characters of what the report says"`
	Why           []string `json:"why" doc:"The signals that made it stand out"`
}

// BecameBody is one claim somebody proposed and what happened to it.
type BecameBody struct {
	Claim    ClaimBody    `json:"claim"`
	Decision DecisionBody `json:"decision"`
	Place    PlaceBody    `json:"place"`
	// Happened is the word for what became of it. "mixed" is a claim whose
	// rows do not all end the same way — an approver agreeing to most of a
	// bulk set and setting some aside, or half of it lapsing as one build
	// moves — and is stated rather than picked between.
	Happened string `json:"happened" enum:"waiting,sent-back,approved,withdrawn,lapsed,undone,mixed" doc:"The claim's outcome"`
	// The moment it became that, and the person who did it where a person
	// did. Both absent while it is waiting: nothing has happened to it yet.
	When      string          `json:"when,omitempty" doc:"The moment it became that"`
	By        string          `json:"by,omitempty" doc:"The person who did it, where a person did, by sign-in identity"`
	ByName    string          `json:"by_name,omitempty" doc:"Their display name, where they have one"`
	Reasoning string          `json:"reasoning"`
	Decisions int             `json:"decisions" doc:"The number of rows the claim wrote"`
	Issues    int             `json:"issues" doc:"The number of distinct issues it covers"`
	Places    int             `json:"places" doc:"The number of distinct places it covers"`
	Finding   *FindingRefBody `json:"finding,omitempty" doc:"The representative decision's subject. Absent where no open finding sits at its place"`
	// Outliers is the rows of a bulk claim that do not look like the rest, for
	// a claim its author may still hold part of back. The same signals an
	// approver is shown, because the author faces the same choice — hold some
	// back, or argue all of it as one — and without them has nothing to choose
	// with.
	Outliers *OutliersBody `json:"outliers,omitempty" doc:"The rows in a bulk claim that do not look like the rest. Absent for a claim about one issue and for one nothing can still be held back from"`
}

// BecameOutput is a page of what somebody proposed.
type BecameOutput struct {
	Body struct {
		Items []BecameBody `json:"items"`
		Total int          `json:"total"`
	}
}

// QueueOutput is a page of the review queue, with how much is behind it.
type QueueOutput struct {
	Body struct {
		Items []WaitingBody `json:"items"`
		// Total is how much work there is, which is not how much is shown. A
		// reviewer deciding whether to start needs the first number.
		Total int `json:"total"`
	}
}

func registerTriage(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-review-queue", Method: http.MethodGet, Path: "/v1/review-queue",
		Summary: "List claims awaiting approval",
		Description: "Returns the claims waiting for a second person, newest first, limited to " +
			"what you may approve every row of. One entry is one claim — one proposer's action, " +
			"however many decisions it wrote — with a representative decision and place, how " +
			"many rows, issues and places it covers, and every build it currently reaches.\n\n" +
			"Each entry carries the full reasoning, whether it was previously approved and came " +
			"back, how long the finding has been deferred in total, and how old the claim is. A " +
			"claim over many issues also carries `outliers`: the rows that do not look like the " +
			"rest, which is what to read instead of all of them.\n\n" +
			"Approve, send back or set rows aside with `POST /v1/claims/{id}/approval` and " +
			"`POST /v1/claims/{id}/send-back`.\n\n" +
			"Your own claims are not here. Approving your own is refused, so a queue " +
			"containing them is a list of work you cannot do. Ask for `mine=true` to see what " +
			"you proposed and nobody has agreed to yet, which is a different question.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Mine    bool   `query:"mine" doc:"Return what you proposed and nobody has agreed to, instead of what is waiting on you"`
		Product string `query:"product" doc:"Limit to claims made in one product, by name. Empty means every product you can see; a name you cannot see is refused rather than answered empty"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset  int    `query:"offset" minimum:"0"`
	}) (*QueueOutput, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		within, err := narrowedTo(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}

		waiting, total, err := store.Queue(ctx, subject, input.Mine, within, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "the review queue could not be read", err)
		}

		// The finding each row is about, and the person who made the claim,
		// resolved here rather than left as identifiers. A queue row saying
		// product 4, issue 91 is a row an approver has to make two more
		// requests to understand, fifty times a page.
		decisions := make([]triage.Decision, 0, len(waiting))
		for _, row := range waiting {
			decisions = append(decisions, row.Decision)
		}
		named, err := describeDecisions(ctx, in, store, decisions, nil)
		if err != nil {
			return nil, wentWrong(in.Logger, "the review queue could not be read", err)
		}

		out := &QueueOutput{}
		out.Body.Items = make([]WaitingBody, 0, len(waiting))
		for i, row := range waiting {
			entry := WaitingBody{
				Claim:              claimBody(row.Claim, named[i].ProposedBy, named[i].ProposedByName),
				Decision:           decisionBody(row.Decision),
				Place:              named[i].Place,
				Reasoning:          row.Reasoning,
				PreviouslyApproved: row.PreviouslyApproved,
				DeferredDays:       int(row.DeferredSoFar.Hours() / 24),
				ProposedBy:         named[i].ProposedBy,
				ProposedByName:     named[i].ProposedByName,
				AgeDays:            int(store.Age(&row.Decision).Hours() / 24),
				Decisions:          row.Decisions,
				Issues:             row.Issues,
				Places:             row.Places,
				Builds:             row.Builds,
			}
			if entry.Builds == nil {
				entry.Builds = []string{}
			}
			if row.Outliers != nil {
				entry.Outliers = outliersBody(*row.Outliers)
			}
			if row.Counter.Said() {
				entry.Counter = &CounterBody{
					Elsewhere: row.Counter.Elsewhere, Undecided: row.Counter.Undecided,
				}
			}
			entry.Finding = named[i].Finding
			out.Body.Items = append(out.Body.Items, entry)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "repromise-upgrade", Method: http.MethodPut,
		Path:    "/v1/claims/{id}/promise",
		Summary: "Change what a release is moving to",
		Description: "Changes the version a promised upgrade moves to, or the date it is " +
			"promised by, on the claim and on every commitment it wrote.\n\n" +
			"This withdraws any existing approval and returns every row of the claim to " +
			"the review queue, and notifies everybody whose approval it withdrew. An approver " +
			"agreed to a version by a date; changing either is " +
			"changing what they agreed to, so it goes through the same act revising the words " +
			"does.\n\n" +
			"`reasoning` is required and is recorded as a revision — saying why a date moved " +
			"is what the second person has to read, and the revisions are where what was said " +
			"before survives being changed.",
		Tags: []string{"Remediation"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			To        string `json:"to" minLength:"1" doc:"The version it now moves to"`
			By        string `json:"by" format:"date" doc:"The date the work will be done by"`
			Reasoning string `json:"reasoning" minLength:"1" doc:"The reason the promise is changing, in markdown"`
		}
	}) (*struct{}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		by, err := time.Parse(time.DateOnly, input.Body.By)
		if err != nil {
			return nil, huma.Error422UnprocessableEntity("by must be a date, as YYYY-MM-DD")
		}
		withdrawn, moved, err := store.Repromise(ctx, subject, input.ID, input.Body.To, by,
			input.Body.Reasoning)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		changed := "The reasoning"
		if moved {
			changed = "The promise"
		}
		tellTheApprovers(ctx, in, input.ID, withdrawn, changed)
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "split-claim", Method: http.MethodPost, Path: "/v1/claims/{id}/split",
		Summary: "Hold part of a claim back",
		Description: "Moves the rows named into a claim of their own, belonging to you, carrying " +
			"the argument they were made under and sitting with you rather than in the review " +
			"queue. Revise it to give them an argument of their own.\n\n" +
			"This is the proposer's side of setting rows aside, and each act is refused to " +
			"the other: an approver holding rows back is agreeing to the rest in the same " +
			"action, and a proposer doing that would be approving their own claim.\n\n" +
			"`because` is required and is recorded as a comment on the new claim. Naming a row " +
			"that is not part of the claim is refused rather than ignored, and so is naming all " +
			"of what is still being argued — that is a revision or a withdrawal.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Rows    []int64 `json:"rows" minItems:"1" doc:"The decisions to hold back, which must be this claim's"`
			Because string  `json:"because" minLength:"1" doc:"The reason they are being held back, in markdown"`
		}
	}) (*struct {
		Body struct {
			ClaimID int64 `json:"claim_id" doc:"The claim the rows were moved into"`
		}
	}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		held, err := store.Split(ctx, subject, input.ID, input.Body.Rows, input.Body.Because)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		out := &struct {
			Body struct {
				ClaimID int64 `json:"claim_id" doc:"The claim the rows were moved into"`
			}
		}{}
		out.Body.ClaimID = held.ID
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-my-claims", Method: http.MethodGet, Path: "/v1/my-claims",
		Summary: "List the outcomes of your own claims",
		Description: "Returns the claims you proposed, newest first, with what happened to " +
			"each: still waiting, sent back, approved, withdrawn, lapsed, an agreement " +
			"undone, or several of those where a claim's rows ended differently.\n\n" +
			"This is the other half of the review queue's `mine=true`, which lists only what " +
			"is still pending — so approved, withdrawn, lapsed and undone all present there " +
			"as the row disappearing. Approval itself sends no message; this is where it is " +
			"seen.\n\n" +
			"Narrowed to what you may still read.",
		Tags: []string{"Triage"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*BecameOutput, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		mine, total, err := store.Became(ctx, subject, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what you proposed could not be read", err)
		}

		decisions := make([]triage.Decision, 0, len(mine))
		for _, row := range mine {
			decisions = append(decisions, row.Decision)
		}
		named, err := describeDecisions(ctx, in, store, decisions, nil)
		if err != nil {
			return nil, wentWrong(in.Logger, "what you proposed could not be read", err)
		}
		// The person who did it, resolved to a name. A row saying "person 7
		// agreed" is a row somebody has to look up, and the fate of a claim is
		// half about who answered it.
		actors := make([]int64, 0, len(mine))
		for _, row := range mine {
			if row.By != 0 {
				actors = append(actors, row.By)
			}
		}
		who, err := whoSigned(ctx, in.DB.DB, actors)
		if err != nil {
			return nil, wentWrong(in.Logger, "what you proposed could not be read", err)
		}

		out := &BecameOutput{}
		out.Body.Items = make([]BecameBody, 0, len(mine))
		for i, row := range mine {
			entry := BecameBody{
				Claim:     claimBody(row.Claim, named[i].ProposedBy, named[i].ProposedByName),
				Decision:  decisionBody(row.Decision),
				Place:     named[i].Place,
				Reasoning: row.Reasoning,
				Happened:  string(row.Happened),
				Decisions: row.Rows,
				Issues:    row.Issues,
				Places:    row.Places,
				Finding:   named[i].Finding,
			}
			if row.When != nil {
				entry.When = row.When.Format(time.RFC3339)
			}
			if row.By != 0 {
				entry.By, entry.ByName = who.identity(row.By), who.label(row.By)
			}
			if row.Outliers != nil {
				entry.Outliers = outliersBody(*row.Outliers)
			}
			out.Body.Items = append(out.Body.Items, entry)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "revise-claim", Method: http.MethodPut, Path: "/v1/claims/{id}/reasoning",
		Summary: "Update a claim's justification",
		Description: "Replaces the justification text with a new revision. Earlier revisions are " +
			"kept and remain readable.\n\n" +
			"A claim is one argument however many places it covers, so this revises all of it. " +
			"It withdraws any existing approval and returns every row of the claim to the " +
			"review queue, marked as previously approved. Everybody whose approval it " +
			"withdrew is notified. Requires no approval of its own.\n\n" +
			"The text is markdown and is validated before it is stored; a 422 names the line and " +
			"the offending text.",
		Tags: []string{"Triage"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Reasoning string `json:"reasoning" minLength:"1"`
		}
	}) (*struct{ Body MentionsBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		revised, err := store.Revise(ctx, subject, input.ID, input.Body.Reasoning)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		tellTheApprovers(ctx, in, input.ID, revised.Withdrawn, "The reasoning")
		dropped := tellMentioned(ctx, in, subject, store, input.ID, input.Body.Reasoning)
		return &struct{ Body MentionsBody }{Body: MentionsBody{NotNotified: dropped}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "withdraw-claim", Method: http.MethodDelete, Path: "/v1/claims/{id}",
		Summary: "Withdraw a triage claim",
		Description: "Withdraws the claim so none of it applies to any finding. A claim is one " +
			"argument however many places it covers, so this takes back all of it; holding part " +
			"of one back is setting rows aside, at `POST /v1/claims/{id}/approval`. The record " +
			"is kept — a withdrawn claim reads as proposed, approved, then withdrawn. " +
			"Requires no approval.",
		Tags:          []string{"Triage"},
		DefaultStatus: http.StatusNoContent,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		if err := store.Withdraw(ctx, subject, input.ID); err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, answering(huma.Operation{
		OperationID: "undo-batch", Method: http.MethodDelete, Path: "/v1/approval-batches/{batch}",
		Summary: "Undo a bulk approval",
		Description: "Withdraws every approval recorded under this batch name, returning those " +
			"decisions to the review queue. The decisions themselves stand — only the approvals " +
			"are undone. Returns how many were affected.\n\n" +
			"Only decisions you may reach are touched.",
		Tags: []string{"Triage"},
	}, perProduct, "A batch is one reviewer's afternoon and may span products, so it "+
		"is undone as far as you reach and no further.", approveRights()...),
		func(ctx context.Context, input *struct {
			Batch string `path:"batch"`
		}) (*struct {
			Body struct {
				Undone int64 `json:"undone"`
			}
		}, error) {
			subject, store, err := triaging(ctx, in)
			if err != nil {
				return nil, err
			}
			undone, err := store.UndoBatch(ctx, subject, input.Batch)
			if err != nil {
				return nil, wentWrong(in.Logger, "an agreement could not be undone", err)
			}
			// Each proposer is told, through the one telling both causes
			// share.
			tellTheProposers(ctx, in, undone,
				"was agreed to and the agreement has been taken back. It is waiting "+
					"for a second person again; nothing you wrote has changed.",
				"batch", input.Batch)
			out := &struct {
				Body struct {
					Undone int64 `json:"undone"`
				}
			}{}
			out.Body.Undone = undone.Rows
			return out, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "comment-on-claim", Method: http.MethodPost, Path: "/v1/claims/{id}/comments",
		Summary: "Add a comment to a claim",
		Description: "Adds a markdown comment to a claim. Comments are separate from the " +
			"justification and never affect an approval, so an approved claim can be annotated " +
			"at any time.\n\n" +
			"A comment may later be edited by its author only, and editing overwrites it rather " +
			"than keeping revisions.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", approveRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Body string `json:"body" minLength:"1"`
		}
	}) (*struct {
		Body struct {
			ID          int64    `json:"id"`
			NotNotified []string `json:"not_notified,omitempty" doc:"Names written after an @ that reached nobody. Either no such person is recorded, or they cannot read what the text is about — deliberately not said which"`
		}
	}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		comment, err := store.Say(ctx, subject, input.ID, input.Body.Body)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		dropped := tellMentioned(ctx, in, subject, store, input.ID, input.Body.Body)
		out := &struct {
			Body struct {
				ID          int64    `json:"id"`
				NotNotified []string `json:"not_notified,omitempty" doc:"Names written after an @ that reached nobody. Either no such person is recorded, or they cannot read what the text is about — deliberately not said which"`
			}
		}{}
		out.Body.ID = comment.ID
		out.Body.NotNotified = dropped
		return out, nil
	})
}

func registerProposing(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "decide", Method: http.MethodPost,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/places/{place}/decision",
		Summary: "Record a triage decision for a finding",
		Description: "Records how a finding was triaged: `affected`, `not-applicable`, " +
			"`mismatched`, `deferred`, `wont-fix`, `already-fixed` or `patch-needed`.\n\n" +
			"`not-applicable` and `mismatched` require a `justification` from the standard " +
			"VEX vocabulary. " +
			"`deferred` requires `deferred_until` as a date. `already-fixed` requires " +
			"`fixed_version`, the version whoever packages the component states the fix " +
			"arrived in — it is recorded for a reader and never compared against what ships.\n\n" +
			"`patch-needed` is the backport case: a fix is being carried into this build " +
			"and the version does not move. It requires `committed_to`, the date the work " +
			"lands, and it closes the only way a backport can — the next inventory declares " +
			"the patch it carries and says what that patch resolves, so the finding goes " +
			"while the version stays where it was.\n\n" +
			"`upgrade-needed` is not recorded here. An upgrade answers a component rather than one " +
			"finding, so it is recorded from the component and covers everything open on it.\n\n" +
			"The decision applies to every build running the same component and consumer upstream " +
			"versions, including future releases — it is matched by code, not copied between " +
			"releases. It stops applying automatically when either upstream version changes.\n\n" +
			"`mismatched` is the exception, and the only one: it says the scanner matched " +
			"this against something it is not, which is a claim about identity rather than " +
			"about risk. It covers the place at whatever versions the place holds, and no " +
			"version change expires it — a bump does not make a wrong match right. Its " +
			"`justification` is limited to the two reasons that say something is not there, " +
			"`component_not_present` and `vulnerable_code_not_present`; the three that " +
			"describe how code is reached or what stops it are refused, because a version " +
			"bump changes those and this outcome would carry them past it.\n\n" +
			"The response says whether a second person must approve it. Most outcomes require " +
			"approval; a deferral shorter than the configured threshold does not.\n\n" +
			"It also says how many findings this one judgment covers, and how many distinct " +
			"versions of the component sit at this place — more than one means a single " +
			"decision cannot honestly cover all of them.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Place         string `path:"place" doc:"The place, as the findings list gives it"`
		Body          DecisionBody
	}) (*struct{ Body DecisionBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		// Refused here rather than by the store, because the fault is in the
		// grain rather than in the claim: the same outcome recorded
		// from a component is exactly right, and the sentence has to say
		// where to go rather than that the word is invalid.
		if triage.Outcome(input.Body.Outcome) == triage.UpgradeNeeded {
			return nil, huma.Error422UnprocessableEntity(
				"an upgrade answers a component rather than one finding: record it from the " +
					"component, where it covers everything open on it in the releases you name")
		}

		at, target, err := decidingAbout(ctx, in, subject, input.Product, input.Stream,
			input.Variant, input.Vulnerability, input.Place)
		if err != nil {
			return nil, err
		}

		proposal := triage.Proposal{
			Place: triage.Place{
				ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
				PlaceIdentity: at.PlaceIdentity, Visibility: at.Visibility,
				ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
				OnTag: at.OnTag,
			},
			Outcome:       triage.Outcome(input.Body.Outcome),
			Justification: triage.Justification(input.Body.Justification),
			Mitigation:    input.Body.Mitigation,
			FixedVersion:  input.Body.FixedVersion,
			// Carried through so the store refuses it rather than dropping
			// it: a request naming a version under an outcome that moves none
			// has said two things, and quietly keeping one of them records a
			// claim nobody made.
			UpgradeTo:     input.Body.UpgradeTo,
			Reasoning:     input.Body.Reasoning,
			By:            subject.ID,
			SeverityCenti: at.SeverityCenti,
			// The build whose deadline a promise made here is gated against.
			// The deadline itself is read inside the transaction that writes
			// the claim, because it is a stored value a re-rating or an
			// arriving scan moves — and never supplied by the caller, since
			// the need for a second person is not a thing the person making
			// the commitment may state.
			BindingAcross: []int64{target},
			FromStatement: cited(input.Body.FromStatement),
		}
		if input.Body.DeferredUntil != "" {
			until, err := time.Parse(time.DateOnly, input.Body.DeferredUntil)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity("a deferral returns on a date, written as YYYY-MM-DD")
			}
			proposal.DeferredUntil = &until
		}
		if input.Body.CommittedTo != "" {
			by, err := time.Parse(time.DateOnly, input.Body.CommittedTo)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(
					"the date promised work lands on is written as YYYY-MM-DD")
			}
			proposal.CommittedTo = &by
		}

		// The wait for a second person is worked out by the store, inside the
		// transaction that records it, and read back off what was written.
		// Asked here and passed in, the answer describes the policy and the
		// postponement in force when the request arrived rather than when the
		// claim landed — and the answer telling the caller it is waiting is
		// the only trace of a control that never ran.
		decision, err := store.Propose(ctx, subject, proposal)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}

		body := decisionBody(*decision)
		body.Reasoning = input.Body.Reasoning
		body.NeedsApproval = decision.NeedsApproval
		// The reach of this one judgment, so nobody discovers afterwards
		// that they answered for sixty-two modules or for two versions of the
		// same package.
		body.Places, body.Versions = at.Places, at.Versions()
		return &struct{ Body DecisionBody }{Body: body}, nil
	})
}

// triaging resolves who is asking and the store they act through.
func triaging(ctx context.Context, in Ingest) (access.Subject, *triage.Store, error) {
	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, nil, err
	}
	if in.DB == nil {
		return access.Subject{}, nil, noDatabase(in.Logger)
	}
	return subject, triage.NewStore(in.DB.DB), nil
}

// refusedDecision turns a store's refusal into an answer.
//
// A decision somebody may not reach answers as one that is not there, so that
// guessing identifiers says nothing. Everything a caller could have got right
// is reported, including where in their text to look.
func refusedDecision(logger *slog.Logger, err error) error {
	switch {
	case errors.Is(err, triage.ErrNotTheirs):
		return noSuchDecision()
	case errors.Is(err, triage.ErrSamePerson):
		return huma.Error409Conflict("the person who proposed a decision may not agree to it")
	}
	// An authorization refusal is not somebody having asked for the
	// impossible. Without this arm it falls through to the default below and
	// answers 422 carrying access.Denied's own sentence — which names the
	// internal product identifier, so a refusal hands the caller a number
	// nothing else publishes.
	if errors.Is(err, access.ErrDenied) {
		return huma.Error403Forbidden("not authorized")
	}
	var faults markdown.Faults
	if errors.As(err, &faults) {
		return refusedText(faults)
	}
	// A database that broke is not somebody having asked for the impossible.
	// The default arm answers both as 422 with the message in it, so a lost
	// connection reaches the caller as a bad request carrying the statement
	// text and the address the driver tried.
	if database.FromEngine(err) {
		return wentWrong(logger, "that could not be recorded", err)
	}
	// The remainder is a sentence the triage store wrote for a person to read:
	// a decision already standing here, a claim covering nothing, a threshold
	// crossed. Those are the caller's to fix, and the message is the answer.
	return huma.Error422UnprocessableEntity(err.Error())
}

// refusedText answers a refused piece of writing with where to look.
//
// Each fault travels as its own detail, carrying the line and the text that
// caused it. Flattened into one sentence they leave an interface with nothing
// to point at: "remote images are not allowed" against a forty-line
// justification means somebody hunting for it by eye, which is the whole
// reason positions are gathered in the first place.
func refusedText(faults markdown.Faults) error {
	details := make([]error, 0, len(faults))
	for _, fault := range faults {
		details = append(details, &huma.ErrorDetail{
			Message: fault.Reason,
			// The position in the submitted text, not in the request body. A
			// client is pointing a cursor at a line somebody typed.
			Location: fmt.Sprintf("line %d", fault.Line),
			Value:    fault.Offending,
		})
	}
	return huma.Error422UnprocessableEntity(
		"that text cannot be stored as written", details...)
}

// decisionBody renders a decision as the API states it.
func decisionBody(d triage.Decision) DecisionBody {
	// The judgment's words come from the claim: one act is one argument,
	// and this row says where it lands. A decision read without its claim is
	// a programming error rather than a state a caller can reach, so it is
	// left to fail here rather than rendered as an outcome nobody chose.
	said := d.Claim
	body := DecisionBody{
		ID: d.ID, ClaimID: d.ClaimID, Outcome: outcome(said.Outcome), State: string(d.State),
	}
	if said.Mitigation != nil {
		body.Mitigation = *said.Mitigation
	}
	if said.Justification != nil {
		body.Justification = justification(*said.Justification)
	}
	if said.FixedVersion != nil {
		body.FixedVersion = *said.FixedVersion
	}
	if said.DeferredUntil != nil {
		body.DeferredUntil = said.DeferredUntil.Format(time.DateOnly)
	}
	if said.CommittedTo != nil {
		body.CommittedTo = said.CommittedTo.Format(time.DateOnly)
	}
	if said.UpgradeTo != nil {
		body.UpgradeTo = *said.UpgradeTo
	}
	if d.SentBackAt != nil {
		body.SentBackAt = d.SentBackAt.UTC().Format(time.RFC3339)
	}
	if d.SelectedBy != nil {
		body.SelectedBy = *d.SelectedBy
	}
	return body
}

// deferralThreshold is how long a deferral may run before a second person has
// to agree, as this deployment has it set.
//
// A failure to read it is reported rather than answered with the shipped
// default. This decides which deferrals need a second person, so quietly
// substituting a different threshold substitutes a different control — and a
// deployment that had tightened it would find it loosened at exactly the
// moment its database was in trouble, with nothing saying so. A setting nobody
// has changed is a different matter, and answers with the default.
func deferralThreshold(ctx context.Context, in Ingest) (time.Duration, error) {
	if in.DB == nil {
		return triage.DefaultDeferralThreshold, nil
	}
	// The same shipped span the store falls back to. Written out here as well,
	// the two disagree about what a deployment that has said nothing is
	// doing.
	return setting.NewStore(in.DB.DB).Duration(ctx, setting.DeferralThreshold,
		triage.DefaultDeferralThreshold)
}

// tellTheApprovers tells everybody whose agreement an edit took back.
//
// Approval is otherwise silent, and this is the one outcome an approver cannot
// see coming: somebody else changed what they agreed to, and their agreement
// stopped counting. What changed is named, the claim is linked, and a claim
// with an undisclosed row carries nothing more than that, like every telling
// about an undisclosed finding.
func tellTheApprovers(ctx context.Context, in Ingest, claimID int64,
	withdrawn []triage.ForPerson, what string) {

	for _, one := range withdrawn {
		tell(ctx, in, "could not say that an agreement was withdrawn", notify.Telling{
			PersonID: one.PersonID, Kind: notify.ApprovalWithdrawn,
			Body: what + " of a claim you agreed to was changed, so your agreement no " +
				"longer counts. It is back in the review queue.",
			Link:    "/claims/" + strconv.FormatInt(claimID, 10),
			Private: one.Undisclosed,
			// The narrowing a later read applies.
			ProductID:       &one.ProductID,
			VulnerabilityID: &one.VulnerabilityID,
		}, "person", one.PersonID, "claim", claimID)
	}
}
