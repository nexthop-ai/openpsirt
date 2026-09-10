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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// DecisionBody is a claim about a finding.
type DecisionBody struct {
	ID int64 `json:"id,omitempty" doc:"What to name this decision in a later request"`
	// ClaimID is the action this row was written by. The review queue lists
	// claims and approval works on them; a decision is one row of one.
	ClaimID int64  `json:"claim_id,omitempty" doc:"The claim this decision is one row of: the action that wrote it, which is what the review queue lists and what is approved"`
	Outcome string `json:"outcome" enum:"affected,not-applicable,deferred,wont-fix,already-fixed,upgrade-needed,patch-needed" doc:"What was decided"`
	// Justification is required for not-applicable and meaningless elsewhere:
	// the claim that something does not affect us is which of the recognized
	// reasons applies.
	Justification string `json:"justification,omitempty" enum:"component_not_present,vulnerable_code_not_present,vulnerable_code_not_in_execute_path,vulnerable_code_cannot_be_controlled_by_adversary,inline_mitigations_already_exist" doc:"Why it does not apply. Required when it does not"`
	// Mitigation is the one claim here that rests on configuration rather
	// than on code, so it is the one thing nothing will notice going away.
	// Naming it does not fix that; it makes the claim checkable.
	Mitigation    string `json:"mitigation,omitempty" maxLength:"65536" doc:"What actually stops it — the rule, the setting, the service that is not exposed. Required when the reason is that mitigations already exist, and refused with any other"`
	DeferredUntil string `json:"deferred_until,omitempty" doc:"When a deferral returns, as a date. Required for a deferral"`
	// FixedVersion is what makes the already-fixed claim checkable against
	// whoever packages the component, rather than something to be taken on
	// trust.
	FixedVersion string `json:"fixed_version,omitempty" doc:"The package version whoever packages this states the fix arrived in. Required when the outcome is already-fixed, and refused with any other. Recorded and never compared against the version shipping"`
	// CommittedTo is when the work an outcome promises will be done, for
	// the two that promise work. Without it there is nothing to gate
	// against and nothing to lapse.
	CommittedTo string `json:"committed_to,omitempty" doc:"When the promised work will be done, as a date. Required for patch-needed and upgrade-needed, and refused with any other"`
	// UpgradeTo is the version an upgrade moves to. Written by the component
	// screen rather than here: a bump answers a component, not one finding.
	UpgradeTo string `json:"upgrade_to,omitempty" doc:"The version an upgrade moves to. Carried on an upgrade-needed decision, which is recorded from a component rather than from one finding"`
	Reasoning string `json:"reasoning" minLength:"1" doc:"Why, in markdown. Somebody else has to agree with this"`
	// FromStatement cites a VEX statement this was started from. A
	// citation and never an application: what they said is not this claim,
	// and recording it is what lets a later revision be noticed .
	FromStatement int64  `json:"from_statement,omitempty" doc:"A VEX statement this was started from, by its identifier. Recorded as a citation so a later revision to it raises an alert. It is never what the claim rests on"`
	State         string `json:"state,omitempty" enum:"proposed,approved,withdrawn,lapsed" doc:"Where it has got to"`
	// NeedsApproval says whether this is waiting for a second person. A short
	// deferral is not.
	NeedsApproval bool `json:"needs_approval,omitempty" doc:"Whether a second person has to agree before it takes effect"`
	// Places is how many findings this one judgment covers. A kernel issue
	// reaches dozens of modules and the answer is usually the same for all of
	// them, so whoever is deciding is told the size of what they are deciding.
	Places int `json:"places,omitempty" doc:"How many findings this decision covers"`
	// Versions is how many distinct versions sit at this place. More than one
	// means a single decision cannot honestly cover all of them.
	Versions int `json:"versions,omitempty" doc:"How many versions of the component sit here. More than one needs care"`
	// SentBackAt is when an approver last asked for more before they would
	// agree. Reported, because otherwise the only trace of it is a comment,
	// and the author's own list cannot tell a claim waiting on somebody else
	// from one waiting on them.
	SentBackAt string `json:"sent_back_at,omitempty" doc:"When an approver last asked for more. Empty means nobody has"`
	// SelectedBy is how the set was narrowed, where this claim was one of many
	// recorded in a single action. Reported so that "how were these chosen"
	// has an answer months later.
	SelectedBy string `json:"selected_by,omitempty" doc:"How the set was narrowed, for a claim recorded as one of many. Never part of the claim itself"`
}

// FindingRefBody is what a decision is about, as the findings list would
// show it: the build to link to, the issue, the component and where it sits.
type FindingRefBody struct {
	Product       string  `json:"product" doc:"The build to link to, by product, branch or tag, and variant"`
	Stream        string  `json:"stream"`
	Variant       string  `json:"variant"`
	Vulnerability string  `json:"vulnerability" doc:"The issue, under the name it is most widely known by"`
	Component     string  `json:"component"`
	Version       string  `json:"version" doc:"The version that ships"`
	Severity      string  `json:"severity,omitempty" doc:"Our rating where one stands, else as published"`
	Score         float64 `json:"score,omitempty"`
	Exploited     bool    `json:"exploited,omitempty"`
	FixState      string  `json:"fix_state,omitempty" enum:"fixed,none,wont-fix,unknown,mixed"`
	FixedIn       string  `json:"fixed_in,omitempty"`
	Description   string  `json:"description,omitempty" doc:"The first four hundred characters of what the report says, as plain text"`
	Owner         string  `json:"owner,omitempty" doc:"The part of the product this belongs to"`
	Parent        string  `json:"parent,omitempty" doc:"What directly pulls it in, which is what the decision is about"`
	Places        int     `json:"places" doc:"How many places the issue sits at in that component in that build"`
	Decided       int     `json:"decided" doc:"How many of those this claim covers"`
}

// PlaceBody names what a decision is about.
//
// Stated by the caller and checked against what is stored, rather than taken
// on trust: it is assembled from a finding, and a caller that could name a
// place freely would be choosing which decisions apply where.
type PlaceBody struct {
	Product       string `json:"product" minLength:"1"`
	Vulnerability string `json:"vulnerability" minLength:"1" doc:"The issue, by any name it is known under"`
	Place         string `json:"place" minLength:"1" doc:"Which place in the build, as the findings list gives it"`
}

// ClaimBody is one proposer's action: what the review queue lists and what an
// approver agrees to.
type ClaimBody struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind" enum:"finding,together,extension,returned" doc:"What sort of action it was: one judgment about a finding, one about many issues at a component, an approved claim carried to a new issue, or rows set aside from a larger claim — by an approver agreeing to the rest, or by the author holding them back"`
	DerivedFrom int64  `json:"derived_from,omitempty" doc:"The claim this one came from, for an extension or a returned set"`
	ProposedBy  string `json:"proposed_by"`
	ProposedAt  string `json:"proposed_at" doc:"When the action was taken, as a date and time"`
	SelectedBy  string `json:"selected_by,omitempty" doc:"How a bulk set was narrowed. Never part of the claim itself"`
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
	DeferredDays       int    `json:"deferred_days,omitempty" doc:"How long this finding has been put off in total"`
	ProposedBy         string `json:"proposed_by"`
	AgeDays            int    `json:"age_days" doc:"How long the claim has stood. An old judgment should look like one"`
	Decisions          int    `json:"decisions" doc:"How many rows the claim wrote"`
	Issues             int    `json:"issues" doc:"How many distinct issues it covers"`
	Places             int    `json:"places" doc:"How many distinct places it covers"`
	// Builds is every build the claim's rows currently cover, by matching.
	Builds []string `json:"builds" doc:"Every build the claim currently covers, as stream and variant"`
	// Outliers is what in a bulk set does not look like the rest. Only for a
	// claim over many issues.
	Outliers *OutliersBody `json:"outliers,omitempty" doc:"For a claim over many issues: the rows that do not look like the rest, and how many there are"`
	// Counter is what would argue against agreeing.
	Counter *CounterBody `json:"counter,omitempty" doc:"What a careful reader would go and look up: what was decided about this issue elsewhere, and how much else at the same place nobody has answered"`
	// Finding is what the representative decision is about: the build to
	// link to, the issue, the component and where it sits. For a claim
	// over many issues it describes the component and the build, with the
	// representative issue.
	Finding *FindingRefBody `json:"finding,omitempty" doc:"What the representative decision is about — build, issue, component, where it sits — so the card can be judged without opening it. Absent where no open finding sits at its place"`
}

// CounterBody is what would make an approver disagree.
//
// **Two counts and no argument.** It does not say a claim is wrong — nothing
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
	Exploited int           `json:"exploited" doc:"Issues in the set known to be exploited"`
	Severe    int           `json:"severe" doc:"Issues rated critical or high"`
	Fixable   int           `json:"fixable" doc:"Issues a fix is available for"`
	Unmatched int           `json:"unmatched" doc:"Issues whose description does not carry the term the set was narrowed by"`
	Rows      []OutlierBody `json:"rows" doc:"The issues that stood out, exploited first and then by severity, at most twenty"`
}

// OutlierBody is one issue in a bulk claim that does not look like the rest.
type OutlierBody struct {
	DecisionID    int64    `json:"decision_id" doc:"A row of the claim about this issue, to set aside when approving"`
	Vulnerability string   `json:"vulnerability"`
	Severity      string   `json:"severity,omitempty"`
	Exploited     bool     `json:"exploited,omitempty"`
	FixedIn       string   `json:"fixed_in,omitempty"`
	Description   string   `json:"description,omitempty" doc:"The first two hundred characters of what the report says"`
	Why           []string `json:"why" doc:"Which of the four signals made it stand out"`
}

// BecameBody is one claim somebody proposed and what happened to it.
type BecameBody struct {
	Claim    ClaimBody    `json:"claim"`
	Decision DecisionBody `json:"decision"`
	Place    PlaceBody    `json:"place"`
	// Happened is the word for what became of it. "mixed" is a claim whose
	// rows did not all end the same way — an approver agreeing to most of a
	// bulk set and setting some aside, or half of it lapsing as one build
	// moved — and is said rather than picked between.
	Happened string `json:"happened" enum:"waiting,sent-back,approved,withdrawn,lapsed,undone,mixed" doc:"What became of the claim"`
	// When it became that, and who did it where a person did. Both absent
	// while it is waiting: nothing has happened to it yet.
	When      string          `json:"when,omitempty" doc:"When it became that, as a date and time"`
	By        string          `json:"by,omitempty" doc:"Who did it, where a person did"`
	Reasoning string          `json:"reasoning"`
	Decisions int             `json:"decisions" doc:"How many rows the claim wrote"`
	Issues    int             `json:"issues" doc:"How many distinct issues it covers"`
	Places    int             `json:"places" doc:"How many distinct places it covers"`
	Finding   *FindingRefBody `json:"finding,omitempty" doc:"What the representative decision is about. Absent where no open finding sits at its place"`
	// Outliers is what in a bulk claim does not look like the rest, for a claim
	// its author may still hold part of back. The same signals an approver is
	// shown, because the author faces the same choice — hold some back, or
	// argue all of it as one — and had nothing to choose with.
	Outliers *OutliersBody `json:"outliers,omitempty" doc:"What in a bulk claim does not look like the rest. Absent for a claim about one issue and for one nothing can still be held back from"`
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
			"**Your own claims are not here.** Approving your own is refused, so a queue " +
			"containing them is a list of work you cannot do. Ask for `mine=true` to see what " +
			"you proposed and nobody has agreed to yet, which is a different question.",
		Tags: []string{"Triage"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Mine   bool `query:"mine" doc:"Return what you proposed and nobody has agreed to, instead of what is waiting on you"`
		Limit  int  `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int  `query:"offset" minimum:"0"`
	}) (*QueueOutput, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}

		waiting, total, err := store.Queue(ctx, subject, input.Mine, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "the review queue could not be read", err)
		}

		// Which finding each row is about, and who made the claim, resolved
		// here rather than left as identifiers. A queue row saying product 4,
		// issue 91 is a row an approver has to make two more requests to
		// understand, fifty times a page.
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
				Claim:              claimBody(row.Claim, named[i].ProposedBy),
				Decision:           decisionBody(row.Decision),
				Place:              named[i].Place,
				Reasoning:          row.Reasoning,
				PreviouslyApproved: row.PreviouslyApproved,
				DeferredDays:       int(row.DeferredSoFar.Hours() / 24),
				ProposedBy:         named[i].ProposedBy,
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
			"**This withdraws any existing approval** and returns every row of the claim to " +
			"the review queue. An approver agreed to a version by a date; changing either is " +
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
			Reasoning string `json:"reasoning" minLength:"1" doc:"Why the promise is changing, in markdown"`
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
		if err := store.Repromise(ctx, subject, input.ID, input.Body.To, by,
			input.Body.Reasoning); err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "split-claim", Method: http.MethodPost, Path: "/v1/claims/{id}/split",
		Summary: "Hold part of a claim back",
		Description: "Moves the rows named into a claim of their own, belonging to you, carrying " +
			"the argument they were made under and sitting with you rather than in the review " +
			"queue. Revise it to give them an argument of their own.\n\n" +
			"This is the proposer's side of setting rows aside: an approver reading a bulk " +
			"claim may agree to most of it and hold some back, and until this the author could " +
			"only withdraw the whole thing and start again. Each act is refused to the other — " +
			"an approver holding rows back is agreeing to the rest in the same action, and a " +
			"proposer doing that would be approving their own claim.\n\n" +
			"`because` is required and is recorded as a comment on the new claim. Naming a row " +
			"that is not part of the claim is refused rather than ignored, and so is naming all " +
			"of what is still being argued — that is a revision or a withdrawal.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Rows    []int64 `json:"rows" minItems:"1" doc:"The decisions to hold back, which must be this claim's"`
			Because string  `json:"because" minLength:"1" doc:"Why they are being held back, in markdown"`
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
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
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
		// Who did it, resolved to a name. A row saying "person 7 agreed" is a
		// row somebody has to look up, and the answer to "what became of my
		// claim" is half about who answered it.
		actors := make([]int64, 0, len(mine))
		for _, row := range mine {
			if row.By != 0 {
				actors = append(actors, row.By)
			}
		}
		names, err := access.NewStore(in.DB.DB).Names(ctx, actors)
		if err != nil {
			return nil, wentWrong(in.Logger, "what you proposed could not be read", err)
		}

		out := &BecameOutput{}
		out.Body.Items = make([]BecameBody, 0, len(mine))
		for i, row := range mine {
			entry := BecameBody{
				Claim:     claimBody(row.Claim, named[i].ProposedBy),
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
				entry.By = names[row.By]
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
			"**It withdraws any existing approval** and returns every row of the claim to the " +
			"review queue, marked as previously approved. Requires no approval of its own.\n\n" +
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
		if _, err := store.Revise(ctx, subject, input.ID, input.Body.Reasoning); err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
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
			// Each proposer is told. Approval itself stays silent,
			// and this is not approval: taking an agreement back
			// reverses something somebody was relying on, which is
			// the one outcome nobody expects.
			for _, one := range undone.Told {
				what := "A claim of yours"
				if one.Rows > 1 {
					what = fmt.Sprintf("%d claims of yours", one.Rows)
				}
				if err := notify.NewStore(in.DB.DB).Tell(ctx, notify.Telling{
					PersonID: one.PersonID, Kind: notify.ApprovalUndone,
					Body: what + " was agreed to and the agreement has been taken back. " +
						"It is waiting for a second person again; nothing you wrote has changed.",
					Link:    "/decisions/" + strconv.FormatInt(one.DecisionID, 10),
					Private: one.Undisclosed,
					// What a later read narrows by.
					ProductID:       &one.ProductID,
					VulnerabilityID: &one.VulnerabilityID,
				}); err != nil && in.Logger != nil {
					in.Logger.Error("could not say that an agreement was taken back",
						"error", err, "person", one.PersonID, "batch", input.Batch)
				}
			}
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
		Description: "Records how a finding was triaged: `affected`, `not-applicable`, `deferred`, " +
			"`wont-fix`, `already-fixed` or `patch-needed`.\n\n" +
			"`not-applicable` requires a `justification` from the standard VEX vocabulary. " +
			"`deferred` requires `deferred_until` as a date. `already-fixed` requires " +
			"`fixed_version`, the version whoever packages the component states the fix " +
			"arrived in — it is recorded for a reader and never compared against what ships.\n\n" +
			"**`patch-needed` is the backport case**: a fix is being carried into this build " +
			"and the version does not move. It requires `committed_to`, the date the work " +
			"lands, and it closes the only way a backport can — the next inventory declares " +
			"the patch it carries and says what that patch resolves, so the finding goes " +
			"while the version stays where it was.\n\n" +
			"`upgrade-needed` is not recorded here. A bump answers a component rather than one " +
			"finding, so it is recorded from the component and covers everything open on it.\n\n" +
			"The decision applies to every build running the same component and consumer upstream " +
			"versions, including future releases — it is matched by code, not copied between " +
			"releases. It stops applying automatically when either upstream version changes.\n\n" +
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
		Place         string `path:"place" doc:"Which place, as the findings list gives it"`
		Body          DecisionBody
	}) (*struct{ Body DecisionBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		// Refused here rather than by the store, because what is wrong with
		// it is the grain rather than the claim: the same outcome recorded
		// from a component is exactly right, and the sentence has to say
		// where to go rather than that the word is invalid.
		if triage.Outcome(input.Body.Outcome) == triage.UpgradeNeeded {
			return nil, huma.Error422UnprocessableEntity(
				"an upgrade answers a component rather than one finding: record it from the " +
					"component, where it covers everything open on it in the releases you name")
		}

		at, err := decidingAbout(ctx, in, subject, input.Product, input.Stream, input.Variant,
			input.Vulnerability, input.Place)
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

		// Asked before the claim is recorded, so the answer can say whether it
		// is waiting for anybody. A short deferral is ordinary triage and
		// takes effect at once.
		threshold, err := deferralThreshold(ctx, in)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot tell whether that needs agreement", err)
		}
		needs, err := store.NeedsApproval(ctx, proposal, threshold)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot tell whether that needs agreement", err)
		}
		// Recorded on the claim, not merely reported back. A claim that says
		// it is waiting for somebody and is stored as needing nobody takes
		// effect the moment it is made, and the answer telling the caller it
		// was waiting is the only trace of a control that did not run.
		proposal.NeedsApproval = needs

		decision, err := store.Propose(ctx, subject, proposal)
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}

		body := decisionBody(*decision)
		body.Reasoning = input.Body.Reasoning
		body.NeedsApproval = needs
		// How much this one judgment covers, so nobody discovers afterwards
		// that they answered for sixty-two modules or for two versions of the
		// same package.
		body.Places, body.Versions = at.Places, at.Versions()
		return &struct{ Body DecisionBody }{Body: body}, nil
	})
}

// FindingDecisionBody is one judgment about a finding, and which of its places
// it covers.
type FindingDecisionBody struct {
	Outcome       string `json:"outcome" enum:"affected,not-applicable,deferred,wont-fix,already-fixed,patch-needed"`
	Justification string `json:"justification,omitempty" enum:"component_not_present,vulnerable_code_not_present,vulnerable_code_not_in_execute_path,vulnerable_code_cannot_be_controlled_by_adversary,inline_mitigations_already_exist" doc:"Why it does not apply. Required when it does not"`
	Mitigation    string `json:"mitigation,omitempty" maxLength:"65536" doc:"What actually stops it — the rule, the setting, the service that is not exposed. Required when the reason is that mitigations already exist, and refused with any other"`
	DeferredUntil string `json:"deferred_until,omitempty" doc:"Required when it is deferred. A date, as 2026-03-31"`
	// CommittedTo is when a promised backport lands. An upgrade is not
	// recorded here at all: it answers a component rather than one
	// finding, so it is recorded from the component.
	CommittedTo string `json:"committed_to,omitempty" doc:"When a promised backport lands, as a date. Required for patch-needed and refused with any other"`
	// FixedVersion is what makes the already-fixed claim checkable against
	// whoever packages the component. Offered here because the outcome is
	// offered here: an enum listing an outcome whose evidence the body
	// cannot carry refuses every request that picks it.
	FixedVersion string `json:"fixed_version,omitempty" doc:"The package version whoever packages this states the fix arrived in. Required when the outcome is already-fixed, and refused with any other"`
	Reasoning    string `json:"reasoning" minLength:"1" doc:"Why this holds"`
	// Places is the deliberate narrowing. Absent means every place, which
	// is the default naming the places covered asks for.
	Places []string `json:"places,omitempty" doc:"Which places this covers, as the finding names them. Omit for all of them"`
	// Extends names an approved claim this one carries to a new issue. The
	// outcome and justification have to be the source's, and the places have
	// to be ones the source sits at.
	Extends int64 `json:"extends,omitempty" doc:"An approved claim at the same component and consumer to carry to this issue. The outcome and justification must match it; the new claim is recorded as an extension of it and still needs a second person"`
	// Remaining decides only the places nothing stands at yet. For applying
	// a decision to another build, where the places at matching versions
	// are already reached by lookup and a second claim about them would be
	// refused.
	Remaining bool `json:"remaining,omitempty" doc:"Decide only the places nothing currently stands at, and leave the rest as they are. For applying a decision to another build, where some of its places are already reached by lookup"`
	// FromStatement cites a VEX statement this was started
	// from. A citation and never an application: what they said is not this
	// claim, and recording it is what lets a later revision be noticed.
	FromStatement int64 `json:"from_statement,omitempty" doc:"A VEX statement this was started from, by its identifier. Recorded as a citation so a later revision to it raises an alert. It is never what the claim rests on"`
	// Also carries the same judgment to other builds of this product, in
	// the same transaction as the build in the path.
	Also []AlsoBuild `json:"also,omitempty" doc:"Other builds of this product the same judgment covers. All of it is written together or none of it is"`
}

// AlsoBuild is another build one judgment reaches, as the reach names it.
type AlsoBuild struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	// Version is what that build ships under this component's name, and is
	// required wherever it ships more than one — the same reason the route
	// takes it as a query for the build in the path.
	Version string `json:"version,omitempty" doc:"The version that build ships under this name, where it ships more than one"`
}

// DecidedBody is what one judgment about a finding recorded.
type DecidedBody struct {
	ClaimID       int64   `json:"claim_id" doc:"The claim this action made, which is what the review queue lists and what is approved"`
	Recorded      int     `json:"recorded" doc:"How many places it was written against"`
	Covered       int     `json:"covered" doc:"How many findings those places hold"`
	Left          int     `json:"left" doc:"Places of this finding left open, because they were not named"`
	NeedsApproval bool    `json:"needs_approval" doc:"Whether a second person has to agree"`
	IDs           []int64 `json:"ids"`
	// Also is what the same judgment wrote in each other build named, in the
	// order they were named. Absent where none were.
	Also []CoveredBuild `json:"also,omitempty" doc:"What this judgment wrote in each other build it was applied to"`
}

// CoveredBuild is what one judgment wrote in one other build.
//
// There is no per-build outcome to report, because there is no per-build
// outcome to have: the whole judgment is written or none of it is.
type CoveredBuild struct {
	Stream   string `json:"stream"`
	Variant  string `json:"variant"`
	Version  string `json:"version,omitempty"`
	Recorded int    `json:"recorded" doc:"How many places it was written against there"`
	Covered  int    `json:"covered" doc:"How many findings those places hold"`
}

func registerFindingDecision(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "decide-finding", Method: http.MethodPost,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/findings/{vulnerability}/components/{component}/decision",
		Summary: "Record one judgment about a finding, covering its places",
		Description: "Records the same claim against every place this issue occupies in this " +
			"component. Naming `places` narrows it; leaving it out covers all of them.\n\n" +
			"**A place left out stays open.** Nothing is recorded against it and nothing is " +
			"asked about it.\n\n" +
			"One record is written per place, each keyed and expiring on its own, so this " +
			"reads later as the several decisions it is rather than as one.\n\n" +
			"The ordinary approval rules apply however many places this reaches: covering " +
			"many places does not on its own require a second person.\n\n" +
			"Pass `also` to apply the same judgment to other builds of this product, naming " +
			"each as the reach gives it. All of it is written in one transaction: the " +
			"response is what every build recorded, or a refusal and nothing written " +
			"anywhere. In those builds only the places nothing already stands at are " +
			"written, because the ones at matching versions are reached by lookup " +
			"already.\n\n" +
			"Pass `extends` to carry an approved claim to this issue: the source must be " +
			"approved, sit at the same component under the same consumer, and the outcome and " +
			"justification must match it. The new claim is recorded as an extension of it and " +
			"still waits for a second person. `similar` on `GET .../findings/{vulnerability}/" +
			"components/{component}` lists the claims that qualify.\n\n" +
			"**`patch-needed` is the backport case**: a fix is being carried into this build " +
			"and the version does not move, so it requires `committed_to`, the date the work " +
			"lands. `upgrade-needed` is not recorded here — a bump answers a component and " +
			"everything open on it, so it is recorded from the component.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Component     string `path:"component" doc:"The component, as the findings list gives it"`
		Version       string `query:"version" doc:"Which version, where the build ships more than one under that name"`
		Body          FindingDecisionBody
	}) (*struct{ Body DecidedBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}

		// Every build this judgment covers, named before anything is
		// written: the one in the path, and any the caller put beside
		// it.
		asked := append([]AlsoBuild{{
			Stream: input.Stream, Variant: input.Variant, Version: input.Version,
		}}, input.Body.Also...)
		named := make(map[string]bool, len(asked))
		for _, build := range asked {
			if named[build.Stream+"\x00"+build.Variant] {
				return nil, huma.Error422UnprocessableEntity(
					"a build is named twice, and one judgment is recorded against it once")
			}
			named[build.Stream+"\x00"+build.Variant] = true
		}

		var until *time.Time
		if input.Body.DeferredUntil != "" {
			when, err := time.Parse(time.DateOnly, input.Body.DeferredUntil)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(
					"a deferral returns on a date, written as YYYY-MM-DD")
			}
			until = &when
		}
		var lands *time.Time
		if input.Body.CommittedTo != "" {
			when, err := time.Parse(time.DateOnly, input.Body.CommittedTo)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(
					"the date promised work lands on is written as YYYY-MM-DD")
			}
			lands = &when
		}

		threshold, err := deferralThreshold(ctx, in)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot tell whether that needs agreement", err)
		}
		limit, err := setting.NewStore(in.DB.DB).Count(ctx, setting.TogetherCap,
			triage.DefaultTogetherCap)
		if err != nil {
			return nil, wentWrong(in.Logger, "the limit on one action could not be read", err)
		}

		out := &struct{ Body DecidedBody }{}
		var proposals []triage.Proposal
		// What each build contributes, so that the judgment can report per
		// build once the whole of it has been written.
		writes := make([]int, len(asked))
		holds := make([]int, len(asked))
		sits := 0
		for i, build := range asked {
			// Only the build in the path takes the caller's narrowing. In the
			// others the places at matching versions are already reached by
			// lookup, and a second claim about them would be refused, so what
			// is written there is whatever nothing stands at yet.
			wanted, remaining := input.Body.Places, input.Body.Remaining
			if i > 0 {
				wanted, remaining = nil, true
			}
			places, all, err := placesToDecide(ctx, in, subject, store, input.Product,
				build.Stream, build.Variant, input.Vulnerability, input.Component,
				build.Version, wanted, remaining)
			if err != nil {
				if i == 0 {
					return nil, err
				}
				return nil, aboutBuild(build.Stream, build.Variant, err)
			}
			if i == 0 {
				sits = all
			}

			for _, place := range places {
				proposal := triage.Proposal{
					Place: triage.Place{
						ProductID: place.ProductID, VulnerabilityID: place.VulnerabilityID,
						PlaceIdentity: place.PlaceIdentity, Visibility: place.Visibility,
						ComponentUpstream: place.ComponentUpstream,
						ConsumerUpstream:  place.ConsumerUpstream,
						OnTag:             place.OnTag,
					},
					Outcome:       triage.Outcome(input.Body.Outcome),
					Justification: triage.Justification(input.Body.Justification),
					Mitigation:    input.Body.Mitigation,
					FixedVersion:  input.Body.FixedVersion,
					Reasoning:     input.Body.Reasoning,
					By:            subject.ID,
					SeverityCenti: place.SeverityCenti,
					DeferredUntil: until,
					CommittedTo:   lands,
				}
				// Asked per place rather than once for the set. The threshold
				// reads the claim, and two places of one finding can differ in
				// what they carry — one answer for all of them would report a
				// control that did not run on some.
				needs, err := store.NeedsApproval(ctx, proposal, threshold)
				if err != nil {
					return nil, wentWrong(in.Logger,
						"cannot tell whether that needs agreement", err)
				}
				proposal.NeedsApproval = needs
				out.Body.NeedsApproval = out.Body.NeedsApproval || needs
				writes[i]++
				holds[i] += place.Places
				proposals = append(proposals, proposal)
			}
		}

		// One action, one transaction, however many builds it reached. Half of
		// them written and the rest abandoned leaves a judgment recorded in
		// some releases and not others — an act nobody performed, and one
		// nobody can point at afterwards.
		var recorded []*triage.Decision
		if input.Body.Extends != 0 {
			recorded, err = store.Extend(ctx, subject, input.Body.Extends, proposals, limit)
		} else {
			recorded, err = store.ProposeMany(ctx, subject, proposals, limit)
		}
		if err != nil {
			return nil, refusedDecision(in.Logger, err)
		}
		for _, decision := range recorded {
			out.Body.IDs = append(out.Body.IDs, decision.ID)
			out.Body.ClaimID = decision.ClaimID
		}
		if out.Body.IDs == nil {
			out.Body.IDs = []int64{}
		}
		// The counts on the body itself are about the build in the path, which
		// is what they have always been about; the others report themselves.
		out.Body.Recorded = writes[0]
		out.Body.Covered = holds[0]
		out.Body.Left = sits - out.Body.Recorded
		for i, build := range asked[1:] {
			out.Body.Also = append(out.Body.Also, CoveredBuild{
				Stream: build.Stream, Variant: build.Variant, Version: build.Version,
				Recorded: writes[i+1], Covered: holds[i+1],
			})
		}
		return out, nil
	})
}

// placesToDecide resolves one build's places for a finding, narrowed the way
// the caller asked for.
//
// Returns what to write against and how many places the finding sits at there.
// The two differ whenever something was left out, and the difference is what
// says how much of the finding is still open.
func placesToDecide(ctx context.Context, in Ingest, subject access.Subject, store *triage.Store,
	product, stream, variant, vulnerability, component, version string,
	wanted []string, remaining bool) ([]finding.Deciding, int, error) {

	target, issue, at, err := findingAbout(ctx, in, subject,
		product, stream, variant, vulnerability, component, version)
	if err != nil {
		return nil, 0, err
	}
	all, err := finding.NewStore(in.DB.DB).PlacesFor(ctx, subject, target, issue, at)
	if err != nil || len(all) == 0 {
		return nil, 0, noSuchFinding()
	}

	// Narrowed to what was named, and a name nothing matches is refused
	// rather than ignored: somebody who meant to cover six places and
	// mistyped one should not quietly cover five.
	places := all
	if len(wanted) > 0 {
		asked := map[string]bool{}
		for _, name := range wanted {
			asked[name] = true
		}
		places = make([]finding.Deciding, 0, len(asked))
		for _, place := range all {
			if asked[place.PlaceIdentity] {
				places = append(places, place)
				delete(asked, place.PlaceIdentity)
			}
		}
		if len(asked) > 0 {
			return nil, 0, huma.Error422UnprocessableEntity(
				"this finding does not sit at every place you named")
		}
	}

	if !remaining {
		return places, len(all), nil
	}
	ask := make([]triage.Place, 0, len(places))
	for _, place := range places {
		ask = append(ask, triage.Place{
			ProductID: place.ProductID, VulnerabilityID: place.VulnerabilityID,
			PlaceIdentity: place.PlaceIdentity, Visibility: place.Visibility,
			ComponentUpstream: place.ComponentUpstream,
			ConsumerUpstream:  place.ConsumerUpstream,
		})
	}
	left, err := store.Undecided(ctx, ask)
	if err != nil {
		return nil, 0, wentWrong(in.Logger, "cannot tell what already stands here", err)
	}
	standing := make(map[string]bool, len(left))
	for _, one := range left {
		standing[one.PlaceIdentity+"\x00"+one.ComponentUpstream+"\x00"+one.ConsumerUpstream] = true
	}
	// Everything else is already reached by lookup: nothing to record there,
	// and nothing wrong either. An empty answer is what says so.
	open := make([]finding.Deciding, 0, len(left))
	for _, place := range places {
		if standing[place.PlaceIdentity+"\x00"+place.ComponentUpstream+"\x00"+place.ConsumerUpstream] {
			open = append(open, place)
		}
	}
	return open, len(all), nil
}

// aboutBuild says which of the builds a refusal is about.
//
// Only for the ones named beside the path, and it says nothing a caller did
// not already know: it named the build itself, and the refusal is the same one
// the build in the path would have got.
func aboutBuild(stream, variant string, err error) error {
	var status huma.StatusError
	if errors.As(err, &status) {
		return huma.NewError(status.GetStatus(), stream+"/"+variant+": "+status.Error())
	}
	return err
}

// findingAbout resolves the names in a path to one finding: the build, the
// issue and the component it is open against, authorized on the way.
//
// Name and version together, because a name alone is not unique — a real image
// ships three vendored versions of one library, and resolving the name on its
// own answers about whichever was interned first.
func findingAbout(ctx context.Context, in Ingest, subject access.Subject,
	product, stream, variant, vulnerability, component, version string) (int64, int64, int64, error) {

	names := catalog.NewStore(in.DB.DB)
	named, err := names.LocateVisible(ctx, subject, product, stream, variant)
	if err != nil {
		return 0, 0, 0, noSuchProduct()
	}
	target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
	if err != nil {
		return 0, 0, 0, nothingScannedThere()
	}
	issue, err := issueHere(ctx, in, subject, named.ProductID, vulnerability)
	if err != nil {
		return 0, 0, 0, err
	}
	at, err := graph.NewStore(in.DB.DB).ComponentVersionAt(ctx, target.ID, component, version)
	if err != nil {
		return 0, 0, 0, ambiguousOrMissing(err)
	}
	return target.ID, issue, at, nil
}

// decidingAbout resolves the names in a path to the place a decision is made
// about, authorized on the way.
func decidingAbout(ctx context.Context, in Ingest, subject access.Subject,
	product, stream, variant, vulnerability, place string) (*finding.Deciding, error) {
	names := catalog.NewStore(in.DB.DB)
	named, err := names.LocateVisible(ctx, subject, product, stream, variant)
	if err != nil {
		return nil, huma.Error404NotFound(err.Error())
	}
	target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
	if err != nil {
		return nil, nothingScannedThere()
	}

	issue, err := issueHere(ctx, in, subject, named.ProductID, vulnerability)
	if err != nil {
		return nil, err
	}

	at, err := finding.NewStore(in.DB.DB).PlaceFor(ctx, subject, target.ID, issue, place)
	if err != nil {
		return nil, noSuchFinding()
	}
	return at, nil
}

// ReachBody is how far a judgment made here would travel.
type ReachBody struct {
	Here      int         `json:"here" doc:"Places in this build the judgment covers"`
	Automatic []MatchBody `json:"automatic" doc:"Other builds it reaches by matching. Nothing to agree to"`
	Differing []MatchBody `json:"differing" doc:"The same issue at the same place held at another version — in this build or in another. Each is a separate judgment, because the code differs"`
}

func reachBody(r finding.Reach) ReachBody {
	body := ReachBody{
		Here:      r.Here,
		Automatic: make([]MatchBody, 0, len(r.Automatic)),
		Differing: make([]MatchBody, 0, len(r.Differing)),
	}
	for _, m := range r.Automatic {
		body.Automatic = append(body.Automatic, MatchBody{
			Stream: m.Stream, Variant: m.Variant, Version: m.Version, Places: m.Places, Here: m.Here,
		})
	}
	for _, m := range r.Differing {
		body.Differing = append(body.Differing, MatchBody{
			Stream: m.Stream, Variant: m.Variant, Version: m.Version, Places: m.Places, Here: m.Here,
		})
	}
	return body
}

// MatchBody is the same issue at the same place in another build.
type MatchBody struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
	// Version is what that build ships, and why this is a separate question.
	// Where it matched, the decision already reaches there and nobody is
	// asked. It is the version the decision route resolves a name by, so a
	// caller applying the decision there passes it back as ?version=.
	Version string `json:"version,omitempty" doc:"The version that build ships under this name — pass it as ?version= when applying a decision there"`
	Places  int    `json:"places" doc:"How many places it sits at there"`
	// Here says this is another version in the build being decided in, rather
	// than in another release or variant. A build commonly ships one name at
	// several versions, and those sit beside the one in hand.
	Here bool `json:"here,omitempty" doc:"This is another version in the same build, not another build"`
}

func registerElsewhere(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-decision-reach", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/places/{place}/reach",
		Summary: "Show how far a decision here would reach",
		Description: "Returns the three parts of what a judgment made here covers.\n\n" +
			"`here` is how many places in this build. `automatic` are other builds it reaches " +
			"without anybody doing anything, because their upstream versions and chains already " +
			"match — a decision is a claim about a combination of code, not about a release. " +
			"`differing` hold the same issue at the same place at another version, so each is a " +
			"separate judgment.\n\n" +
			"Only `differing` is a choice. The first two follow from the matching rules and are " +
			"there to be told, not agreed to — and showing them as one number is how a decision " +
			"comes to reach builds the person making it never knew about.",
		Tags: []string{"Triage"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Place         string `path:"place"`
	}) (*struct{ Body ReachBody }, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		at, err := decidingAbout(ctx, in, subject, input.Product, input.Stream, input.Variant,
			input.Vulnerability, input.Place)
		if err != nil {
			return nil, err
		}

		names := catalog.NewStore(in.DB.DB)
		named, err := names.LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, huma.Error404NotFound(err.Error())
		}
		here, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
		if err != nil {
			return nil, nothingScannedThere()
		}

		reach, err := finding.NewStore(in.DB.DB).Reaching(ctx, subject, *at, here.ID)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot look for the same issue elsewhere", err)
		}
		return &struct{ Body ReachBody }{Body: reachBody(reach)}, nil
	})
}

func registerReachAcross(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-finding-reach", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/findings/{vulnerability}/components/{component}/reach",
		Summary: "Show how far a decision about this finding would reach",
		Description: "The same three parts the per-place answer gives, for every place " +
			"the finding sits at, merged.\n\n" +
			"A judgment is made about an issue in a component, which is a group of places " +
			"rather than one — a kernel flaw sits at sixty. Asking per place is a request " +
			"each, so a screen doing that samples, and a sample decides which other builds " +
			"it can offer to include: one reachable only from a place the sample missed is " +
			"never offered and the judgment does not travel there.\n\n" +
			"A build reached from two places of the finding is one thing to agree to, and " +
			"carries the places of both.",
		Tags: []string{"Triage"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability"`
		Component     string `path:"component"`
		Version       string `query:"version" doc:"Which version, where the build holds that name at more than one"`
	}) (*struct{ Body ReachBody }, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		target, issue, at, err := findingAbout(ctx, in, subject, input.Product, input.Stream,
			input.Variant, input.Vulnerability, input.Component, input.Version)
		if err != nil {
			return nil, err
		}
		places, err := finding.NewStore(in.DB.DB).PlacesFor(ctx, subject, target, issue, at)
		if err != nil || len(places) == 0 {
			return nil, noSuchFinding()
		}
		reach, err := finding.NewStore(in.DB.DB).ReachingAcross(ctx, subject, places, target)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot look for the same issue elsewhere", err)
		}
		return &struct{ Body ReachBody }{Body: reachBody(reach)}, nil
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

// refused turns a store's refusal into an answer.
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
	var faults markdown.Faults
	if errors.As(err, &faults) {
		return refusedText(faults)
	}
	// A database that broke is not somebody having asked for the impossible.
	// The default arm answered both as 422 with the message in it, so a lost
	// connection reached the caller as a bad request carrying the statement
	// text and the address the driver had tried.
	if database.FromEngine(err) {
		return wentWrong(logger, "that could not be recorded", err)
	}
	// What is left is a sentence the triage store wrote for a person to read:
	// a decision already standing here, a claim covering nothing, a threshold
	// crossed. Those are the caller's to fix, and the message is the answer.
	return huma.Error422UnprocessableEntity(err.Error())
}

// refusedText answers a refused piece of writing with where to look.
//
// Each fault travels as its own detail, carrying the line and the text that
// caused it. Flattening them into one sentence is what this used to do, and it
// leaves an interface with nothing to point at: "remote images are not
// allowed" against a forty-line justification means somebody hunting for it by
// eye, which is the whole reason positions are gathered in the first place.
func refusedText(faults markdown.Faults) error {
	details := make([]error, 0, len(faults))
	for _, fault := range faults {
		details = append(details, &huma.ErrorDetail{
			Message: fault.Reason,
			// Where in the submitted text, not where in the request body. A
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
	// What the judgment says comes from the claim: one act is one argument,
	// and this row says where it lands. A decision read without its claim is
	// a programming error rather than a state a caller can reach, so it is
	// left to fail here rather than rendered as an outcome nobody chose.
	said := d.Claim
	body := DecisionBody{
		ID: d.ID, ClaimID: d.ClaimID, Outcome: string(said.Outcome), State: string(d.State),
	}
	if said.Mitigation != nil {
		body.Mitigation = *said.Mitigation
	}
	if said.Justification != nil {
		body.Justification = *said.Justification
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
	const shipped = 30 * 24 * time.Hour
	if in.DB == nil {
		return shipped, nil
	}
	return setting.NewStore(in.DB.DB).Duration(ctx, setting.DeferralThreshold, shipped)
}
