// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

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
	ID          int64          `json:"id"`
	Kind        core.ClaimKind `json:"kind" doc:"The sort of action: one judgment about a finding, one about many issues at a component, an approved claim carried to a new issue, or rows set aside from a larger claim — by an approver agreeing to the rest, or by the author holding them back"`
	DerivedFrom int64          `json:"derived_from,omitempty" doc:"The claim this one came from, for an extension or a returned set"`
	ProposedBy  string         `json:"proposed_by" doc:"The person who took it, by sign-in identity"`
	// ProposedByName is the label beside the identity.
	ProposedByName string `json:"proposed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
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
	Decision core.DecisionBody `json:"decision"`
	Place    core.PlaceBody    `json:"place"`
	// Everything an approver needs to judge without opening it. A list where
	// judging a row means opening it is a list that gets approved unread.
	Reasoning          string `json:"reasoning"`
	PreviouslyApproved bool   `json:"previously_approved,omitempty" doc:"This was agreed to before and came back"`
	DeferredDays       int    `json:"deferred_days,omitempty" doc:"The total this finding has been put off for"`
	ProposedBy         string `json:"proposed_by" doc:"The person who made the claim, by sign-in identity"`
	ProposedByName     string `json:"proposed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
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
	Finding *core.FindingRefBody `json:"finding,omitempty" doc:"The representative decision's subject — build, issue, component, where it sits — so the card can be judged without opening it. Absent where no open finding sits at its place"`
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
	Claim    ClaimBody         `json:"claim"`
	Decision core.DecisionBody `json:"decision"`
	Place    core.PlaceBody    `json:"place"`
	// Happened is the word for what became of it. "mixed" is a claim whose
	// rows do not all end the same way — an approver agreeing to most of a
	// bulk set and setting some aside, or half of it lapsing as one build
	// moves — and is stated rather than picked between.
	Happened core.Happened `json:"happened" doc:"The claim's outcome"`
	// The moment it became that, and the person who did it where a person
	// did. Both absent while it is waiting: nothing has happened to it yet.
	When      string               `json:"when,omitempty" doc:"The moment it became that"`
	By        string               `json:"by,omitempty" doc:"The person who did it, where a person did, by sign-in identity"`
	ByName    string               `json:"by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	Reasoning string               `json:"reasoning"`
	Decisions int                  `json:"decisions" doc:"The number of rows the claim wrote"`
	Issues    int                  `json:"issues" doc:"The number of distinct issues it covers"`
	Places    int                  `json:"places" doc:"The number of distinct places it covers"`
	Finding   *core.FindingRefBody `json:"finding,omitempty" doc:"The representative decision's subject. Absent where no open finding sits at its place"`
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

func registerTriage(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-review-queue", Method: http.MethodGet, Path: "/v1/review-queue",
		Summary: "List the review queue",
		Description: "Returns the claims waiting for one reason, newest first. One entry is one " +
			"claim — one proposer's action, however many decisions it wrote — with a " +
			"representative decision and place, how many rows, issues and places it covers, " +
			"and every build it currently reaches.\n\n" +
			"`reason` picks the list:\n\n" +
			"- `approval`, the default: claims waiting for a second person, limited to what " +
			"you may approve every row of. Your own are not here, because approving your own " +
			"is refused. Approve, send back or set rows aside with " +
			"`POST /v1/claims/{id}/approval` and `POST /v1/claims/{id}/send-back`.\n" +
			"- `expired-deferral`: deferrals whose date has passed.\n" +
			"- `missed-fix-date`: promised upgrades and patches whose date has passed with the " +
			"finding still open. Change the promise with `PUT /v1/claims/{id}/promise`.\n\n" +
			"The last two list claims you may decide on every row of, your own included, and " +
			"are answered by a new decision. A decision the code moved out from under is in " +
			"none of them; its author finds it in `GET /v1/to-reaffirm`.\n\n" +
			"`mine=true` keeps only your own claims: for approvals, what you proposed and " +
			"nobody has agreed to yet.\n\n" +
			"Each entry carries the full reasoning, whether it was previously approved and came " +
			"back, how long the finding has been deferred in total, and how old the claim is. A " +
			"claim over many issues also carries `outliers`: the rows that do not look like the " +
			"rest, which is what to read instead of all of them.\n\n" +
			"Narrow by who proposed a claim, how old it is, how severe the issues it covers " +
			"are, its outcome, and the release it covers. A claim is kept where one of its " +
			"rows matches every filter, and is then returned whole.\n\n" +
			"`limit=0` returns `total` alone, with no entries.",
		Tags: []string{"Triage"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Mine    bool   `query:"mine" doc:"Return only claims you proposed. For approvals, what you proposed and nobody has agreed to, instead of what is waiting on you"`
		Product string `query:"product" doc:"Limit to claims made in one product, by name. Empty means every product you can see; a name you cannot see is refused rather than answered empty"`
		core.QueueNarrowing
		core.CountedPaging
	}) (*QueueOutput, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		filter, err := input.Filter(ctx, in, subject, input.Mine, input.Product)
		if err != nil {
			return nil, err
		}

		waiting, total, err := store.Queue(ctx, subject, filter, input.Limit, input.Offset)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the review queue could not be read", err)
		}

		// The finding each row is about, and the person who made the claim,
		// resolved here rather than left as identifiers. A queue row saying
		// product 4, issue 91 is a row an approver has to make two more
		// requests to understand, fifty times a page.
		decisions := make([]triage.Decision, 0, len(waiting))
		for _, row := range waiting {
			decisions = append(decisions, row.Decision)
		}
		named, err := core.DescribeDecisions(ctx, in, store, decisions, nil)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the review queue could not be read", err)
		}

		out := &QueueOutput{}
		out.Body.Items = make([]WaitingBody, 0, len(waiting))
		for i, row := range waiting {
			entry := WaitingBody{
				Claim:              claimBody(row.Claim, named[i].ProposedBy, named[i].ProposedByName),
				Decision:           core.DecisionBodyOf(row.Decision),
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

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "repromise-upgrade", Method: http.MethodPut,
		Path:    "/v1/claims/{id}/promise",
		Summary: "Change a promised upgrade or patch",
		Description: "Changes the version a promised upgrade moves to, or the date a promised " +
			"upgrade or patch is promised by, on the claim and on every commitment it wrote. " +
			"A promised patch has no version: send `to` empty or leave it out.\n\n" +
			"This withdraws any existing approval and returns every row of the claim to " +
			"the review queue, and notifies everybody whose approval it withdrew. An approver " +
			"agreed to a version by a date; changing either is " +
			"changing what they agreed to, so it goes through the same act revising the words " +
			"does.\n\n" +
			"`reasoning` is required and is recorded as a revision — saying why a date moved " +
			"is what the second person has to read, and the revisions are where what was said " +
			"before survives being changed.",
		Tags: []string{"Remediation"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			To        string `json:"to,omitempty" doc:"The version an upgrade now moves to. Required for an upgrade, and refused for a patch"`
			By        string `json:"by" format:"date" doc:"The date the work will be done by"`
			Reasoning string `json:"reasoning" minLength:"1" doc:"The reason the promise is changing, in markdown"`
		}
	}) (*struct{}, error) {
		subject, store, err := core.Triaging(ctx, in)
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
			return nil, core.RefusedDecision(in.Logger, err)
		}
		changed := "The reasoning"
		if moved {
			changed = "The promise"
		}
		tellTheApprovers(ctx, in, input.ID, withdrawn, changed)
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
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
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		held, err := store.Split(ctx, subject, input.ID, input.Body.Rows, input.Body.Because)
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		out := &struct {
			Body struct {
				ClaimID int64 `json:"claim_id" doc:"The claim the rows were moved into"`
			}
		}{}
		out.Body.ClaimID = held.ID
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*BecameOutput, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		mine, total, err := store.Became(ctx, subject, input.Limit, input.Offset)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what you proposed could not be read", err)
		}

		decisions := make([]triage.Decision, 0, len(mine))
		for _, row := range mine {
			decisions = append(decisions, row.Decision)
		}
		named, err := core.DescribeDecisions(ctx, in, store, decisions, nil)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what you proposed could not be read", err)
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
		who, err := core.WhoSigned(ctx, in.DB.DB, actors)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what you proposed could not be read", err)
		}

		out := &BecameOutput{}
		out.Body.Items = make([]BecameBody, 0, len(mine))
		for i, row := range mine {
			entry := BecameBody{
				Claim:     claimBody(row.Claim, named[i].ProposedBy, named[i].ProposedByName),
				Decision:  core.DecisionBodyOf(row.Decision),
				Place:     named[i].Place,
				Reasoning: row.Reasoning,
				Happened:  core.Happened(row.Happened),
				Decisions: row.Rows,
				Issues:    row.Issues,
				Places:    row.Places,
				Finding:   named[i].Finding,
			}
			if row.When != nil {
				entry.When = row.When.UTC().Format(time.RFC3339)
			}
			if row.By != 0 {
				entry.By, entry.ByName = who.Identity(row.By), who.Label(row.By)
			}
			if row.Outliers != nil {
				entry.Outliers = outliersBody(*row.Outliers)
			}
			out.Body.Items = append(out.Body.Items, entry)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		ID   int64 `path:"id"`
		Body struct {
			Reasoning string `json:"reasoning" minLength:"1"`
		}
	}) (*struct{ Body core.MentionsBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		revised, err := store.Revise(ctx, subject, input.ID, input.Body.Reasoning)
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		tellTheApprovers(ctx, in, input.ID, revised.Withdrawn, "The reasoning")
		dropped := core.TellMentioned(ctx, in, subject, store, input.ID, input.Body.Reasoning)
		return &struct{ Body core.MentionsBody }{Body: core.MentionsBody{NotNotified: dropped}}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "withdraw-claim", Method: http.MethodDelete, Path: "/v1/claims/{id}",
		Summary: "Withdraw a triage claim",
		Description: "Withdraws the claim so none of it applies to any finding. A claim is one " +
			"argument however many places it covers, so this takes back all of it; holding part " +
			"of one back is setting rows aside, at `POST /v1/claims/{id}/approval`. The record " +
			"is kept — a withdrawn claim reads as proposed, approved, then withdrawn. " +
			"Requires no approval.",
		Tags:          []string{"Triage"},
		DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{}, error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		if err := store.Withdraw(ctx, subject, input.ID); err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Answering(huma.Operation{
		OperationID: "undo-batch", Method: http.MethodDelete, Path: "/v1/approval-batches/{batch}",
		Summary: "Undo a bulk approval",
		Description: "Withdraws every approval recorded under this batch name, returning those " +
			"decisions to the review queue. The decisions themselves stand — only the approvals " +
			"are undone. Returns how many were affected.\n\n" +
			"Only decisions you may reach are touched.",
		Tags: []string{"Triage"},
	}, core.PerProduct, "A batch is one reviewer's afternoon and may span products, so it "+
		"is undone as far as you reach and no further.", core.ApproveRights()...),
		func(ctx context.Context, input *struct {
			Batch string `path:"batch"`
		}) (*struct {
			Body struct {
				Undone int64 `json:"undone"`
			}
		}, error) {
			subject, store, err := core.Triaging(ctx, in)
			if err != nil {
				return nil, err
			}
			undone, err := store.UndoBatch(ctx, subject, input.Batch)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "an agreement could not be undone", err)
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

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "comment-on-claim", Method: http.MethodPost, Path: "/v1/claims/{id}/comments",
		Summary: "Add a comment to a claim",
		Description: "Adds a markdown comment to a claim. Comments are separate from the " +
			"justification and never affect an approval, so an approved claim can be annotated " +
			"at any time.\n\n" +
			"A comment may later be edited by its author only, and editing overwrites it rather " +
			"than keeping revisions.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", core.ApproveRights()...), func(ctx context.Context, input *struct {
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
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		comment, err := store.Say(ctx, subject, input.ID, input.Body.Body)
		if err != nil {
			return nil, core.RefusedDecision(in.Logger, err)
		}
		dropped := core.TellMentioned(ctx, in, subject, store, input.ID, input.Body.Body)
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

func registerProposing(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
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
	}, core.PerProduct, "", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Place         string `path:"place" doc:"The place, as the findings list gives it"`
		Body          core.DecisionBody
	}) (*struct{ Body core.DecisionBody }, error) {
		subject, store, err := core.Triaging(ctx, in)
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
			Place:         placeOf(*at),
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
			FromStatement: core.Cited(input.Body.FromStatement),
			// Made on the build in the path, which is the one on screen.
			MadeOn: []int64{target},
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
			return nil, core.RefusedDecision(in.Logger, err)
		}

		body := core.DecisionBodyOf(*decision)
		body.Reasoning = input.Body.Reasoning
		// The reach of this one judgment, so nobody discovers afterwards
		// that they answered for sixty-two modules or for two versions of the
		// same package.
		body.Places, body.Versions = at.Places, at.Versions()
		return &struct{ Body core.DecisionBody }{Body: body}, nil
	})
}

// tellTheApprovers tells everybody whose agreement an edit took back.
//
// Approval is otherwise silent, and this is the one outcome an approver cannot
// see coming: somebody else changed what they agreed to, and their agreement
// stopped counting. What changed is named, the claim is linked, and a claim
// with an undisclosed row carries nothing more than that, like every telling
// about an undisclosed finding.
func tellTheApprovers(ctx context.Context, in core.Deps, claimID int64,
	withdrawn []triage.ForPerson, what string) {

	for _, one := range withdrawn {
		core.Tell(ctx, in, "could not say that an agreement was withdrawn", notify.Telling{
			PersonID: one.PersonID, Kind: notify.ApprovalWithdrawn,
			Body: what + " of a claim you agreed to was changed, so your agreement no " +
				"longer counts. It is back in the review queue.",
			Link:    weblink.Claim(claimID),
			Private: one.Undisclosed,
			// The narrowing a later read applies.
			ProductID:       &one.ProductID,
			VulnerabilityID: &one.VulnerabilityID,
		}, "person", one.PersonID, "claim", claimID)
	}
}
