// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// PieceBody names one row of the findings list: an issue at a fold.
type PieceBody struct {
	Vulnerability string `json:"vulnerability" minLength:"1" maxLength:"191" doc:"The issue, by any name it is known under"`
	Fold          string `json:"fold" minLength:"1" maxLength:"512" doc:"The row's fold, as the findings list gives it"`
}

// AssignedMatchingBody is what one assignment over a narrowing did.
type AssignedMatchingBody struct {
	Pieces int   `json:"pieces" doc:"The number of rows of the list this reached"`
	Moved  int64 `json:"moved" doc:"The number of findings that changed hands, across every build of the product. Work somebody else holds stays with them unless you may give work away"`
	// Left is the rows that stayed, so a screen can keep them selected.
	Left []PieceBody `json:"left,omitempty" doc:"The rows that did not wholly move, because somebody else holds part of them and you may not take it"`
}

// errRecipient carries a refusal about who work is going to out of the
// transaction, so it reaches the caller in its own words.
type errRecipient struct{ answer error }

func (e errRecipient) Error() string { return e.answer.Error() }

// recipient answers err in the words a refused recipient carries, and anything
// else as otherwise does.
func recipient(err error, otherwise func(error) error) error {
	var refused errRecipient
	if errors.As(err, &refused) {
		return refused.answer
	}
	return otherwise(err)
}

// personAdmits refuses handing a person work they could not open once they held
// it, asked through the transaction that hands the work over.
//
// Somebody who holds no role in the product, or has left, is refused whatever
// the work's visibility: disclosed work travels with its assignment only to
// somebody who holds a role there, which is the rule a hand-back keeps it by,
// and anything handed to somebody refused at sign-in sits in no list. Each
// visibility other than public the work holds is then asked about, because
// each is its own grant and handing over what they may not read would be the
// disclosure.
func personAdmits(person *access.Account, productID int64) finding.Admits {
	return func(ctx context.Context, db bun.IDB, withheld []access.Visibility) error {
		holds, err := access.NewStore(db).PersonHolds(ctx, person.ID, productID)
		if err != nil {
			return err
		}
		if len(holds) == 0 {
			return errRecipient{huma.Error422UnprocessableEntity(
				"they hold no role in this product, so the work would sit with somebody who cannot open it")}
		}
		for _, v := range withheld {
			reads := slices.Contains(holds, v)
			if !reads && v == access.SecurityTesting {
				return errRecipient{huma.Error422UnprocessableEntity(
					"some of this is at security testing visibility and they may not read security testing work here, " +
						"so handing it to them would show it to them")}
			}
			if !reads {
				return errRecipient{huma.Error422UnprocessableEntity(
					"some of this has not been disclosed and they may not read " +
						"undisclosed work here, so handing it to them would be the disclosure")}
			}
		}
		return nil
	}
}

// teamAdmits refuses assigning work to a team none of whose members may read it,
// where it would sit in a queue nobody on it can see.
func teamAdmits(team *access.Team, productID int64) finding.Admits {
	return func(ctx context.Context, db bun.IDB, withheld []access.Visibility) error {
		reads, err := teamMayHold(ctx, access.NewStore(db), team.ID, productID, withheld)
		if err != nil {
			return err
		}
		if !reads {
			return errRecipient{huma.Error422UnprocessableEntity(
				"nobody on " + team.Called() + " may read this, so it would sit in a " +
					"queue none of them can see")}
		}
		return nil
	}
}

// receiver is who work is given to: the party it lands on, the person told
// of it, and what the party is asked inside the write that moves it. The zero
// receiver is nobody, which is how work is handed back.
type receiver struct {
	to *int64
	// tell is the person to tell, and zero for a team: a queue filling up is
	// digest content rather than an interruption.
	tell int64
	// identity is the person's, read back as them to ask what they may see.
	identity string
	admits   finding.Admits
}

// receiverOf resolves the person or team a request names as the receiver of
// work in a product.
//
// The right to hand work over is asked before either name is looked up:
// resolving first answers whether an account exists differently for a held
// and an unheld name, which is a directory of the organization for the price
// of one request (REQ-42).
func receiverOf(ctx context.Context, in core.Deps, subject access.Subject, productID int64,
	person, team string) (receiver, error) {

	if err := mayHandOver(subject, productID, person, team); err != nil {
		return receiver{}, err
	}
	rights := access.NewStore(in.DB.DB)
	switch {
	case person != "":
		who, err := core.PersonNamed(ctx, in.Logger, rights, person)
		if err != nil {
			return receiver{}, err
		}
		party := who.PartyID
		return receiver{to: &party, tell: who.ID, identity: who.Identity,
			admits: personAdmits(who, productID)}, nil
	case team != "":
		found, err := core.TeamNamed(ctx, in.Logger, rights, team)
		if err != nil {
			return receiver{}, err
		}
		party := found.PartyID
		return receiver{to: &party, admits: teamAdmits(found, productID)}, nil
	}
	return receiver{}, nil
}

// told reports whether the receiver is told the work arrived: a person, never
// a team, never somebody assigning to themselves, never for handing back, and
// only where they read the work at every visibility it holds (seenBy).
func (r receiver) told(ctx context.Context, in core.Deps, subject access.Subject, productID int64,
	withheld []access.Visibility) bool {

	if r.to == nil || r.tell == 0 || *r.to == subject.Party() {
		return false
	}
	return seenBy(ctx, in, r.identity, productID, withheld)
}

func registerAssignMatching(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "assign-matching-findings", Method: http.MethodPost,
		Path:    "/v1/products/{product}/findings/assignment",
		Summary: "Assign every finding a filter matches",
		Description: "Assigns every row the findings list returns for the same parameters, " +
			"across all of its pages, in one request. Takes the same filters as " +
			"`GET /v1/products/{product}/findings`.\n\n" +
			"Each row is assigned the way one finding is: across every build of the product, " +
			"at every package the row folds together. Send `person` as an empty string to " +
			"hand the rows back to nobody, or `team` to assign them to a team.\n\n" +
			"`only` limits the act to rows somebody picked from the list. A picked row the " +
			"filter no longer matches is not assigned; `pieces` says how many were.\n\n" +
			"Without the assigner right you may take what nobody holds and hand back your own. " +
			"Rows somebody else holds are left with them, and `moved` counts only what changed " +
			"hands.\n\n" +
			"Refused as a whole where the person holds no role in the product or has been " +
			"deactivated, or where any row has not been disclosed and the person or team may " +
			"not read undisclosed work in the product.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "Giving work to somebody else also needs assigner. Taking unowned work, "+
		"or handing back your own, does not.", core.TriageRights()...), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		BranchOrTag string `query:"branch_or_tag" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant     string `query:"variant" doc:"Limit to one variant. Left out, every one under the product"`
		core.AtOneBuild
		core.Narrowing
		Body struct {
			Person string      `json:"person,omitempty" doc:"Their sign-in identity, or empty for nobody"`
			Team   string      `json:"team,omitempty" doc:"A team to route the rows to instead, by name"`
			Only   []PieceBody `json:"only,omitempty" minItems:"1" maxItems:"2000" doc:"The rows picked from the list. Left out, every row the filter matches; an empty list is refused"`
		}
	}) (*struct{ Body AssignedMatchingBody }, error) {
		in := core.Of(ctx, in)
		at, err := core.ListNarrowed(ctx, in, core.ScopeQuery{
			Product: input.Product, BranchOrTag: input.BranchOrTag, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "cannot tell what is worth triaging here")
		if err != nil {
			return nil, err
		}
		subject, product := at.Subject, *at.Scope.ProductID

		// Every right this needs, asked before any name in the body is
		// looked up, for the reason the single assignment gives: resolving
		// first answers whether an account exists to anybody who may read.
		if !subject.TriagesIn(product) {
			return nil, huma.Error403Forbidden("not authorized")
		}
		to, err := receiverOf(ctx, in, subject, product, input.Body.Person, input.Body.Team)
		if err != nil {
			return nil, err
		}

		only, err := piecesNamed(ctx, in, subject, product, input.Body.Only)
		if err != nil {
			return nil, err
		}

		handed, err := at.Store.AssignMatching(ctx, subject, at.Scope, at.Filter, only, to.to, to.admits)
		if err != nil {
			return nil, recipient(err, func(err error) error {
				return core.Refused(in.Logger, err, "cannot record who is dealing with this")
			})
		}

		// One notification for the act rather than one per row: a selection
		// of two thousand is one thing that happened to the person receiving
		// it. Told only where they may see all of it, for the reason the
		// single assignment gives, and never for handing back.
		arrived := handed.Pieces - len(handed.Left)
		if arrived > 0 && to.told(ctx, in, subject, product, handed.Withheld) {
			private, securityTesting := notify.Withholding(handed.Withheld)
			core.Tell(ctx, in, "could not say that work was assigned", notify.Telling{
				PersonID: to.tell, Kind: notify.Assigned,
				Body: piecesOfWork(arrived) + " in " + input.Product,
				Link: weblink.Assignments(), Private: private, SecurityTesting: securityTesting,
				ProductID: &product,
			}, "person", to.tell)
		}
		left, err := pieceBodies(ctx, in, handed.Left)
		if err != nil {
			return nil, err
		}
		return &struct{ Body AssignedMatchingBody }{Body: AssignedMatchingBody{
			Pieces: handed.Pieces, Moved: handed.Moved, Left: left,
		}}, nil
	})
}

// piecesNamed resolves the rows somebody picked to the issues they name.
//
// Resolved the way a bulk decision's names are. A name nothing is filed under is
// refused by name, because a person who picked it from a list wants to know
// which row went wrong rather than bisect the selection — and a name filed
// only where this person may not look is refused in the same words.
func piecesNamed(ctx context.Context, in core.Deps, subject access.Subject, productID int64,
	picked []PieceBody) ([]finding.Piece, error) {

	if len(picked) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(picked))
	for _, each := range picked {
		names = append(names, each.Vulnerability)
	}
	found, unknown, err := core.IssuesHere(ctx, in, subject, productID, names)
	if err != nil {
		return nil, err
	}
	out := make([]finding.Piece, 0, len(picked))
	for _, each := range picked {
		if id, ok := found[each.Vulnerability]; ok {
			out = append(out, finding.Piece{VulnerabilityID: id, Fold: each.Fold})
		}
	}
	if len(unknown) > 0 {
		return nil, huma.Error404NotFound(
			"no issue is filed under " + strings.Join(clipped(unknown), ", "))
	}
	return out, nil
}

// pieceBodies names pieces by their issues' names.
func pieceBodies(ctx context.Context, in core.Deps, pieces []finding.Piece) ([]PieceBody, error) {
	if len(pieces) == 0 {
		return nil, nil
	}
	issues := make([]int64, 0, len(pieces))
	for _, each := range pieces {
		issues = append(issues, each.VulnerabilityID)
	}
	named, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, core.WentWrong(in.Logger, "what these issues are called could not be read", err)
	}
	out := make([]PieceBody, 0, len(pieces))
	for _, each := range pieces {
		out = append(out, PieceBody{Vulnerability: named[each.VulnerabilityID], Fold: each.Fold})
	}
	return out, nil
}

// piecesOfWork says how many pieces of work, in words a notification reads.
func piecesOfWork(n int) string {
	if n == 1 {
		return "1 piece of work"
	}
	return strconv.Itoa(n) + " pieces of work"
}
