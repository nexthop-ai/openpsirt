// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
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

func registerAssignMatching(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "assign-matching-findings", Method: http.MethodPost,
		Path:    "/v1/products/{product}/findings/assignment",
		Summary: "Assign every finding a filter matches",
		Description: "Assigns every row the findings list returns for the same parameters, " +
			"across all of its pages, in one request. Takes the same filters as " +
			"`GET /v1/products/{product}/findings`.\n\n" +
			"Each row is assigned the way one finding is: across every build of the product, " +
			"at every package the row folds together. Send `person` as an empty string to " +
			"hand the rows back to nobody, or `team` to route them to a team.\n\n" +
			"`only` limits the act to rows somebody picked from the list. A picked row the " +
			"filter no longer matches is not assigned; `pieces` says how many were.\n\n" +
			"Without the assigner right you may take what nobody holds and hand back your own. " +
			"Rows somebody else holds are left with them, and `moved` counts only what changed " +
			"hands.\n\n" +
			"Refused as a whole where any row has not been disclosed and the person or team " +
			"may not read undisclosed work in the product.",
		Tags: []string{"Findings"},
	}, perProduct, "Giving work to somebody else also needs assigner. Taking unowned work, "+
		"or handing back your own, does not.", triageRights()...), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant string `query:"variant" doc:"Limit to one variant. Left out, every one under the product"`
		AtOneBuild
		Narrowing
		Body struct {
			Person string      `json:"person,omitempty" doc:"Their sign-in identity, or empty for nobody"`
			Team   string      `json:"team,omitempty" doc:"A team to route the rows to instead, by name"`
			Only   []PieceBody `json:"only,omitempty" minItems:"1" maxItems:"2000" doc:"The rows picked from the list. Left out, every row the filter matches; an empty list is refused"`
		}
	}) (*struct{ Body AssignedMatchingBody }, error) {
		at, err := narrowing(ctx, in, ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
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
		if err := mayHandOver(subject, product, input.Body.Person, input.Body.Team); err != nil {
			return nil, err
		}

		only, err := piecesNamed(ctx, in, subject, product, input.Body.Only)
		if err != nil {
			return nil, err
		}

		rights := access.NewStore(in.DB.DB)
		var to *int64
		var whoToTell int64
		var admits finding.Admits
		switch {
		case input.Body.Person != "":
			person, err := rights.ByIdentity(ctx, input.Body.Person)
			if err != nil {
				return nil, absent(in.Logger, err, "that person could not be looked up", noSuchPerson)
			}
			party := person.PartyID
			to, whoToTell = &party, person.ID
			admits = func(ctx context.Context, db bun.IDB, strictest access.Visibility) error {
				if strictest != access.Private {
					return nil
				}
				reads, err := access.NewStore(db).PersonReads(ctx, person.ID, product, strictest)
				if err != nil {
					return err
				}
				if !reads {
					return errRecipient{huma.Error422UnprocessableEntity(
						"some of this has not been disclosed and they may not read " +
							"undisclosed work here, so handing it to them would be the disclosure")}
				}
				return nil
			}
		case input.Body.Team != "":
			team, err := rights.TeamByName(ctx, input.Body.Team)
			if err != nil {
				return nil, absent(in.Logger, err, "that team could not be looked up",
					func() error { return noSuchTeamNamed(input.Body.Team) })
			}
			party := team.PartyID
			to = &party
			admits = func(ctx context.Context, db bun.IDB, strictest access.Visibility) error {
				reads, err := teamMayHold(ctx, access.NewStore(db), team.ID, product, strictest)
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

		handed, err := at.Store.AssignMatching(ctx, subject, at.Scope, at.Filter, only, to, admits)
		if err != nil {
			var recipient errRecipient
			if errors.As(err, &recipient) {
				return nil, recipient.answer
			}
			return nil, refused(in.Logger, err, "cannot record who is dealing with this")
		}

		// One notification for the act rather than one per row: a selection
		// of two thousand is one thing that happened to the person receiving
		// it. Told only where they may see all of it, for the reason the
		// single assignment gives, and never for handing back.
		arrived := handed.Pieces - len(handed.Left)
		if to != nil && *to != subject.Party() && whoToTell != 0 && arrived > 0 &&
			seenBy(ctx, in, input.Body.Person, product, handed.Undisclosed) {
			tell(ctx, in, "could not say that work was assigned", notify.Telling{
				PersonID: whoToTell, Kind: notify.Assigned,
				Body: piecesOfWork(arrived) + " in " + input.Product,
				Link: "/work", Private: handed.Undisclosed, ProductID: &product,
			}, "person", whoToTell)
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
// Resolved the way a bulk claim's names are. A name nothing is filed under is
// refused by name, because a person who picked it from a list wants to know
// which row went wrong rather than bisect the selection — and a name filed
// only where this person may not look is refused in the same words.
func piecesNamed(ctx context.Context, in Ingest, subject access.Subject, productID int64,
	picked []PieceBody) ([]finding.Piece, error) {

	if len(picked) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(picked))
	for _, each := range picked {
		names = append(names, each.Vulnerability)
	}
	found, unknown, err := issuesHere(ctx, in, subject, productID, names)
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
func pieceBodies(ctx context.Context, in Ingest, pieces []finding.Piece) ([]PieceBody, error) {
	if len(pieces) == 0 {
		return nil, nil
	}
	issues := make([]int64, 0, len(pieces))
	for _, each := range pieces {
		issues = append(issues, each.VulnerabilityID)
	}
	named, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, wentWrong(in.Logger, "what these issues are called could not be read", err)
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
