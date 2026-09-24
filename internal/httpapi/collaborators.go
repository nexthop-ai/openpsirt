// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// CollaboratorBody is one person brought into one case.
type CollaboratorBody struct {
	Identity    string `json:"identity"`
	Name        string `json:"name,omitempty" doc:"Their display name, where it differs from their identity"`
	AddedBy     string `json:"added_by" doc:"The person who brought them in, by sign-in identity"`
	AddedByName string `json:"added_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	AddedAt     string `json:"added_at"`
}

// registerCollaborators is the list of people brought into one undisclosed
// case.
//
// The grant is on the pair of product and issue. A collaborator sees that
// issue everywhere it sits in that product and nothing else — not the rest of
// the embargo list, and not a count of it. The case it exists for is the
// engineer who normally sees only public findings and is needed on one
// embargoed flaw in their own component.
//
// Anybody holding private triage on the product manages the list, rather
// than an administrator: knowing who needs to be on a case is knowing the case,
// and routing that through somebody who does not read it would make the
// administrator the bottleneck on every embargo.
func registerCollaborators(api huma.API, in Ingest, a Administering) {
	const path = "/v1/products/{product}/issues/{vulnerability}/collaborators"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-collaborators", Method: http.MethodGet, Path: path,
		Summary: "List who has been brought into a case",
		Description: "Everybody granted this one issue in this product, oldest first.\n\n" +
			"Being on a case is not reading the product. A collaborator sees this issue " +
			"wherever it sits here and nothing else, may argue about it and comment on it, " +
			"and may not agree to anybody's claim.",
		Tags: []string{"Findings"},
	}, perProduct, "Only where you may read undisclosed work.", privateRights()...),
		func(ctx context.Context, input *struct {
			Product       string `path:"product"`
			Vulnerability string `path:"vulnerability"`
		}) (*listOutput[CollaboratorBody], error) {
			subject, _, product, issue, err := caseAt(ctx, in, input.Product, input.Vulnerability)
			if err != nil {
				return nil, err
			}
			if !subject.Reads(access.Private, product) {
				return nil, noSuchFinding()
			}
			people, err := access.NewStore(in.DB.DB).OnCase(ctx, product, issue)
			if err != nil {
				return nil, wentWrong(in.Logger, "who is on this case could not be read", err)
			}
			body, err := collaboratorBodies(ctx, in, product, issue, people)
			if err != nil {
				return nil, wentWrong(in.Logger, "who is on this case could not be read", err)
			}
			out := &listOutput[CollaboratorBody]{}
			out.Body.Items = body
			return out, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-collaborator", Method: http.MethodPut,
		Path:    path + "/{identity}",
		Summary: "Bring somebody into a case",
		Description: "Grants one person this one issue in this product, without granting them " +
			"private reading on the product.\n\n" +
			"It is an access change and is recorded as one: it lands in the " +
			"administration trail, and they are told at once — in the notification area " +
			"inside the application, where an undisclosed finding may be named.\n\n" +
			"They must already have been recorded here: this grants access to somebody who " +
			"has some, and cannot bring anybody into the deployment.\n\n" +
			"Adding somebody who is already on the case succeeds and changes nothing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "Only where you may read undisclosed work.", privateRights()...),
		func(ctx context.Context, input *struct {
			Product       string `path:"product"`
			Vulnerability string `path:"vulnerability"`
			Identity      string `path:"identity"`
		}) (*struct{}, error) {
			subject, _, product, issue, err := caseAt(ctx, in, input.Product, input.Vulnerability)
			if err != nil {
				return nil, err
			}
			if !subject.Reads(access.Private, product) {
				return nil, noSuchFinding()
			}
			named, issued, err := namedCase(ctx, in, product, issue)
			if err != nil {
				return nil, err
			}
			about := named + " · " + issued
			var person *access.Account
			if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
				rights := access.NewStore(tx)
				var err error
				if person, err = rights.ByIdentity(ctx, input.Identity); err != nil {
					return noSuchPerson()
				}
				if err := rights.AddToCase(ctx, product, issue, person.ID, subject.ID); err != nil {
					return wentWrong(in.Logger, "they could not be brought in", err)
				}
				if err := noted(ctx, tx, trail.Case,
					about+" · "+person.Identity,
					nil, trail.Said("a collaborator", true)); err != nil {
					return notRecorded(a.Logger, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			// Told at once, and told what it is about. Nothing
			// leaving this deployment carries detail about an
			// undisclosed finding; the area inside it is where
			// one may be named, and a message saying "you were
			// given access to something" without saying to what
			// is unactionable.
			tell(ctx, in, "could not say that somebody was brought into a case", notify.Telling{
				PersonID: person.ID, Kind: notify.BroughtIn,
				Body: "You have been brought into " + input.Vulnerability + " in " +
					input.Product + ". You can read and argue about that issue there, " +
					"and nothing else of that product.",
				Link:    "/products/" + input.Product + "/findings?q=" + input.Vulnerability,
				Private: true,
				// The pair the case grant itself is, so the
				// person being brought in can read the line
				// saying so: they hold nothing on the product,
				// and the grant is what reaches this issue.
				ProductID:       &product,
				VulnerabilityID: &issue,
			}, "person", person.Identity)
			return &struct{}{}, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "remove-collaborator", Method: http.MethodDelete,
		Path:    path + "/{identity}",
		Summary: "Take somebody off a case",
		Description: "Withdraws the grant. The record of it is kept, because who could see " +
			"an embargoed case, and when, is exactly what is asked afterwards.\n\n" +
			"Taking somebody off a case they are not on succeeds and changes nothing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "Only where you may read undisclosed work.", privateRights()...),
		func(ctx context.Context, input *struct {
			Product       string `path:"product"`
			Vulnerability string `path:"vulnerability"`
			Identity      string `path:"identity"`
		}) (*struct{}, error) {
			subject, _, product, issue, err := caseAt(ctx, in, input.Product, input.Vulnerability)
			if err != nil {
				return nil, err
			}
			if !subject.Reads(access.Private, product) {
				return nil, noSuchFinding()
			}
			named, issued, err := namedCase(ctx, in, product, issue)
			if err != nil {
				return nil, err
			}
			about := named + " · " + issued
			if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
				rights := access.NewStore(tx)
				person, err := rights.ByIdentity(ctx, input.Identity)
				if err != nil {
					return noSuchPerson()
				}
				if err := rights.RemoveFromCase(ctx, product, issue, person.ID, subject.ID); err != nil {
					return wentWrong(in.Logger, "they could not be taken off", err)
				}
				if err := noted(ctx, tx, trail.Case,
					about+" · "+person.Identity,
					trail.Said("a collaborator", true), nil); err != nil {
					return notRecorded(a.Logger, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			return &struct{}{}, nil
		})
}

// collaboratorBodies names the people on a case.
func collaboratorBodies(ctx context.Context, in Ingest, productID, issueID int64,
	people []int64) ([]CollaboratorBody, error) {

	out := make([]CollaboratorBody, 0, len(people))
	if len(people) == 0 {
		return out, nil
	}
	rights := access.NewStore(in.DB.DB)
	// Both halves. The identity is what the removal route resolves, and the
	// display name is what a screen shows — one field each, because a list
	// that published the label where the handle belongs is a grant on an
	// embargoed case that the API can show and cannot withdraw.
	handles, err := rights.Handles(ctx, people)
	if err != nil {
		return nil, err
	}
	names, err := rights.Names(ctx, people)
	if err != nil {
		return nil, err
	}
	rows, err := rights.CaseRows(ctx, productID, issueID)
	if err != nil {
		return nil, err
	}
	added := map[int64]access.Collaborator{}
	for _, row := range rows {
		added[row.PersonID] = row
	}
	adders := make([]int64, 0, len(rows))
	for _, row := range rows {
		adders = append(adders, row.AddedBy)
	}
	by, err := whoSigned(ctx, in.DB.DB, adders)
	if err != nil {
		return nil, err
	}
	for _, id := range people {
		// A person the grant reports and the rows do not is left out rather
		// than published with a zero time: "0001-01-01" is not a date anybody
		// should read as when somebody was brought into a case.
		row, recorded := added[id]
		if !recorded {
			continue
		}
		body := CollaboratorBody{
			Identity: handles[id], AddedBy: by.identity(row.AddedBy),
			AddedByName: by.label(row.AddedBy),
			AddedAt:     row.AddedAt.Format(time.RFC3339),
		}
		body.Name = labelBeside(names[id], handles[id])
		out = append(out, body)
	}
	return out, nil
}

// caseAt resolves a product and an issue for the collaborator endpoints, and
// answers "no such finding" for anything the caller may not reach.
func caseAt(ctx context.Context, in Ingest, product, vulnerability string) (
	access.Subject, *access.Store, int64, int64, error) {

	return caseAtHolding(ctx, in, product, vulnerability, false)
}

// namedCase is the subject of a case, as the record writes it: the names the
// two identifiers resolve to rather than the ones the caller typed.
//
// A typed name is unbounded and a stored one is not. A path segment
// carries no length on any route here, and an issue is looked up through a
// normalization that keeps the first 191 runes — so a seven-hundred-character
// name whose head is a real identifier resolves, and composing the record from
// it writes seven hundred characters into a column sized for three names. The
// row it resolved to is the thing the record is about anyway.
func namedCase(ctx context.Context, in Ingest, productID, issueID int64) (string, string, error) {
	product, err := catalog.NewStore(in.DB.DB).ProductByID(ctx, productID)
	if err != nil {
		return "", "", wentWrong(in.Logger, "that product could not be looked up", err)
	}
	issues, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, []int64{issueID})
	if err != nil {
		return "", "", wentWrong(in.Logger, "that issue could not be looked up", err)
	}
	return product.Name, issues[issueID], nil
}

// caseAtTriaging is the same, for the routes that ask for the right to argue
// about findings rather than only to read them.
//
// Named separately because the difference is not cosmetic: a route that
// declares triage and enforces a read role has the annotation on the
// operation and the check in the handler saying different things — and the
// annotation is what the generated reference tells an operator the rule is.
func caseAtTriaging(ctx context.Context, in Ingest, product, vulnerability string) (
	access.Subject, *access.Store, int64, int64, error) {

	return caseAtHolding(ctx, in, product, vulnerability, true)
}

func caseAtHolding(ctx context.Context, in Ingest, product, vulnerability string,
	triaging bool) (access.Subject, *access.Store, int64, int64, error) {

	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, nil, 0, 0, err
	}
	if in.DB == nil {
		return access.Subject{}, nil, 0, 0,
			noDatabase(in.Logger)
	}
	// A route about one named issue, so the wider of the two rules: somebody
	// brought into a case here holds nothing on the product and is still
	// answering about the one issue they were granted. Their reach over it is
	// decided below, by the issue rather than by the product.
	named, err := productForIssue(ctx, in, subject, product)
	if err != nil {
		return access.Subject{}, nil, 0, 0, err
	}
	if triaging && !subject.TriagesIn(named.ID) {
		// Asked before the name is resolved further, so a refusal says
		// nothing about whether the issue is here.
		return access.Subject{}, nil, 0, 0,
			huma.Error403Forbidden("not authorized")
	}
	issueID, err := issueHere(ctx, in, subject, named.ID, vulnerability)
	if err != nil {
		return access.Subject{}, nil, 0, 0, err
	}
	return subject, access.NewStore(in.DB.DB), named.ID, issueID, nil
}
