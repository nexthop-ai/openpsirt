// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// registerCodeFindingAssigning is giving a code finding to somebody and handing it back: the
// assignment a finding has, at the grain of a code finding.
func registerCodeFindingAssigning(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "assign-code-finding", Method: http.MethodPut,
		Path:    "/v1/products/{product}/branches-and-tags/{stream}/variants/{variant}/code-findings/{occurrence}/assignment",
		Summary: "Assign a code finding to somebody",
		Description: "Records who is dealing with this code finding.\n\n" +
			"It covers the product, not the build named in the path: what is assigned is the " +
			"code finding on every build of the product it is open on.\n\n" +
			"Send `person` as an empty string to hand it back to nobody. Send `team` instead to " +
			"assign it to a team, which is a queue rather than a holding: it stays unheld until " +
			"somebody takes it.\n\n" +
			"A person is given a code finding only where they may read it at its visibility, and a team " +
			"only where one member may. A code finding every release of which is past its end of life " +
			"is refused with 409, and so is a code finding recorded as a flaw: assign the flaw " +
			"instead.\n\n" +
			"A code finding seen on a build it was not open on when it was assigned starts unassigned there.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "At the code finding's visibility. Giving it to somebody else also needs "+
		"assigner. Taking a code finding nobody holds, or handing back your own, does not.",
		core.TriageRights()...), func(ctx context.Context, input *struct {
		Product    string `path:"product"`
		Stream     string `path:"stream"`
		Variant    string `path:"variant"`
		Occurrence string `path:"occurrence" doc:"The code finding's occurrence identity"`
		Body       struct {
			Person string `json:"person,omitempty" doc:"Their sign-in identity, or empty for nobody"`
			Team   string `json:"team,omitempty" doc:"A team to assign it to instead, by name. A queue rather than a holding: it stays unheld until somebody takes it"`
		}
	}) (*struct{}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, targetID, err := locateCodeFinding(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		if err := mayHandOver(subject, product, input.Body.Person, input.Body.Team); err != nil {
			return nil, err
		}

		var to *int64
		var whoToTell int64
		var admits finding.Admits
		rights := access.NewStore(in.DB.DB)
		switch {
		case input.Body.Person != "":
			person, err := core.PersonNamed(ctx, in.Logger, rights, input.Body.Person)
			if err != nil {
				return nil, err
			}
			party := person.PartyID
			to, whoToTell = &party, person.ID
			admits = personAdmits(person, product)
		case input.Body.Team != "":
			team, err := core.TeamNamed(ctx, in.Logger, rights, input.Body.Team)
			if err != nil {
				return nil, err
			}
			party := team.PartyID
			to = &party
			admits = teamAdmits(team, product)
		}

		findings := finding.NewStore(in.DB.DB)
		_, withheld, err := findings.AssignCodeFinding(ctx, subject, targetID, input.Occurrence, to, admits)
		switch {
		case errors.Is(err, finding.ErrCodeFindingPastEndOfLife), errors.Is(err, finding.ErrCodeFindingRecordedAsFlaw):
			return nil, huma.Error409Conflict(err.Error())
		case errors.Is(err, finding.ErrNothingOpenThere):
			return nil, core.NoSuchFinding()
		case err != nil:
			return nil, recipient(err, func(err error) error { return core.RefusedFinding(in, err) })
		}

		// Told on the terms a finding's assignment is: to a person and never
		// a team, never for handing back, and only where they read the code finding
		// at every visibility it holds. The line is internal work, so it is
		// withheld as such, and nothing leaving the deployment names the code finding.
		if to == nil || *to == subject.Party() || !seenBy(ctx, in, input.Body.Person, product, withheld) {
			return &struct{}{}, nil
		}
		codeFinding, err := findings.CodeFindingAt(ctx, subject, targetID, input.Occurrence)
		if err != nil {
			in.Log().ErrorContext(ctx, "could not say that a code finding was assigned", "error", err)
			return &struct{}{}, nil
		}
		said := "A code finding"
		if evidence, err := analysis.EvidenceOf(ctx, in.DB.DB, subject, codeFinding, product); err == nil {
			said = evidence.Rule
			if evidence.At.Path != "" {
				said += " at " + evidence.At.Path
				if evidence.At.StartLine > 0 {
					said += fmt.Sprintf(":%d", evidence.At.StartLine)
				}
			}
		} else {
			in.Log().ErrorContext(ctx, "could not say which code finding was assigned", "error", err)
		}
		private, internal := notify.Withholding(withheld)
		core.Tell(ctx, in, "could not say that a code finding was assigned", notify.Telling{
			PersonID: whoToTell, Kind: notify.Assigned,
			Body: said + ", in " + input.Product + " " + input.Stream + " " + input.Variant,
			Link: weblink.CodeFinding(input.Product, input.Stream, input.Variant, input.Occurrence),
			// Withheld at every visibility it holds, so a read narrows the
			// line by the grant the code finding is read under, and a role lost is a
			// line no longer read.
			Private: private, Internal: internal,
			ProductID:       &product,
			VulnerabilityID: &codeFinding.VulnerabilityID,
		}, "person", whoToTell)
		return &struct{}{}, nil
	})
}

// locateCodeFinding is the product and the build a code finding's address names, resolved
// only for somebody who triages the product at some visibility. A case
// collaborator resolves the address and triages nothing, so the product
// reaches no check that carries no subject on their behalf. Authorized before
// any recipient's name is looked up, for the reason the finding's assignment
// gives: resolving first answers whether a person has an account here to
// anybody who may read the product.
func locateCodeFinding(ctx context.Context, in core.Deps, subject access.Subject,
	product, stream, variant string) (int64, int64, error) {

	named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return 0, 0, err
	}
	if !triagesAny(subject, named.ProductID) {
		return 0, 0, core.NoSuchFinding()
	}
	target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return 0, 0, err
	}
	return named.ProductID, target.ID, nil
}

// triagesAny reports whether a subject triages a product at any visibility: a
// code finding is triaged at internal visibility, and a code finding included in its flaw's disclosure at the
// case's.
func triagesAny(subject access.Subject, productID int64) bool {
	for _, v := range access.Visibilities() {
		if subject.Triages(v, productID) {
			return true
		}
	}
	return false
}
