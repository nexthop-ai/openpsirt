// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// LeadBuild is one build a hand-off names.
type LeadBuild struct {
	Stream  string `json:"stream" minLength:"1" doc:"A branch or a tag"`
	Variant string `json:"variant" minLength:"1" doc:"The way that line is built"`
}

// HandoffSource is where a suggested component came from.
type HandoffSource string

// Schema answers with the sources a suggestion comes from.
func (HandoffSource) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.Sources()))
	for _, each := range analysis.Sources() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// SuggestionBody is one component offered at hand-off.
type SuggestionBody struct {
	Component  string        `json:"component,omitempty" doc:"The component, as the builds name it. Absent for the build itself"`
	Ecosystem  string        `json:"ecosystem,omitempty" doc:"Its ecosystem, where its package identifier states one"`
	Namespace  string        `json:"namespace,omitempty" doc:"Its namespace, where its package identifier states one"`
	From       HandoffSource `json:"from" doc:"Where the suggestion came from: a prefix confirmed at an earlier hand-off, the component the lead was placed on, a component whose name resembles the lead's directory, or the build itself"`
	Lacking    []LeadBuild   `json:"lacking" doc:"The builds the lead was seen in that hold no such component. Recording the flaw against them is refused"`
	Unanalyzed []LeadBuild   `json:"unanalyzed" doc:"The builds holding the component that the lead's series never analyzed"`
}

// AuthorBody is one person who wrote about a lead.
type AuthorBody struct {
	Identity string `json:"identity"`
	Name     string `json:"name,omitempty" doc:"Their display name, where it differs from their identity"`
	Writings int    `json:"writings" doc:"The number of revisions of reasoning and comments they wrote on claims about the lead"`
}

// DisclosesBody is what moving a lead into its flaw's case discloses with the
// flaw.
type DisclosesBody struct {
	Authors  []AuthorBody `json:"authors" doc:"Everybody who wrote reasoning or a comment on a claim about the lead"`
	Paths    []string     `json:"paths" doc:"Every path the lead names"`
	Messages int          `json:"messages" doc:"The number of messages the analyzer wrote at those paths"`
	Snippets int          `json:"snippets" doc:"The number of source snippets disclosed with the flaw"`
	Stripped int          `json:"stripped" doc:"The number of source snippets removed at disclosure, under paths the product does not disclose snippets for"`
}

// HandoffOfferBody is what a hand-off of one lead is offered.
type HandoffOfferBody struct {
	Rule        string           `json:"rule" doc:"The analyzer's rule, as <tool>/<rule>"`
	Seen        []LeadBuild      `json:"seen" doc:"Every build the lead was seen in, which the flaw is proposed against"`
	Suggestions []SuggestionBody `json:"suggestions" doc:"The components offered, most likely first. The build itself is always last"`
	Prefix      string           `json:"prefix,omitempty" doc:"The path a confirmed component is remembered for: the repository the lead is in, or its directory"`
	Discloses   DisclosesBody    `json:"discloses" doc:"What moving the lead into the flaw's case discloses when the flaw is disclosed"`
}

// HandedOffBody is the record of a lead handed off.
type HandedOffBody struct {
	Identifier string `json:"identifier" doc:"The identifier the flaw was filed under"`
	Component  string `json:"component" doc:"The component in the build that carries it"`
	Builds     int    `json:"builds" doc:"The number of builds it was recorded against"`
	Places     int    `json:"places" doc:"The number of findings of the flaw that opened"`
	Moved      bool   `json:"moved" doc:"Whether the lead moved into the flaw's case"`
}

// leadPath is one lead, addressed by its place on one build.
const leadPath = "/v1/products/{product}/streams/{stream}/variants/{variant}/leads/{place}"

// leadAt is the reader, the build and the product a route about one lead
// names.
type leadAt struct {
	subject access.Subject
	named   *catalog.Named
	target  int64
}

// locateLead resolves the build a lead route names.
func locateLead(ctx context.Context, in core.Deps, product, stream, variant string) (*leadAt, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return nil, err
	}
	named, err := core.LocatedVisibly(ctx, in, subject, product, stream, variant)
	if err != nil {
		return nil, err
	}
	target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
	if err != nil {
		return nil, err
	}
	return &leadAt{subject: subject, named: named, target: target.ID}, nil
}

// refusedHandoff is the answer to a hand-off, a move or an undo the store
// turned away.
func refusedHandoff(in core.Deps, err error) error {
	switch {
	case errors.Is(err, finding.ErrNoOpenFinding):
		return core.NoSuchFinding()
	case errors.Is(err, access.ErrDenied):
		return huma.Error403Forbidden("not authorized")
	case errors.Is(err, analysis.ErrHandedOff), errors.Is(err, analysis.ErrNotConfirmed),
		errors.Is(err, analysis.ErrAlreadyMoved), errors.Is(err, analysis.ErrNotMoved),
		errors.Is(err, analysis.ErrFlawDisclosed), errors.Is(err, analysis.ErrNotHandedOff):
		return huma.Error409Conflict(err.Error())
	}
	return refusedFlaw(in, err)
}

func registerHandoff(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-lead-handoff", Method: http.MethodGet, Path: leadPath + "/hand-off",
		Summary: "Get what a lead's hand-off is offered",
		Description: "Returns what recording a confirmed lead as a flaw here is offered: the " +
			"components it may be recorded against, most likely first, the builds it was seen in, " +
			"and what moving it into the flaw's case would disclose with the flaw.\n\n" +
			"A suggestion lists the builds the lead was seen in that lack it, since recording the " +
			"flaw against those is refused, and the builds holding it that the lead's series never " +
			"analyzed.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
	}) (*struct{ Body HandoffOfferBody }, error) {
		at, err := locateLead(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		offer, err := analysis.Propose(ctx, in.DB.DB, at.subject, at.named.ProductID, input.Place)
		if err != nil {
			return nil, refusedHandoff(in, err)
		}
		discloses, err := disclosesBody(ctx, in, offer.Discloses)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "who wrote about the lead could not be read", err)
		}
		body := HandoffOfferBody{
			Rule: offer.Rule, Seen: leadBuilds(offer.Seen), Prefix: offer.Prefix,
			Suggestions: make([]SuggestionBody, 0, len(offer.Suggestions)), Discloses: discloses,
		}
		for _, s := range offer.Suggestions {
			body.Suggestions = append(body.Suggestions, SuggestionBody{
				Component: s.Component, Ecosystem: s.Ecosystem, Namespace: s.Namespace,
				From: HandoffSource(s.From), Lacking: leadBuilds(s.Lacking), Unanalyzed: leadBuilds(s.Unanalyzed),
			})
		}
		return &struct{ Body HandoffOfferBody }{Body: body}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "hand-off-lead", Method: http.MethodPost, Path: leadPath + "/hand-off",
		Summary: "Hand off a confirmed lead as a flaw",
		Description: "Records a confirmed lead as a flaw in this product, found here and " +
			"undisclosed, through the same path as `POST /v1/products/{product}/findings`, and " +
			"links the lead to it.\n\n" +
			"`builds` is the whole set the flaw is recorded against. `component` names what " +
			"carries it, as the builds name it, and is remembered for the lead's prefix so the next " +
			"lead under it is offered the same; leave it out for the build itself.\n\n" +
			"`move` makes the lead part of the flaw's case: it becomes private, internal readers " +
			"keep only its state, rule, location and sightings, and it is disclosed with the flaw. " +
			"Left out, the lead is kept internal and linked.\n\n" +
			"A lead nobody confirmed, or one already handed off, is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
		Body    struct {
			Builds    []LeadBuild `json:"builds" minItems:"1" maxItems:"200" doc:"Every build the flaw is recorded against"`
			Component string      `json:"component,omitempty" doc:"The component that carries it. Omit for the build itself"`
			Ecosystem string      `json:"ecosystem,omitempty" doc:"The ecosystem, where two components share the name"`
			Namespace string      `json:"namespace,omitempty" doc:"The namespace, where two share a name and an ecosystem"`
			FlawFields
			Move bool `json:"move,omitempty" doc:"Whether the lead moves into the flaw's case. Kept internal by default"`
		}
	}) (*struct {
		Status int
		Body   HandedOffBody
	}, error) {
		at, err := locateLead(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		subject := at.subject
		// Before any build the body names is resolved, so a refusal says
		// nothing about which of them exist.
		if err := analysis.MayHandOff(subject, at.named.ProductID); err != nil {
			return nil, refusedHandoff(in, err)
		}
		names := catalog.NewStore(in.DB.DB)
		targets := make([]int64, 0, len(input.Body.Builds))
		for _, b := range input.Body.Builds {
			located, err := names.LocateVisible(ctx, subject, input.Product, b.Stream, b.Variant)
			if err != nil {
				return nil, core.Undeclared(in.Logger, err, "that build could not be looked up")
			}
			target, err := core.TargetRow(ctx, in, located.StreamID, located.VariantID)
			if err != nil {
				return nil, err
			}
			targets = append(targets, target.ID)
		}
		done, err := analysis.HandOff(ctx, in.DB.DB, subject, analysis.Handing{
			ProductID: at.named.ProductID, PlaceIdentity: input.Place, Move: input.Body.Move,
			Flaw: finding.Entering{
				TargetIDs: targets, Component: input.Body.Component,
				Ecosystem: input.Body.Ecosystem, Namespace: input.Body.Namespace,
				Summary: input.Body.Summary, Severity: string(input.Body.Severity),
				Vector: input.Body.Vector, Weaknesses: input.Body.Weaknesses,
			},
		})
		if err != nil {
			return nil, refusedHandoff(in, err)
		}
		return &struct {
			Status int
			Body   HandedOffBody
		}{Status: http.StatusCreated, Body: HandedOffBody{
			Identifier: done.Identifier, Component: done.Component,
			Builds: done.Builds, Places: done.Places, Moved: input.Body.Move,
		}}, nil
	})

	moving := func(move bool) func(context.Context, *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
	}) (*struct{}, error) {
		return func(ctx context.Context, input *struct {
			Product string `path:"product"`
			Stream  string `path:"stream"`
			Variant string `path:"variant"`
			Place   string `path:"place" doc:"The lead's place identity"`
		}) (*struct{}, error) {
			at, err := locateLead(ctx, in, input.Product, input.Stream, input.Variant)
			if err != nil {
				return nil, err
			}
			if move {
				err = analysis.Move(ctx, in.DB.DB, at.subject, at.named.ProductID, input.Place, time.Now())
			} else {
				err = analysis.Unmove(ctx, in.DB.DB, at.subject, at.named.ProductID, input.Place)
			}
			if err != nil {
				return nil, refusedHandoff(in, err)
			}
			return &struct{}{}, nil
		}
	}
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "move-lead", Method: http.MethodPut, Path: leadPath + "/move",
		Summary: "Move a handed-off lead into its flaw's case",
		Description: "Makes a kept lead part of its flaw's case: it becomes private, internal " +
			"readers keep only its state, rule, location and sightings, and it is disclosed with " +
			"the flaw. `GET .../hand-off` lists what that discloses.\n\n" +
			"Recorded in the administration trail. A lead not handed off, one already moved, or " +
			"one whose flaw is disclosed, is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), moving(true))
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "unmove-lead", Method: http.MethodDelete, Path: leadPath + "/move",
		Summary: "Take a lead back out of its flaw's case",
		Description: "Makes a moved lead internal again while its flaw is undisclosed, with the " +
			"claims about it. It stays linked to the flaw.\n\n" +
			"Recorded in the administration trail. A lead not handed off, a kept lead, or one whose " +
			"flaw is disclosed, is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), moving(false))
}

// leadBuilds is builds as an answer states them.
func leadBuilds(builds []analysis.BuildName) []LeadBuild {
	out := make([]LeadBuild, 0, len(builds))
	for _, b := range builds {
		out = append(out, LeadBuild{Stream: b.Stream, Variant: b.Variant})
	}
	return out
}

// disclosesBody names the authors of what a move discloses.
func disclosesBody(ctx context.Context, in core.Deps, d analysis.Disclosure) (DisclosesBody, error) {
	people := make([]int64, 0, len(d.Authors))
	for _, a := range d.Authors {
		people = append(people, a.PersonID)
	}
	who, err := core.WhoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return DisclosesBody{}, err
	}
	out := DisclosesBody{Authors: make([]AuthorBody, 0, len(d.Authors)), Paths: d.Paths,
		Messages: d.Messages, Snippets: d.Snippets, Stripped: d.Stripped}
	if out.Paths == nil {
		out.Paths = []string{}
	}
	for _, a := range d.Authors {
		out.Authors = append(out.Authors, AuthorBody{
			Identity: who.Identity(a.PersonID), Name: who.Label(a.PersonID), Writings: a.Writings,
		})
	}
	return out, nil
}

// LeadCollaboratorBody is one person granted a handed-off lead.
type LeadCollaboratorBody = CollaboratorBody

func registerLeadCollaborators(api huma.API, in core.Deps, a core.Administering) {
	const path = leadPath + "/collaborators"
	type leadInput = struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Place   string `path:"place" doc:"The lead's place identity"`
	}
	type personInput = struct {
		Product  string `path:"product"`
		Stream   string `path:"stream"`
		Variant  string `path:"variant"`
		Place    string `path:"place" doc:"The lead's place identity"`
		Identity string `path:"identity"`
	}
	// handed is the hand-off of the lead a route names, where the reader
	// reads the lead in the product at the visibility it holds while its flaw
	// is undisclosed: who is on a lead is managed by whoever reads it there.
	handed := func(ctx context.Context, db bun.IDB, at *leadAt, place string) (*finding.Handoff, error) {
		if _, err := finding.NewStore(db).LeadAt(ctx, at.subject, at.target, place); err != nil {
			return nil, core.Absent(in.Logger, err, "that lead could not be looked up", core.NoSuchFinding)
		}
		h, err := finding.HandoffAt(ctx, db, at.named.ProductID, place)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that lead could not be looked up", err)
		}
		if h == nil {
			return nil, huma.Error404NotFound(analysis.ErrNotHandedOff.Error())
		}
		if !at.subject.Reads(h.Undisclosed(), at.named.ProductID) {
			return nil, core.NoSuchFinding()
		}
		return h, nil
	}
	// changing is handed asked inside the transaction granting or withdrawing,
	// where a disclosed flaw ends the grants.
	changing := func(ctx context.Context, tx bun.IDB, at *leadAt, place string) (*finding.Handoff, string, error) {
		h, err := handed(ctx, tx, at, place)
		if err != nil {
			return nil, "", err
		}
		if h.Disclosed() {
			return nil, "", huma.Error409Conflict(analysis.ErrFlawDisclosed.Error())
		}
		name, err := analysis.LeadName(ctx, tx, h)
		if err != nil {
			return nil, "", core.WentWrong(in.Logger, "that lead could not be looked up", err)
		}
		return h, name, nil
	}

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-lead-collaborators", Method: http.MethodGet, Path: path,
		Summary: "List who has been granted a handed-off lead",
		Description: "Everybody granted this one handed-off lead in this product, oldest first.\n\n" +
			"A grant reads the lead's evidence and nothing else of the product, until its flaw " +
			"is disclosed.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "Where you read the lead at the visibility it holds while its flaw is undisclosed: internal work for a kept lead, undisclosed work for a moved one.", leadReaders()...),
		func(ctx context.Context, input *leadInput) (*core.ListOutput[LeadCollaboratorBody], error) {
			at, err := locateLead(ctx, in, input.Product, input.Stream, input.Variant)
			if err != nil {
				return nil, err
			}
			h, err := handed(ctx, in.DB.DB, at, input.Place)
			if err != nil {
				return nil, err
			}
			rows, err := access.NewStore(in.DB.DB).LeadRows(ctx, at.named.ProductID, h.PlaceIdentity)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "who is on this lead could not be read", err)
			}
			body, err := leadCollaboratorBodies(ctx, in, rows)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "who is on this lead could not be read", err)
			}
			out := &core.ListOutput[LeadCollaboratorBody]{}
			out.Body.Items = body
			return out, nil
		})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "add-lead-collaborator", Method: http.MethodPut, Path: path + "/{identity}",
		Summary: "Grant somebody a handed-off lead",
		Description: "Grants one person this one handed-off lead in this product, to read its " +
			"evidence, without granting them anything else of the product.\n\n" +
			"It is an access change: it lands in the administration trail, and they are told in " +
			"the notification area inside the application.\n\n" +
			"Adding somebody who already holds it succeeds and changes nothing. Once the flaw is " +
			"disclosed, a grant is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Where you read the lead at the visibility it holds while its flaw is undisclosed: internal work for a kept lead, undisclosed work for a moved one.", leadReaders()...),
		func(ctx context.Context, input *personInput) (*struct{}, error) {
			at, err := locateLead(ctx, in, input.Product, input.Stream, input.Variant)
			if err != nil {
				return nil, err
			}
			var h *finding.Handoff
			var person *access.Account
			var added bool
			if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
				var name string
				var err error
				if h, name, err = changing(ctx, tx, at, input.Place); err != nil {
					return err
				}
				rights := access.NewStore(tx)
				if person, err = core.PersonNamed(ctx, a.Logger, rights, input.Identity); err != nil {
					return err
				}
				if added, err = rights.AddToLead(ctx, at.named.ProductID, h.PlaceIdentity, person.ID,
					at.subject.ID); err != nil {
					return core.WentWrong(in.Logger, "they could not be granted the lead", err)
				}
				if !added {
					return nil
				}
				if err := core.Noted(ctx, tx, trail.Case, name+" · "+person.Identity,
					nil, trail.Said("a lead collaborator", true)); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			if !added {
				return &struct{}{}, nil
			}
			flaw, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, []int64{h.VulnerabilityID})
			if err != nil {
				in.Log().Error("could not name the flaw a lead was handed off as", "error", err)
			}
			core.Tell(ctx, in, "could not say that somebody was granted a lead", notify.Telling{
				PersonID: person.ID, Kind: notify.BroughtIn,
				Body: "You have been granted the static analysis lead behind " + flaw[h.VulnerabilityID] +
					" in " + at.named.Product + ". You can read its evidence, and nothing else of that product.",
				Link:    weblink.Lead(at.named.Product, at.named.Stream, at.named.Variant, h.PlaceIdentity),
				Private: true,
				// The flaw, so somebody on its case reads the line as well as
				// somebody reading the product's undisclosed work, and the
				// lead, so the person granted it alone does.
				ProductID:       &at.named.ProductID,
				VulnerabilityID: &h.VulnerabilityID,
				Concerns:        notify.ConcerningLead(at.named.ProductID, h.PlaceIdentity),
			}, "person", person.Identity)
			return &struct{}{}, nil
		})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "remove-lead-collaborator", Method: http.MethodDelete, Path: path + "/{identity}",
		Summary: "Withdraw somebody's grant of a handed-off lead",
		Description: "Withdraws the grant. The record of it is kept.\n\n" +
			"Withdrawing a grant somebody does not hold answers 404 and records nothing. Once the " +
			"flaw is disclosed, a withdrawal is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Where you read the lead at the visibility it holds while its flaw is undisclosed: internal work for a kept lead, undisclosed work for a moved one.", leadReaders()...),
		func(ctx context.Context, input *personInput) (*struct{}, error) {
			at, err := locateLead(ctx, in, input.Product, input.Stream, input.Variant)
			if err != nil {
				return nil, err
			}
			if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
				h, name, err := changing(ctx, tx, at, input.Place)
				if err != nil {
					return err
				}
				rights := access.NewStore(tx)
				person, err := core.PersonNamed(ctx, a.Logger, rights, input.Identity)
				if err != nil {
					return err
				}
				switch err := rights.RemoveFromLead(ctx, at.named.ProductID, h.PlaceIdentity, person.ID,
					at.subject.ID); {
				case errors.Is(err, access.ErrNothingMatched):
					return huma.Error404NotFound("they do not hold this lead")
				case err != nil:
					return core.WentWrong(in.Logger, "their grant could not be withdrawn", err)
				}
				if err := core.Noted(ctx, tx, trail.Case, name+" · "+person.Identity,
					trail.Said("a lead collaborator", true), nil); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			return &struct{}{}, nil
		})
}

// leadCollaboratorBodies names the people granted a lead.
func leadCollaboratorBodies(ctx context.Context, in core.Deps, rows []access.LeadCollaborator) (
	[]LeadCollaboratorBody, error) {

	out := make([]LeadCollaboratorBody, 0, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	people := make([]int64, 0, len(rows)*2)
	for _, row := range rows {
		people = append(people, row.PersonID, row.AddedBy)
	}
	who, err := core.WhoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, LeadCollaboratorBody{
			Identity: who.Identity(row.PersonID), Name: who.Label(row.PersonID),
			AddedBy: who.Identity(row.AddedBy), AddedByName: who.Label(row.AddedBy),
			AddedAt: core.Stamp(row.AddedAt),
		})
	}
	return out, nil
}

// leadReaders is the roles that read a handed-off lead: internal work for a
// kept lead, undisclosed work for a moved one.
func leadReaders() []access.Role {
	return append([]access.Role{access.InternalRead, access.InternalTriage}, core.PrivateRights()...)
}
