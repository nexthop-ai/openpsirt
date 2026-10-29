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

// CodeFindingBuild is one build a flaw record names.
type CodeFindingBuild struct {
	BranchOrTag string `json:"branch_or_tag" minLength:"1" doc:"A branch or a tag"`
	Variant     string `json:"variant" minLength:"1" doc:"The way that line is built"`
}

// FlawOfferSource is where a suggested component came from.
type FlawOfferSource string

// Schema answers with the sources a suggestion comes from.
func (FlawOfferSource) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.Sources()))
	for _, each := range analysis.Sources() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// SuggestionBody is one component offered at flaw record.
type SuggestionBody struct {
	Component  string             `json:"component,omitempty" doc:"The component, as the builds name it. Absent for the build itself"`
	Ecosystem  string             `json:"ecosystem,omitempty" doc:"Its ecosystem, where its package identifier states one"`
	Namespace  string             `json:"namespace,omitempty" doc:"Its namespace, where its package identifier states one"`
	From       FlawOfferSource    `json:"from" doc:"Where the suggestion came from: a prefix confirmed at an earlier flaw record, the component the code finding was placed on, a component whose name resembles the code finding's directory, or the build itself"`
	Lacking    []CodeFindingBuild `json:"lacking" doc:"The builds the code finding was seen in that hold no such component. Recording the flaw against them is refused"`
	Unanalyzed []CodeFindingBuild `json:"unanalyzed" doc:"The builds holding the component that the code finding's series never analyzed"`
}

// NoteBody is one piece of writing on a decision about a code finding.
type NoteBody struct {
	Decision int64  `json:"decision" doc:"The decision it was written on"`
	Comment  bool   `json:"comment,omitempty" doc:"Whether it is a comment. Otherwise it is a revision of the decision's reasoning"`
	Body     string `json:"body" doc:"What was written, in markdown"`
	Written  string `json:"written" format:"date-time"`
}

// AuthorBody is one person who wrote about a code finding, with what they wrote.
type AuthorBody struct {
	Identity string     `json:"identity"`
	Name     string     `json:"name,omitempty" doc:"Their display name, where it differs from their identity"`
	Notes    []NoteBody `json:"notes" doc:"The revisions of reasoning and the comments they wrote on decisions about the code finding, oldest first"`
}

// AnalyzerSaidBody is one message the analyzer wrote at a path.
type AnalyzerSaidBody struct {
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// DisclosesBody is what including a code finding in its flaw's disclosure discloses with the
// flaw.
type DisclosesBody struct {
	Authors  []AuthorBody       `json:"authors" doc:"Everybody who wrote reasoning or a comment on a decision about the code finding or the code findings linked with it, with what each wrote, as you read the decisions"`
	Paths    []string           `json:"paths" doc:"Every path the code finding names"`
	Said     []AnalyzerSaidBody `json:"said" doc:"Every message the analyzer wrote at those paths"`
	Snippets int                `json:"snippets" doc:"The number of source snippets disclosed with the flaw. Zero where none is"`
	Stripped int                `json:"stripped" doc:"The number of source snippets removed at disclosure, under paths the product does not disclose snippets for"`
}

// FlawOfferBody is what a flaw record of one code finding is offered.
type FlawOfferBody struct {
	Rule        string             `json:"rule" doc:"The analyzer's rule, as <tool>/<rule>"`
	Seen        []CodeFindingBuild `json:"seen" doc:"Every build the code finding was seen in, which the flaw is proposed against"`
	Suggestions []SuggestionBody   `json:"suggestions" doc:"The components offered, most likely first. The build itself is always last"`
	Prefix      string             `json:"prefix,omitempty" doc:"The path a confirmed component is remembered for: the repository or declared third-party path the code finding is in, or its directory"`
	ThirdParty  bool               `json:"third_party,omitempty" doc:"Whether the code finding is in code its newest run declared third-party. The flaw is reported to the upstream the code came from; recording it here is still accepted"`
	Together    int                `json:"together" doc:"The number of other code findings linked to the flaw with this one: the code findings its confirming decision covers. They are included in disclosure or taken out with it"`
	Discloses   DisclosesBody      `json:"discloses" doc:"What including the code finding, and the code findings linked with it, in the flaw's disclosure discloses when the flaw is disclosed"`
}

// RecordedAsFlawBody is the record of a code finding recorded as a flaw.
type RecordedAsFlawBody struct {
	Identifier           string `json:"identifier" doc:"The identifier the flaw was filed under"`
	Component            string `json:"component" doc:"The component in the build that carries it"`
	Builds               int    `json:"builds" doc:"The number of builds it was recorded against"`
	Occurrences          int    `json:"occurrences" doc:"The number of findings of the flaw that opened"`
	IncludedInDisclosure bool   `json:"included_in_disclosure" doc:"Whether the code finding is included in its flaw's disclosure"`
}

// codeFindingPath is one code finding, addressed by its occurrence on one build.
const codeFindingPath = "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}"

// codeFindingAt is the reader, the build and the product a route about one code finding
// names.
type codeFindingAt struct {
	subject access.Subject
	named   *catalog.Named
	build   int64
}

// locateCodeFinding resolves the build a code finding route names.
func locateCodeFinding(ctx context.Context, in core.Deps, product, branchOrTag, variant string) (*codeFindingAt, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return nil, err
	}
	named, err := core.LocatedVisibly(ctx, in, subject, product, branchOrTag, variant)
	if err != nil {
		return nil, err
	}
	build, err := core.BuildRow(ctx, in, named.BranchOrTagID, named.VariantID)
	if err != nil {
		return nil, err
	}
	return &codeFindingAt{subject: subject, named: named, build: build.ID}, nil
}

// refusedFlawRecord is the answer to recording a flaw, an inclusion in disclosure
// or an undo the store turned away.
func refusedFlawRecord(in core.Deps, err error) error {
	switch {
	case errors.Is(err, finding.ErrNoOpenFinding):
		return core.NoSuchFinding()
	case errors.Is(err, access.ErrDenied):
		return huma.Error403Forbidden("not authorized")
	case errors.Is(err, analysis.ErrRecordedAsFlaw), errors.Is(err, analysis.ErrNotConfirmed),
		errors.Is(err, analysis.ErrAlreadyIncluded), errors.Is(err, analysis.ErrNotIncluded),
		errors.Is(err, analysis.ErrFlawDisclosed), errors.Is(err, analysis.ErrNotRecordedAsFlaw),
		errors.Is(err, finding.ErrCodeFindingPastEndOfLife):
		return huma.Error409Conflict(err.Error())
	}
	return refusedFlaw(in, err)
}

func registerFlaw(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-code-finding-flaw", Method: http.MethodGet, Path: codeFindingPath + "/flaw",
		Summary: "Get the offer to record a code finding as a flaw",
		Description: "Returns what recording a confirmed code finding as a flaw here is offered: the " +
			"components it may be recorded against, most likely first, the builds it was seen in, " +
			"and what including it in the flaw's disclosure would publish with the flaw.\n\n" +
			"A suggestion lists the builds the code finding was seen in that lack it, since recording the " +
			"flaw against those is refused, and the builds holding it that the code finding's series never " +
			"analyzed.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
	}) (*struct{ Body FlawOfferBody }, error) {
		at, err := locateCodeFinding(ctx, in, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		offer, err := analysis.Propose(ctx, in.DB.DB, at.subject, at.named.ProductID, input.Occurrence)
		if err != nil {
			return nil, refusedFlawRecord(in, err)
		}
		discloses, err := disclosesBody(ctx, in, offer.Discloses)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "who wrote about the code finding could not be read", err)
		}
		body := FlawOfferBody{
			Rule: offer.Rule, Seen: codeFindingBuilds(offer.Seen), Prefix: offer.Prefix, ThirdParty: offer.ThirdParty,
			Together:    offer.Together,
			Suggestions: make([]SuggestionBody, 0, len(offer.Suggestions)), Discloses: discloses,
		}
		for _, s := range offer.Suggestions {
			body.Suggestions = append(body.Suggestions, SuggestionBody{
				Component: s.Component, Ecosystem: s.Ecosystem, Namespace: s.Namespace,
				From: FlawOfferSource(s.From), Lacking: codeFindingBuilds(s.Lacking), Unanalyzed: codeFindingBuilds(s.Unanalyzed),
			})
		}
		return &struct{ Body FlawOfferBody }{Body: body}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "record-code-finding-as-flaw", Method: http.MethodPost, Path: codeFindingPath + "/flaw",
		Summary: "Record a confirmed code finding as a flaw",
		Description: "Records a confirmed code finding as a flaw in this product, found here and " +
			"undisclosed, through the same path as `POST /v1/products/{product}/findings`, and " +
			"links the code finding to it, with every other code finding the decision confirming it covers.\n\n" +
			"`builds` is the whole set the flaw is recorded against. `component` names what " +
			"carries it, as the builds name it, and is remembered for the code finding's prefix so the next " +
			"code finding under it is offered the same; leave it out for the build itself.\n\n" +
			"`include_in_disclosure` includes the linked code findings in the flaw's disclosure: everybody " +
			"who reads them keeps reading them, the flaw's readers read them too, and they are disclosed " +
			"with the flaw. Left out, the code findings are internal only and linked.\n\n" +
			"A code finding nobody confirmed, or one already recorded as a flaw, is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
		Body        struct {
			Builds    []CodeFindingBuild `json:"builds" minItems:"1" maxItems:"200" doc:"Every build the flaw is recorded against"`
			Component string             `json:"component,omitempty" doc:"The component that carries it. Omit for the build itself"`
			Ecosystem string             `json:"ecosystem,omitempty" doc:"The ecosystem, where two components share the name"`
			Namespace string             `json:"namespace,omitempty" doc:"The namespace, where two share a name and an ecosystem"`
			FlawFields
			IncludeInDisclosure bool `json:"include_in_disclosure,omitempty" doc:"Whether the code finding is included in its flaw's disclosure. Internal only by default"`
		}
	}) (*struct {
		Status int
		Body   RecordedAsFlawBody
	}, error) {
		at, err := locateCodeFinding(ctx, in, input.Product, input.BranchOrTag, input.Variant)
		if err != nil {
			return nil, err
		}
		subject := at.subject
		// Before any build the body names is resolved, so a refusal says
		// nothing about which of them exist.
		if err := analysis.MayRecordAsFlaw(subject, at.named.ProductID); err != nil {
			return nil, refusedFlawRecord(in, err)
		}
		names := catalog.NewStore(in.DB.DB)
		buildIDs := make([]int64, 0, len(input.Body.Builds))
		for _, b := range input.Body.Builds {
			located, err := names.LocateVisible(ctx, subject, input.Product, b.BranchOrTag, b.Variant)
			if err != nil {
				return nil, core.Undeclared(in.Logger, err, "that build could not be looked up")
			}
			build, err := core.BuildRow(ctx, in, located.BranchOrTagID, located.VariantID)
			if err != nil {
				return nil, err
			}
			buildIDs = append(buildIDs, build.ID)
		}
		done, err := analysis.RecordAsFlaw(ctx, in.DB.DB, subject, analysis.Recording{
			ProductID: at.named.ProductID, OccurrenceIdentity: input.Occurrence, IncludeInDisclosure: input.Body.IncludeInDisclosure,
			Sweeps: in.Queue,
			Flaw: finding.Entering{
				BuildIDs: buildIDs, Component: input.Body.Component,
				Ecosystem: input.Body.Ecosystem, Namespace: input.Body.Namespace,
				Summary: input.Body.Summary, Severity: string(input.Body.Severity),
				Vector: input.Body.Vector, Weaknesses: input.Body.Weaknesses,
			},
		})
		if err != nil {
			return nil, refusedFlawRecord(in, err)
		}
		if err := notify.TellCodeFindingTriagers(ctx, in.DB.DB, notify.CodeFindingAct{Kind: notify.CodeFindingRecordedAsFlaw,
			ProductID: at.named.ProductID, Occurrence: input.Occurrence, By: subject.ID}); err != nil {
			in.Log().Error("could not say that a code finding was recorded as a flaw", "error", err)
		}
		return &struct {
			Status int
			Body   RecordedAsFlawBody
		}{Status: http.StatusCreated, Body: RecordedAsFlawBody{
			Identifier: done.Identifier, Component: done.Component,
			Builds: done.Builds, Occurrences: done.Occurrences, IncludedInDisclosure: input.Body.IncludeInDisclosure,
		}}, nil
	})

	including := func(include bool) func(context.Context, *struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
	}) (*struct{}, error) {
		return func(ctx context.Context, input *struct {
			Product     string `path:"product"`
			BranchOrTag string `path:"branch_or_tag"`
			Variant     string `path:"variant"`
			Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
		}) (*struct{}, error) {
			at, err := locateCodeFinding(ctx, in, input.Product, input.BranchOrTag, input.Variant)
			if err != nil {
				return nil, err
			}
			if include {
				err = analysis.IncludeInDisclosure(ctx, in.DB.DB, at.subject, at.named.ProductID, input.Occurrence, time.Now())
			} else {
				err = analysis.ExcludeFromDisclosure(ctx, in.DB.DB, at.subject, at.named.ProductID, input.Occurrence)
			}
			if err != nil {
				return nil, refusedFlawRecord(in, err)
			}
			if err := notify.TellCodeFindingTriagers(ctx, in.DB.DB, notify.CodeFindingAct{Kind: notify.CodeFindingIncludedInDisclosure,
				ProductID: at.named.ProductID, Occurrence: input.Occurrence, By: at.subject.ID, Into: include}); err != nil {
				in.Log().Error("could not say that a code finding was included in disclosure or taken out", "error", err)
			}
			return &struct{}{}, nil
		}
	}
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "include-code-finding-in-disclosure", Method: http.MethodPut, Path: codeFindingPath + "/flaw/disclosure",
		Summary: "Include a code finding in its flaw's disclosure",
		Description: "Includes an internal-only code finding in its flaw's disclosure, with every code finding linked to the " +
			"same flaw: everybody who reads them keeps reading them, the flaw's readers read them " +
			"too, and they are disclosed with the flaw. `GET .../flaw` lists what that " +
			"discloses.\n\n" +
			"Recorded in the administration trail. A code finding not recorded as a flaw, one already included, or " +
			"one whose flaw is disclosed, is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), including(true))
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "exclude-code-finding-from-disclosure", Method: http.MethodDelete, Path: codeFindingPath + "/flaw/disclosure",
		Summary: "Take a code finding out of its flaw's disclosure",
		Description: "Takes a code finding out of its flaw's disclosure while the flaw is undisclosed, with " +
			"every code finding linked to the same flaw. The flaw's readers no longer read them, everybody " +
			"else who read them still does, and they stay linked to the flaw.\n\n" +
			"Recorded in the administration trail. A code finding not recorded as a flaw, one that is internal only, or one whose " +
			"flaw is disclosed, is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Both internal-triage and private-triage on the product.",
		access.InternalTriage, access.PrivateTriage), including(false))
}

// codeFindingBuilds is builds as an answer states them.
func codeFindingBuilds(builds []analysis.BuildName) []CodeFindingBuild {
	out := make([]CodeFindingBuild, 0, len(builds))
	for _, b := range builds {
		out = append(out, CodeFindingBuild{BranchOrTag: b.BranchOrTag, Variant: b.Variant})
	}
	return out
}

// disclosesBody names the authors of what an inclusion discloses, with what each
// wrote.
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
		Said: make([]AnalyzerSaidBody, 0, len(d.Said)), Snippets: d.Snippets, Stripped: d.Stripped}
	if out.Paths == nil {
		out.Paths = []string{}
	}
	for _, a := range d.Authors {
		author := AuthorBody{Identity: who.Identity(a.PersonID), Name: who.Label(a.PersonID),
			Notes: make([]NoteBody, 0, len(a.Notes))}
		for _, n := range a.Notes {
			author.Notes = append(author.Notes, NoteBody{Decision: n.DecisionID, Comment: n.Comment, Body: n.Body,
				Written: core.Stamp(n.WrittenAt)})
		}
		out.Authors = append(out.Authors, author)
	}
	for _, said := range d.Said {
		out.Said = append(out.Said, AnalyzerSaidBody{Path: said.Path, Message: said.Message})
	}
	return out, nil
}

// CodeFindingCollaboratorBody is one person granted a code finding recorded as a flaw.
type CodeFindingCollaboratorBody = CollaboratorBody

func registerCodeFindingCollaborators(api huma.API, in core.Deps, a core.Administering) {
	const path = codeFindingPath + "/collaborators"
	type codeFindingInput = struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
	}
	type personInput = struct {
		Product     string `path:"product"`
		BranchOrTag string `path:"branch_or_tag"`
		Variant     string `path:"variant"`
		Occurrence  string `path:"occurrence" doc:"The code finding's occurrence identity"`
		Identity    string `path:"identity"`
	}
	// recorded is the flaw record of the code finding a route names, where the reader
	// reads internal work in the product: who is on a code finding is managed by its
	// internal readers, whether or not it is included in disclosure.
	recorded := func(ctx context.Context, db bun.IDB, at *codeFindingAt, occurrence string) (*finding.CodeFindingFlaw, error) {
		if _, err := finding.NewStore(db).CodeFindingAt(ctx, at.subject, at.build, occurrence); err != nil {
			return nil, core.Absent(in.Logger, err, "that code finding could not be looked up", core.NoSuchFinding)
		}
		h, err := finding.CodeFindingFlawAt(ctx, db, at.named.ProductID, occurrence)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that code finding could not be looked up", err)
		}
		if h == nil {
			return nil, huma.Error404NotFound(analysis.ErrNotRecordedAsFlaw.Error())
		}
		if !at.subject.Reads(access.Internal, at.named.ProductID) {
			return nil, core.NoSuchFinding()
		}
		return h, nil
	}
	// changing is recorded asked inside the transaction granting or withdrawing,
	// where a disclosed flaw ends the grants.
	changing := func(ctx context.Context, tx bun.IDB, at *codeFindingAt, occurrence string) (*finding.CodeFindingFlaw, string, error) {
		h, err := recorded(ctx, tx, at, occurrence)
		if err != nil {
			return nil, "", err
		}
		if h.Disclosed() {
			return nil, "", huma.Error409Conflict(analysis.ErrFlawDisclosed.Error())
		}
		name, err := analysis.CodeFindingName(ctx, tx, h)
		if err != nil {
			return nil, "", core.WentWrong(in.Logger, "that code finding could not be looked up", err)
		}
		return h, name, nil
	}

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-code-finding-collaborators", Method: http.MethodGet, Path: path,
		Summary: "List a code finding's collaborators",
		Description: "Everybody granted this one code finding recorded as a flaw in this product, oldest first.\n\n" +
			"A grant reads the code finding's evidence and nothing else of the product, until its flaw " +
			"is disclosed.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "Where you read internal work in the product, whether or not the code finding is included in disclosure.", codeFindingReaders()...),
		func(ctx context.Context, input *codeFindingInput) (*core.ListOutput[CodeFindingCollaboratorBody], error) {
			at, err := locateCodeFinding(ctx, in, input.Product, input.BranchOrTag, input.Variant)
			if err != nil {
				return nil, err
			}
			h, err := recorded(ctx, in.DB.DB, at, input.Occurrence)
			if err != nil {
				return nil, err
			}
			rows, err := access.NewStore(in.DB.DB).CodeFindingRows(ctx, at.named.ProductID, h.OccurrenceIdentity)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "who is on this code finding could not be read", err)
			}
			body, err := codeFindingCollaboratorBodies(ctx, in, rows)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "who is on this code finding could not be read", err)
			}
			out := &core.ListOutput[CodeFindingCollaboratorBody]{}
			out.Body.Items = body
			return out, nil
		})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "add-code-finding-collaborator", Method: http.MethodPut, Path: path + "/{identity}",
		Summary: "Add a code finding collaborator",
		Description: "Grants one person this one code finding recorded as a flaw in this product, to read its " +
			"evidence, without granting them anything else of the product.\n\n" +
			"It is an access change: it lands in the administration trail, and they are told in " +
			"the notification area inside the application.\n\n" +
			"Adding somebody who already holds it succeeds and changes nothing. Once the flaw is " +
			"disclosed, a grant is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Where you read internal work in the product, whether or not the code finding is included in disclosure.", codeFindingReaders()...),
		func(ctx context.Context, input *personInput) (*struct{}, error) {
			at, err := locateCodeFinding(ctx, in, input.Product, input.BranchOrTag, input.Variant)
			if err != nil {
				return nil, err
			}
			var h *finding.CodeFindingFlaw
			var person *access.Account
			var added bool
			if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
				var name string
				var err error
				if h, name, err = changing(ctx, tx, at, input.Occurrence); err != nil {
					return err
				}
				rights := access.NewStore(tx)
				if person, err = core.PersonNamed(ctx, a.Logger, rights, input.Identity); err != nil {
					return err
				}
				if added, err = rights.AddToCodeFinding(ctx, at.named.ProductID, h.OccurrenceIdentity, person.ID,
					at.subject.ID); err != nil {
					return core.WentWrong(in.Logger, "they could not be granted the code finding", err)
				}
				if !added {
					return nil
				}
				if err := core.Noted(ctx, tx, trail.Case, name+" · "+person.Identity,
					nil, trail.Said("a code finding collaborator", true)); err != nil {
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
				in.Log().Error("could not name the flaw a code finding was recorded as", "error", err)
			}
			core.Tell(ctx, in, "could not say that somebody was granted a code finding", notify.Telling{
				PersonID: person.ID, Kind: notify.BroughtIn,
				Body: "You have been granted the static analysis code finding behind " + flaw[h.VulnerabilityID] +
					" in " + at.named.Product + ". You can read its evidence, and nothing else of that product.",
				Link:    weblink.CodeFinding(at.named.Product, at.named.BranchOrTag, at.named.Variant, h.OccurrenceIdentity),
				Private: true,
				// The flaw, so somebody on its case reads the line as well as
				// somebody reading the product's undisclosed work, and the
				// code finding, so the person granted it alone does.
				ProductID:       &at.named.ProductID,
				VulnerabilityID: &h.VulnerabilityID,
				Concerns:        notify.ConcerningCodeFinding(at.named.ProductID, h.OccurrenceIdentity),
			}, "person", person.Identity)
			return &struct{}{}, nil
		})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "remove-code-finding-collaborator", Method: http.MethodDelete, Path: path + "/{identity}",
		Summary: "Remove a code finding collaborator",
		Description: "Withdraws the grant. The record of it is kept.\n\n" +
			"Withdrawing a grant somebody does not hold answers 404 and records nothing. Once the " +
			"flaw is disclosed, a withdrawal is refused with 409.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Where you read internal work in the product, whether or not the code finding is included in disclosure.", codeFindingReaders()...),
		func(ctx context.Context, input *personInput) (*struct{}, error) {
			at, err := locateCodeFinding(ctx, in, input.Product, input.BranchOrTag, input.Variant)
			if err != nil {
				return nil, err
			}
			if err := core.Changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
				h, name, err := changing(ctx, tx, at, input.Occurrence)
				if err != nil {
					return err
				}
				rights := access.NewStore(tx)
				person, err := core.PersonNamed(ctx, a.Logger, rights, input.Identity)
				if err != nil {
					return err
				}
				switch err := rights.RemoveFromCodeFinding(ctx, at.named.ProductID, h.OccurrenceIdentity, person.ID,
					at.subject.ID); {
				case errors.Is(err, access.ErrNothingMatched):
					return huma.Error404NotFound("they do not hold this code finding")
				case err != nil:
					return core.WentWrong(in.Logger, "their grant could not be withdrawn", err)
				}
				if err := core.Noted(ctx, tx, trail.Case, name+" · "+person.Identity,
					trail.Said("a code finding collaborator", true), nil); err != nil {
					return core.NotRecorded(a.Logger, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			return &struct{}{}, nil
		})
}

// codeFindingCollaboratorBodies names the people granted a code finding.
func codeFindingCollaboratorBodies(ctx context.Context, in core.Deps, rows []access.CodeFindingCollaborator) (
	[]CodeFindingCollaboratorBody, error) {

	out := make([]CodeFindingCollaboratorBody, 0, len(rows))
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
		out = append(out, CodeFindingCollaboratorBody{
			Identity: who.Identity(row.PersonID), Name: who.Label(row.PersonID),
			AddedBy: who.Identity(row.AddedBy), AddedByName: who.Label(row.AddedBy),
			AddedAt: core.Stamp(row.AddedAt),
		})
	}
	return out, nil
}

// codeFindingReaders is the roles that manage who is granted a code finding recorded as a flaw:
// internal work, which the code finding is until its flaw is disclosed.
func codeFindingReaders() []access.Role {
	return []access.Role{access.InternalRead, access.InternalTriage}
}
