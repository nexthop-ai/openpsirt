// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

func registerVEX(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-vex", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/vex",
		Summary: "Generate a VEX document for a build",
		Description: "Returns an OpenVEX document saying what stands about the third-party " +
			"components this build ships: every approved `not applicable` and `already fixed` " +
			"claim, as `not_affected` and `fixed` statements with the justification and the " +
			"reasoning somebody wrote.\n\n" +
			"Approved claims only, and a deferral is absent rather than exported as " +
			"anything — silence already reads as affected in this format.\n\n" +
			"Public findings only. `undisclosed=true` includes the rest for somebody who " +
			"may read them, which is a preview rather than a thing to publish.\n\n" +
			"Requires a publisher configured for this deployment: a document naming none has " +
			"nobody as its author.",
		Tags: []string{"Findings"},
	}, perProduct, "Answers only what you may see. A grant on one case does not reach it: "+
		"the document is about the whole build rather than about one issue.",
		readRights()...),
		func(ctx context.Context, input *struct {
			Product     string `path:"product"`
			Stream      string `path:"stream"`
			Variant     string `path:"variant"`
			Undisclosed bool   `query:"undisclosed" doc:"Include findings nobody has announced. A preview, not a document to publish"`
		}) (*struct{ Body *vex.Statements }, error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			if in.DB == nil {
				return nil, noDatabase(in.Logger)
			}
			doc, err := vex.NewStore(in.DB.DB).For(ctx, subject, in.Publisher,
				input.Product, input.Stream, input.Variant, input.Undisclosed)
			if err != nil {
				return nil, vexRefused(in, err, "the document could not be generated")
			}
			return &struct{ Body *vex.Statements }{Body: doc}, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-vex-issuances", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/vex/issuance",
		Summary: "List the times a VEX document went out",
		Description: "What has been published for this build, oldest first: which revision, " +
			"when, and what the document hashed to at the time.\n\n" +
			"The record itself is read without generating a document. `changed` generates " +
			"the public one to compare, so it is absent where that cannot be done.\n\n" +
			"The digest is over what the document says, with the moment it was generated, " +
			"the version and the build of OpenPSIRT that wrote it left out, so a document " +
			"regenerated unchanged hashes the same. `changed` says whether the public " +
			"document generated now differs from the last one that went out.\n\n" +
			"`changed` is absent where nothing has gone out, where no publisher is " +
			"configured, and where the build now holds more statements than one document " +
			"carries.",
		Tags: []string{"Findings"},
	}, perProduct, "Answers only what you may see. A grant on one case does not reach it: "+
		"a row saying a document about this build went out is as much a disclosure as the "+
		"document.", readRights()...),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
			Stream  string `path:"stream"`
			Variant string `path:"variant"`
		}) (*vexIssuances, error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			if in.DB == nil {
				return nil, noDatabase(in.Logger)
			}
			store := vex.NewStore(in.DB.DB)
			gone, err := store.Issuances(ctx, subject,
				input.Product, input.Stream, input.Variant)
			if err != nil {
				return nil, vexRefused(in, err, "what has gone out could not be read")
			}
			changed, err := store.Changed(ctx, subject, in.Publisher,
				input.Product, input.Stream, input.Variant)
			switch {
			case errors.Is(err, vex.ErrTooLarge):
				// What went out is still what went out. A build that grew past
				// one document has no document to compare, which is no answer
				// rather than a failed read.
				changed = nil
			case err != nil:
				return nil, vexRefused(in, err, "what has gone out could not be compared")
			}
			out := &vexIssuances{}
			out.Body.Changed = changed
			out.Body.Items = make([]VEXIssuanceBody, 0, len(gone))
			for _, one := range gone {
				out.Body.Items = append(out.Body.Items, VEXIssuanceBody{
					Version: one.Ordinal, Digest: one.Digest, IssuedBy: one.IssuedBy,
					IssuedAt: one.IssuedAt.Format(time.RFC3339),
				})
			}
			return out, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "record-vex-issued", Method: http.MethodPost,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/vex/issuance",
		Summary: "Record that a VEX document went out",
		Description: "Records that the document for this build was published: when, by whom, " +
			"and a digest of the document as it stands now. Answers with the document " +
			"that was recorded, which is the one to send: it carries the version it is " +
			"recorded under, and a document generated before recording may not.\n\n" +
			"A fact about a moment rather than a derived value. What was published on a date " +
			"cannot be worked out again once a claim is withdrawn, a decision is revised or a " +
			"scan closes a finding.\n\n" +
			"It is what the document's version counts. A document is assembled from what " +
			"stands now and holds no history of its own, so without this every generation is " +
			"the first revision of something, and a reader keeping documents by their " +
			"identifier cannot tell which supersedes which.\n\n" +
			"The digest is taken from the document generated here rather than from anything " +
			"sent: a digest of whatever a caller says answers nothing. The public document, " +
			"never the preview that includes work nobody has announced.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "The document is this deployment's word to a customer. The second pair of "+
		"eyes on each statement it carries was taken when the claim was approved.",
		triageRights()...),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
			Stream  string `path:"stream"`
			Variant string `path:"variant"`
		}) (*struct {
			Status int
			Body   VEXRecordedBody
		}, error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			if in.DB == nil {
				return nil, noDatabase(in.Logger)
			}
			recorded, err := vex.NewStore(in.DB.DB).Issued(ctx, subject, in.Publisher,
				input.Product, input.Stream, input.Variant)
			if err != nil {
				return nil, vexRefused(in, err, "that could not be recorded")
			}
			return &struct {
				Status int
				Body   VEXRecordedBody
			}{Status: http.StatusCreated, Body: VEXRecordedBody{
				VEXIssuanceBody: VEXIssuanceBody{
					Version: recorded.Ordinal, Digest: recorded.Digest,
					IssuedBy: subject.Identity,
					IssuedAt: recorded.IssuedAt.Format(time.RFC3339),
				},
				Document: json.RawMessage(recorded.Document),
			}}, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-vex-issued", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/vex/issuance/{version}",
		Summary: "Read a VEX document that went out",
		Description: "The OpenVEX document recorded as one revision, byte for byte as it went " +
			"out. It carries the version it was recorded under and the moment it was " +
			"recorded.\n\n" +
			"A revision nobody recorded answers 404.",
		Tags: []string{"Findings"},
	}, perProduct, "Answers only what you may see. A grant on one case does not reach it: "+
		"the document is about the whole build rather than about one issue.",
		readRights()...),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
			Stream  string `path:"stream"`
			Variant string `path:"variant"`
			Version int    `path:"version" minimum:"1" doc:"Which revision, counting from one"`
		}) (*struct{ Body json.RawMessage }, error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			if in.DB == nil {
				return nil, noDatabase(in.Logger)
			}
			sent, err := vex.NewStore(in.DB.DB).Sent(ctx, subject,
				input.Product, input.Stream, input.Variant, input.Version)
			if errors.Is(err, vex.ErrNoSuchRevision) {
				return nil, huma.Error404NotFound("no document went out as that revision")
			}
			if err != nil {
				return nil, vexRefused(in, err, "what went out could not be read")
			}
			// The bytes as kept, handed over untouched: they are what a
			// customer was sent.
			return &struct{ Body json.RawMessage }{Body: json.RawMessage(sent)}, nil
		})
}

// vexIssuances is what has gone out for a build, and whether what would be
// generated now differs from the last of it.
type vexIssuances struct {
	Body struct {
		Items   []VEXIssuanceBody `json:"items"`
		Changed *bool             `json:"changed,omitempty" doc:"Whether the public document generated now says something different from the last one that went out. Absent where nothing has gone out or no publisher is configured"`
	}
}

// VEXRecordedBody is one issuance just recorded, with the document it
// recorded.
type VEXRecordedBody struct {
	VEXIssuanceBody
	Document json.RawMessage `json:"document" doc:"The OpenVEX document recorded, as its bytes, carrying the version it is recorded under. This is the one to send"`
}

// VEXIssuanceBody is one time the document for a build went out.
type VEXIssuanceBody struct {
	Version  int    `json:"version" doc:"Which revision went out, counting from one. It is the version that document carries"`
	Digest   string `json:"digest" doc:"A digest of what the document said, so that what is published and what we would generate stay answerable against each other"`
	IssuedBy string `json:"issued_by" doc:"Who published it. The act leaves this row and nothing else, so the row names them"`
	IssuedAt string `json:"issued_at"`
}

// vexRefused maps what the store refuses to what a caller is told.
//
// One mapping for every route here, because generating the document,
// recording that it went out and reading what has are the same names resolved
// the same way. Spelled per route, the answer to a build nobody declared
// differs by which route somebody happened to ask on.
//
// A build in a product nobody may see and one nobody declared answer the same
// way. Telling them apart turns a lookup into a directory of what this
// deployment ships.
func vexRefused(in Ingest, err error, what string) error {
	switch {
	case errors.Is(err, vex.ErrMayNotPublish):
		// Before the denial below, which this one is. Whoever sees it has
		// already been handed the build by name, so the answer a build nobody
		// declared gets would contradict the read they just performed.
		return asked(in.Logger, err)
	case errors.Is(err, catalog.ErrNotFound), errors.Is(err, access.ErrDenied):
		return noSuchProduct()
	case errors.Is(err, vex.ErrTooLarge):
		// Something to narrow rather than something broken, and the sentence
		// says which build and what the limit is. Answered as a fault it is a
		// 500 reading "the document could not be generated", with the part a
		// caller can act on in the log. Recording that one went out generates
		// the document too, so it refuses the same way.
		return huma.Error422UnprocessableEntity(err.Error())
	// Asked of the publisher directly. A wrapper of its own in the package
	// that answers it spells one predicate two ways in one file, and the
	// wrapper is the half nothing executes.
	case !in.Publisher.Stated():
		// A configuration gap rather than a bad request, and named as one:
		// whoever is asking cannot fix it from here, and an operator can.
		return huma.Error409Conflict(err.Error())
	}
	return wentWrong(in.Logger, what, err)
}
