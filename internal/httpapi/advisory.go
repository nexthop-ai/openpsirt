// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// startsAdvisory is what starting one and editing it asks for.
//
// An advisory names no product until an issue is added to it, so there is no
// product to hold a role on at the moment it is minted. What the handler asks
// for is a triage role somewhere, which is the same population that records
// the flaws an advisory is written about.
const startsAdvisory = "A triage role on some product. An advisory names no product " +
	"until an issue is added to it, so there is none for the role to be held on here."

// namesAFlaw is what naming a flaw on an advisory, or taking one off, asks
// for.
//
// The role on the product named in the request rather than on some product:
// naming a flaw is what puts it into a document published about that product,
// and taking one back off is as much a statement about it.
const namesAFlaw = "A triage role on the product named in the request, and on every product " +
	"the advisory already covers. Naming a flaw on an advisory is what puts it into a document " +
	"published about that product, and opens an edition of the whole document."

// changesWhatItSays is what retitling an advisory, agreeing to it and taking
// an agreement back ask for.
//
// Every product it covers rather than one named in the request, because these
// three name no product at all.
const changesWhatItSays = "A triage role on every product the advisory covers. What it says " +
	"about one product is part of the same document as what it says about another."

// advisoryRefused maps what the store refuses to what a caller is told.
func advisoryRefused(in Ingest, err error, what string) error {
	switch {
	case errors.Is(err, advisory.ErrNoPublisher), errors.Is(err, advisory.ErrNoPrefix):
		// A configuration gap rather than a bad request, and named as one:
		// whoever is asking cannot fix it from here, and an operator can.
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, advisory.ErrNotOurs), errors.Is(err, advisory.ErrAlreadyCovered),
		errors.Is(err, advisory.ErrNothingToSay), errors.Is(err, advisory.ErrAlreadyAgreed),
		errors.Is(err, advisory.ErrNothingAgreed), errors.Is(err, access.ErrDenied):
		// A denial among them, because asked is where this tree turns one
		// into 403. Left to the sentence at the end it answers 500, and
		// spelled again here it is the same rule in two places.
		return asked(in.Logger, err)
	case errors.Is(err, advisory.ErrSamePerson), errors.Is(err, advisory.ErrNotAgreed):
		// The state the advisory is in refuses this, rather than the request
		// being malformed. What a caller does about it is an act somewhere
		// else — a second person agreeing, or the flaw being disclosed.
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, advisory.ErrNoSuchAdvisory):
		return huma.Error404NotFound(advisory.ErrNoSuchAdvisory.Error())
	case errors.Is(err, advisory.ErrNoSuchIssue), errors.Is(err, catalog.ErrNotFound):
		// The same answer for a product nobody holds and an issue that is not
		// there. Telling them apart turns a lookup into a directory of what
		// exists.
		return noSuchIssue()
	}
	return wentWrong(in.Logger, what, err)
}

func registerAdvisory(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "start-advisory", Method: http.MethodPost, Path: "/v1/advisories",
		Summary: "Start an advisory",
		Description: "Mints an identifier and returns the empty advisory under it.\n\n" +
			"The identifier is minted here rather than chosen. It is what a reader cites " +
			"the document by and what a revision of it keeps, so two advisories under one " +
			"name is a state this has no way back from.\n\n" +
			"An advisory covers issues, which are added one at a time and each names the " +
			"product it is covered in. Until one is added the advisory generates no " +
			"document: the standard requires at least one vulnerability, and a document " +
			"about nothing is not a draft of anything.\n\n" +
			"Requires a prefix configured for this deployment to mint under.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, anyPerson, startsAdvisory, triageRights()...), func(ctx context.Context, input *struct {
		Body struct {
			Title string `json:"title,omitempty" maxLength:"191" doc:"What to call it. Left out, the document names the issues it covers"`
		}
	}) (*struct {
		Status int
		Body   AdvisoryBody
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		made, err := advisory.NewStore(in.DB.DB).Mint(ctx, subject, in.Publisher,
			input.Body.Title)
		if err != nil {
			return nil, advisoryRefused(in, err, "the advisory could not be started")
		}
		return &struct {
			Status int
			Body   AdvisoryBody
		}{Status: http.StatusCreated, Body: AdvisoryBody{
			Advisory: made.Identifier, Title: made.Title,
			MintedAt: made.MintedAt.Format(time.RFC3339),
			Covers:   []CoveredBody{},
		}}, nil
	})

	huma.Register(api, answering(huma.Operation{
		OperationID: "list-advisories", Method: http.MethodGet, Path: "/v1/advisories",
		Summary: "List advisories",
		Description: "Every advisory you may see, newest first.\n\n" +
			"An advisory covering a product you hold nothing on is not listed, and the " +
			"total says the same. A document is read whole or not at all: one with a " +
			"product quietly left out reads as a complete statement about a product it " +
			"says nothing about.\n\n" +
			"`issues` and `products` are both given because one issue in three products " +
			"and three issues in one are different documents, and a single count reads " +
			"the same for each.\n\n" +
			"`product` and `vulnerability` narrow it to what covers them, which is what a " +
			"screen about one flaw asks before somebody starts another advisory about it.",
		Tags: []string{"Findings"},
	}, anyPerson, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `query:"product" doc:"Only advisories covering something in this product"`
		Vulnerability string `query:"vulnerability" doc:"Only advisories covering this issue"`
		Limit         int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset        int    `query:"offset" minimum:"0" default:"0"`
	}) (*listOutput[AdvisoryListedBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		rows, total, err := advisory.NewStore(in.DB.DB).List(ctx, subject,
			advisory.Covering{Product: input.Product, Vulnerability: input.Vulnerability},
			input.Limit, input.Offset)
		if err != nil {
			return nil, advisoryRefused(in, err, "the advisories could not be read")
		}
		out := &listOutput[AdvisoryListedBody]{}
		out.Body.Items = make([]AdvisoryListedBody, 0, len(rows))
		for _, one := range rows {
			out.Body.Items = append(out.Body.Items, AdvisoryListedBody{
				Advisory: one.Identifier, Title: one.Title,
				Issues: one.Issues, Products: one.Products, Issuances: one.Issuances,
				Status: one.Status(), Agreed: one.Agreed,
				MintedAt: one.MintedAt.Format(time.RFC3339),
			})
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-advisory", Method: http.MethodGet, Path: "/v1/advisories/{advisory}",
		Summary: "Read an advisory",
		Description: "The advisory and the issues it covers, in the order they were added, " +
			"who agrees to what it says now, and whether what it would generate now differs " +
			"from what last went out.\n\n" +
			"`changed` is absent where nothing has gone out, where it covers nothing, and " +
			"where no publisher is configured, since then there is no document to compare.\n\n" +
			"An advisory covering a product you hold nothing on answers as one that does " +
			"not exist. Told apart, the pair of answers says what exists.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory" doc:"The identifier the advisory is tracked by"`
	}) (*struct{ Body AdvisoryBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		store := advisory.NewStore(in.DB.DB)
		row, held, err := store.Covers(ctx, subject, input.Advisory)
		if err != nil {
			return nil, advisoryRefused(in, err, "the advisory could not be read")
		}
		where, err := store.Where(ctx, subject, input.Advisory)
		if err != nil {
			return nil, advisoryRefused(in, err, "the advisory could not be read")
		}
		changed, err := store.Changed(ctx, subject, in.Publisher, input.Advisory)
		if err != nil {
			return nil, advisoryRefused(in, err, "the advisory could not be compared")
		}
		body := bodyFor(row, held)
		body.Status, body.Agreed = where.Status, len(where.Agreed)
		body.Changed = changed
		body.AgreedBy = make([]AgreerBody, 0, len(where.Agreed))
		for i, one := range where.Agreed {
			body.AgreedBy = append(body.AgreedBy, AgreerBody{
				Person: where.AgreedBy[i], AgreedAt: one.ApprovedAt.Format(time.RFC3339),
			})
		}
		return &struct{ Body AdvisoryBody }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-nameable-flaws", Method: http.MethodGet,
		Path:    "/v1/products/{product}/nameable-flaws",
		Summary: "List the flaws an advisory may name",
		Description: "Every flaw recorded here in this product, open or fixed, by identifier. " +
			"These are the issues adding one to an advisory accepts in this product.\n\n" +
			"`open` is how many of its findings are still open; none means it is fixed " +
			"wherever it was found. At most 500, in identifier order; `total` says how many " +
			"there are.\n\n" +
			"A product you do not triage answers 404.",
		Tags: []string{"Findings"},
	}, perProduct, "Answers only what you may see.", triageRights()...),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
		}) (*listOutput[NameableBody], error) {
			subject, err := reading(ctx)
			if err != nil {
				return nil, err
			}
			if in.DB == nil {
				return nil, noDatabase(in.Logger)
			}
			rows, total, err := advisory.NewStore(in.DB.DB).Nameable(ctx, subject, input.Product)
			if errors.Is(err, catalog.ErrNotFound) {
				return nil, noSuchProduct()
			}
			if err != nil {
				return nil, advisoryRefused(in, err, "the flaws could not be read")
			}
			out := &listOutput[NameableBody]{}
			out.Body.Total = total
			out.Body.Items = make([]NameableBody, 0, len(rows))
			for _, one := range rows {
				out.Body.Items = append(out.Body.Items, NameableBody{
					Vulnerability: one.Identifier, Summary: one.Summary, Open: one.Open,
				})
			}
			return out, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-advisory-issue", Method: http.MethodPost,
		Path:    "/v1/advisories/{advisory}/issues",
		Summary: "Add an issue to an advisory",
		Description: "Names an issue in a product as covered by this advisory.\n\n" +
			"The pair, not the issue alone: an issue in two products is two entries, " +
			"because the releases that carry it differ and a status is stated about " +
			"releases.\n\n" +
			"Only a flaw recorded here. An issue a scanner reported against a third-party " +
			"component is refused, and refused at this point rather than when the document " +
			"is generated, so the refusal names the issue you chose.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, anyPerson, namesAFlaw, triageRights()...), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
		Body     struct {
			Product       string `json:"product" minLength:"1"`
			Vulnerability string `json:"vulnerability" minLength:"1" doc:"The identifier the issue is filed under"`
		}
	}) (*struct {
		Status int
		Body   CoveredBody
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		added, err := advisory.NewStore(in.DB.DB).Add(ctx, subject, input.Advisory,
			input.Body.Product, input.Body.Vulnerability)
		if err != nil {
			return nil, advisoryRefused(in, err, "the issue could not be added")
		}
		return &struct {
			Status int
			Body   CoveredBody
		}{Status: http.StatusCreated, Body: CoveredBody{
			Product: added.Product, ProductName: added.ProductName,
			Vulnerability: added.Issue, Summary: added.Summary,
			AddedAt: added.AddedAt.Format(time.RFC3339),
		}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "drop-advisory-issue", Method: http.MethodDelete,
		Path:    "/v1/advisories/{advisory}/issues/{product}/{vulnerability}",
		Summary: "Take an issue off an advisory",
		Description: "Removes one issue in one product from this advisory.\n\n" +
			"Nothing here asks whether the advisory has gone out. An issuance records what " +
			"went out at a moment, and editing the advisory afterwards is how the next " +
			"revision differs from the last.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, anyPerson, namesAFlaw, triageRights()...), func(ctx context.Context, input *struct {
		Advisory      string `path:"advisory"`
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*struct{}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		if err := advisory.NewStore(in.DB.DB).Drop(ctx, subject, input.Advisory,
			input.Product, input.Vulnerability); err != nil {
			return nil, advisoryRefused(in, err, "the issue could not be taken off")
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-advisory-document", Method: http.MethodGet,
		Path:    "/v1/advisories/{advisory}/document",
		Summary: "Generate a CSAF document for an advisory",
		Description: "Returns a CSAF 2.0 document for this advisory: what it covers, and " +
			"which releases hold each issue and which no longer do.\n\n" +
			"One entry per issue and one product branch per product, so several flaws " +
			"released together are one document on one date.\n\n" +
			"The document is generated, not published. Nothing is sent anywhere. Recording " +
			"that it was issued is a separate request, and what it keeps is a digest of " +
			"what was generated, so that whether what you published is still what this " +
			"would generate can be answered.\n\n" +
			"How far the document may travel is its distribution label, red while " +
			"anything it covers is still held back. `tracking.status` says where the " +
			"document is in its life. Reaching a disclosure date discloses nothing, so " +
			"nothing here does either.\n\n" +
			"An advisory covering no issue is refused: the standard requires at least one. " +
			"Requires a publisher configured for this deployment, because a document " +
			"naming none is not a valid CSAF document.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
	}) (*struct{ Body *advisory.Document }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		doc, err := advisory.NewStore(in.DB.DB).ForAdvisory(ctx, subject, in.Publisher,
			input.Advisory)
		if err != nil {
			return nil, advisoryRefused(in, err, "the advisory could not be generated")
		}
		return &struct{ Body *advisory.Document }{Body: doc}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-advisory-issuances", Method: http.MethodGet,
		Path:    "/v1/advisories/{advisory}/issuance",
		Summary: "List the times an advisory went out",
		Description: "What has been published for this advisory, oldest first: which " +
			"revision, when, and what the document hashed to at the time.\n\n" +
			"Readable without generating a document. Every issuance is in the document's " +
			"own revision history, which is right for a reader of the document — but it " +
			"made \"has this gone out, and is what is published still what we would " +
			"generate\" a question you had to build a CSAF document to answer, and " +
			"somebody deciding whether to publish a revision is asking before they " +
			"generate anything.\n\n" +
			"The digest is what makes the comparison possible, and it was taken from " +
			"the document generated here rather than from anything sent.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
	}) (*listOutput[IssuanceBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		gone, err := advisory.NewStore(in.DB.DB).Issuances(ctx, subject, input.Advisory)
		if err != nil {
			return nil, advisoryRefused(in, err, "what has gone out could not be read")
		}
		out := &listOutput[IssuanceBody]{}
		out.Body.Items = make([]IssuanceBody, 0, len(gone))
		for _, one := range gone {
			out.Body.Items = append(out.Body.Items, IssuanceBody{
				Version: one.Ordinal, Digest: one.Digest, Summary: one.Summary,
				IssuedAt: one.IssuedAt.Format(time.RFC3339),
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retitle-advisory", Method: http.MethodPatch,
		Path:    "/v1/advisories/{advisory}",
		Summary: "Retitle an advisory",
		Description: "Gives the advisory a new title, as a new edition of what it says.\n\n" +
			"Every agreement standing on the old title is taken back. A second person " +
			"agreed to particular words, and different words are a document nobody has " +
			"agreed to.\n\n" +
			"Requires a triage role on every product the advisory covers, because what it " +
			"says about one of them is part of the same document as what it says about " +
			"another.",
		Tags: []string{"Findings"},
	}, anyPerson, changesWhatItSays, triageRights()...), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
		Body     struct {
			Title string `json:"title" maxLength:"191" doc:"What to call it. Empty, the document names the issues it covers"`
		}
	}) (*struct{ Body AdvisoryBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		row, held, err := advisory.NewStore(in.DB.DB).Retitle(ctx, subject,
			input.Advisory, input.Body.Title)
		if err != nil {
			return nil, advisoryRefused(in, err, "the advisory could not be retitled")
		}
		return &struct{ Body AdvisoryBody }{Body: bodyFor(row, held)}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "approve-advisory", Method: http.MethodPost,
		Path:    "/v1/advisories/{advisory}/approval",
		Summary: "Approve an advisory",
		Description: "Records that you have read what this advisory says and agree to it.\n\n" +
			"The agreement names the edition it was given against rather than the " +
			"advisory. Retitling it, naming another flaw on it or taking one off opens a " +
			"new edition and takes the agreement back, so what stands is always an " +
			"agreement to the document as it reads now.\n\n" +
			"You may not agree to an advisory you started or whose current edition you " +
			"wrote. Both answer 409, and there is no override, so a deployment with one " +
			"person publishes no advisory.\n\n" +
			"Requires a triage role on every product the advisory covers.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, anyPerson, changesWhatItSays, triageRights()...), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
	}) (*struct {
		Status int
		Body   AgreementBody
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		given, err := advisory.NewStore(in.DB.DB).Approve(ctx, subject, input.Advisory)
		if err != nil {
			return nil, advisoryRefused(in, err, "that could not be agreed to")
		}
		return &struct {
			Status int
			Body   AgreementBody
		}{Status: http.StatusCreated, Body: AgreementBody{
			Edition: given.Edition, AgreedAt: given.AgreedAt.Format(time.RFC3339),
		}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "withdraw-advisory-approval", Method: http.MethodDelete,
		Path:    "/v1/advisories/{advisory}/approval",
		Summary: "Withdraw approval of an advisory",
		Description: "Takes back every agreement standing on what the advisory says now.\n\n" +
			"Every agreement standing, not only your own. It needs no agreement of its " +
			"own, and the advisory cannot go out until somebody agrees again.\n\n" +
			"Answers 422 where no agreement is standing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, anyPerson, changesWhatItSays, triageRights()...), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
	}) (*struct{}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		if err := advisory.NewStore(in.DB.DB).Withdraw(ctx, subject, input.Advisory); err != nil {
			return nil, advisoryRefused(in, err, "that could not be withdrawn")
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "record-advisory-issued", Method: http.MethodPost,
		Path:    "/v1/advisories/{advisory}/issuance",
		Summary: "Record that an advisory went out",
		Description: "Records that this advisory was published: when, by whom, and a digest " +
			"of the document as it stands now.\n\n" +
			"A fact about a moment rather than a derived value. What was published on a " +
			"date cannot be worked out again once the record it came from has moved on — a " +
			"release is added, a decision is revised, a fix lands — so if it is not written " +
			"down when it happens it is gone.\n\n" +
			"It is what lets a second document be a revision. Without it a second document " +
			"cannot carry a revision history or a higher version, and both are things CSAF " +
			"validators check; a document that fails validation is one a customer's tooling " +
			"drops.\n\n" +
			"The document as it goes out is kept, because it cannot be worked out again: " +
			"what would be generated tomorrow is a different document. The digest beside " +
			"it makes \"is what is published still what we generate\" a question with an " +
			"answer, and it is taken from the document generated here rather than from " +
			"anything sent — a digest of whatever a caller says answers nothing.\n\n" +
			"Answers 409 where nobody has agreed to what the advisory says.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, anyPerson, startsAdvisory, triageRights()...), func(ctx context.Context, input *struct {
		Advisory string `path:"advisory"`
		Body     struct {
			Summary string `json:"summary,omitempty" maxLength:"191" doc:"The revision's summary, for the document's revision history. A history whose every entry reads the same is one nobody reads"`
		}
	}) (*struct {
		Status int
		Body   IssuanceBody
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		recorded, err := advisory.NewStore(in.DB.DB).Issued(ctx, subject, in.Publisher,
			input.Advisory, input.Body.Summary)
		if err != nil {
			return nil, advisoryRefused(in, err, "that could not be recorded")
		}
		return &struct {
			Status int
			Body   IssuanceBody
		}{Status: http.StatusCreated, Body: IssuanceBody{
			Version: recorded.Ordinal, Digest: recorded.Digest,
			Summary: recorded.Summary, IssuedAt: recorded.IssuedAt.Format(time.RFC3339),
		}}, nil
	})
}

// bodyFor is an advisory and what it covers, as a reader gets it.
func bodyFor(row *advisory.Advisory, held []advisory.Covered) AdvisoryBody {
	body := AdvisoryBody{
		Advisory: row.Identifier, Title: row.Title,
		MintedAt: row.MintedAt.Format(time.RFC3339),
		Covers:   make([]CoveredBody, 0, len(held)),
	}
	for _, one := range held {
		body.Covers = append(body.Covers, CoveredBody{
			Product: one.Product, ProductName: one.ProductName,
			Vulnerability: one.Issue, Summary: one.Summary,
			AddedAt: one.AddedAt.Format(time.RFC3339),
		})
	}
	return body
}

// AdvisoryBody is one advisory and the issues it covers.
type AdvisoryBody struct {
	Advisory string `json:"advisory" doc:"The identifier the advisory is tracked by"`
	Title    string `json:"title,omitempty"`
	// Status and Agreed are left out where the advisory was just started or
	// just retitled, which answers with what the act did rather than with
	// where the advisory stands.
	Status   string        `json:"status,omitempty" enum:"draft,final,interim" doc:"Where the document is in its life. Final where somebody agrees to what it says now, interim where it has gone out and nobody does, draft before either"`
	Agreed   int           `json:"agreed,omitempty" doc:"How many people agree to what it says now. None means it cannot go out"`
	AgreedBy []AgreerBody  `json:"agreed_by,omitempty" doc:"Who agrees to what it says now, oldest first"`
	Changed  *bool         `json:"changed,omitempty" doc:"Whether the document generated now says something different from the last one that went out"`
	MintedAt string        `json:"minted_at"`
	Covers   []CoveredBody `json:"covers"`
}

// NameableBody is one flaw an advisory may name in a product.
type NameableBody struct {
	Vulnerability string `json:"vulnerability" doc:"The identifier the issue is filed under"`
	Summary       string `json:"summary,omitempty"`
	Open          int    `json:"open" doc:"How many of its findings in this product are still open. None means it is fixed wherever it was found"`
}

// AgreerBody is one person agreeing to what an advisory says now.
type AgreerBody struct {
	Person   string `json:"person" doc:"Who agrees, by sign-in identity"`
	AgreedAt string `json:"agreed_at"`
}

// AgreementBody is one person's agreement to what an advisory says.
type AgreementBody struct {
	Edition  int    `json:"edition" doc:"Which edition was agreed to, counting from one within this advisory. A later edition is a document nobody has agreed to yet"`
	AgreedAt string `json:"agreed_at"`
}

// AdvisoryListedBody is one advisory as a list of them reads it.
type AdvisoryListedBody struct {
	Advisory  string `json:"advisory"`
	Title     string `json:"title,omitempty"`
	Issues    int    `json:"issues" doc:"How many issues it covers"`
	Products  int    `json:"products" doc:"How many products those sit in"`
	Issuances int    `json:"issuances" doc:"How many times it has gone out"`
	Status    string `json:"status" enum:"draft,final,interim" doc:"Where the document is in its life"`
	Agreed    int    `json:"agreed" doc:"How many people agree to what it says now"`
	MintedAt  string `json:"minted_at"`
}

// CoveredBody is one issue an advisory covers, in one product.
type CoveredBody struct {
	Product       string `json:"product"`
	ProductName   string `json:"product_name,omitempty" doc:"The product's display name, where it has one"`
	Vulnerability string `json:"vulnerability"`
	Summary       string `json:"summary,omitempty"`
	AddedAt       string `json:"added_at"`
}

// IssuanceBody is one time an advisory went out.
type IssuanceBody struct {
	Version  int    `json:"version" doc:"The issuance number, counting from one. It is what the next document's version says"`
	Digest   string `json:"digest" doc:"A digest of what went out, so that what is published and what we would generate stay answerable against each other"`
	Summary  string `json:"summary,omitempty"`
	IssuedAt string `json:"issued_at"`
}
