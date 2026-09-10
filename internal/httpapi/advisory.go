package httpapi

import (
	"time"

	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

func registerAdvisory(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-advisory", Method: http.MethodGet,
		Path:    "/v1/products/{product}/issues/{vulnerability}/advisory",
		Summary: "Generate a CSAF advisory for an issue",
		Description: "Returns a CSAF 2.0 document for a flaw in this product: what it is, and " +
			"which releases hold it and which no longer do.\n\n" +
			"**The document is generated, not published.** Nothing is sent anywhere and " +
			"nothing here records that an advisory was issued — the triage record is ours and " +
			"the published advisory belongs to whoever publishes it, and keeping both as the " +
			"source of truth is how such an arrangement rots.\n\n" +
			"**Only for a flaw in what you ship.** An issue a scanner reported against a " +
			"third-party component is refused: that is dependency hygiene a consumer can " +
			"already read out of the inventory, and a vendor advisory for every upstream CVE " +
			"in a dependency is not what an advisory is.\n\n" +
			"**A document about an undisclosed flaw is a draft**, and says so in `tracking." +
			"status`. Reaching a disclosure date discloses nothing, so nothing here does " +
			"either.\n\n" +
			"Requires a publisher configured for this deployment: a document naming none is " +
			"not a valid CSAF document.",
		Tags: []string{"Findings"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The identifier the issue is filed under"`
	}) (*struct{ Body *advisory.Document }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}

		doc, err := advisory.NewStore(in.DB.DB).For(ctx, subject, in.Publisher,
			input.Product, input.Vulnerability)
		if err != nil {
			switch {
			case errors.Is(err, advisory.ErrNoPublisher):
				// A configuration gap rather than a bad request, and named as
				// one: whoever is asking cannot fix it from here, and an
				// operator can.
				return nil, huma.Error409Conflict(err.Error())
			case errors.Is(err, advisory.ErrNotOurs):
				return nil, asked(in.Logger, err)
			case errors.Is(err, advisory.ErrNoSuchIssue), errors.Is(err, catalog.ErrNotFound):
				// The same answer for a product nobody holds and an issue that
				// is not there. Telling them apart turns a lookup into a
				// directory of what exists.
				return nil, noSuchIssue()
			}
			return nil, wentWrong(in.Logger, "the advisory could not be generated", err)
		}
		return &struct{ Body *advisory.Document }{Body: doc}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-advisory-issuances", Method: http.MethodGet,
		Path:    "/v1/products/{product}/issues/{vulnerability}/advisory/issuance",
		Summary: "List the advisories that went out for a flaw",
		Description: "What has been published about this flaw in this product, newest first: " +
			"which revision, when, and what the document hashed to at the time.\n\n" +
			"**Readable without generating a document.** Every issuance is in the document's " +
			"own revision history, which is right for a reader of the document — but it made " +
			"\"has an advisory gone out, and is what is published still what we would " +
			"generate\" a question you had to build a CSAF document to answer, and somebody " +
			"deciding whether to publish a revision is asking before they generate " +
			"anything.\n\n" +
			"The published document itself belongs to whoever published it. The digest is what " +
			"makes the comparison possible, and it was taken from the document generated here " +
			"rather than from anything sent.",
		Tags: []string{"Findings"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The identifier the issue is filed under"`
	}) (*listOutput[IssuanceBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		gone, err := advisory.NewStore(in.DB.DB).Issuances(ctx, subject,
			input.Product, input.Vulnerability)
		if err != nil {
			switch {
			case errors.Is(err, advisory.ErrNotOurs):
				return nil, asked(in.Logger, err)
			case errors.Is(err, advisory.ErrNoSuchIssue), errors.Is(err, catalog.ErrNotFound):
				return nil, noSuchIssue()
			}
			return nil, wentWrong(in.Logger, "what has gone out could not be read", err)
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
		OperationID: "record-advisory-issued", Method: http.MethodPost,
		Path:    "/v1/products/{product}/issues/{vulnerability}/advisory/issuance",
		Summary: "Record that an advisory went out",
		Description: "Records that an advisory for this flaw was published: when, by whom, and " +
			"a digest of the document as it stands now.\n\n" +
			"**A fact about a moment rather than a derived value.** What was published on a " +
			"date cannot be worked out again once the record it came from has moved on — a " +
			"release is added, a decision is revised, a fix lands — so if it is not written " +
			"down when it happens it is gone.\n\n" +
			"**It is what lets a second document be a revision.** Without it a second advisory " +
			"for the same flaw cannot carry a revision history or a higher version, and both " +
			"are things CSAF validators check; a document that fails validation is one a " +
			"customer's tooling drops.\n\n" +
			"The published advisory itself stays with whoever published it. The digest is what " +
			"makes \"is what is published still what we generate\" a question with an answer, " +
			"and it is taken from the document generated here rather than from anything sent — " +
			"a digest of whatever a caller says answers nothing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
		Body          struct {
			Summary string `json:"summary,omitempty" maxLength:"191" doc:"What this revision says, for the document's revision history. A history whose every entry reads the same is one nobody reads"`
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
			input.Product, input.Vulnerability, input.Body.Summary)
		if err != nil {
			switch {
			case errors.Is(err, advisory.ErrNoPublisher):
				return nil, huma.Error409Conflict(err.Error())
			case errors.Is(err, advisory.ErrNotOurs):
				return nil, asked(in.Logger, err)
			case errors.Is(err, advisory.ErrNoSuchIssue), errors.Is(err, catalog.ErrNotFound):
				return nil, noSuchIssue()
			}
			return nil, wentWrong(in.Logger, "that could not be recorded", err)
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

// IssuanceBody is one time an advisory went out.
type IssuanceBody struct {
	Version  int    `json:"version" doc:"Which issuance this is, counting from one. It is what the next document's version says"`
	Digest   string `json:"digest" doc:"What went out, hashed, so that what is published and what we would generate stay answerable against each other"`
	Summary  string `json:"summary,omitempty"`
	IssuedAt string `json:"issued_at"`
}
