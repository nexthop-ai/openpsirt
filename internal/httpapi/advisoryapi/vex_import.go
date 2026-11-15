// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// statementParts is a VEX document arriving.
type statementParts struct {
	// The declared content type is permissive for the reason an inventory's
	// is: a part's type is decided by reading it rather than by the label a
	// client put on it.
	Statements huma.FormFile `form:"statements" contentType:"application/json,application/octet-stream" required:"true"`
}

// StatementsTakenBody is the record of what one VEX document changed.
type StatementsTakenBody struct {
	Publisher  string `json:"publisher" doc:"The publisher the statements were recorded under: the one the request names, else the one the document names"`
	Recorded   int    `json:"recorded" doc:"Statements taken from it"`
	Superseded int    `json:"superseded" doc:"Statements set aside rather than deleted: those the earlier revision of this document made and this one does not, and the publisher's older statements about a product and issue this document states newer"`
	Digest     string `json:"digest" doc:"The document's digest, which is how a revision is noticed later"`
}

func registerVexImport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "upload-vex-statements", Method: http.MethodPost,
		Path:    "/v1/products/{product}/vex-documents",
		Summary: "Upload a VEX document",
		Description: "Takes one OpenVEX document of what a distribution or an upstream " +
			"security team has published about components this product ships.\n\n" +
			"A supplier's statement that its own product, at the version a build ships, is " +
			"not affected closes the finding where every route to it runs through that " +
			"product, at the next scan. Everything else that arrives is a third layer beside " +
			"the build's own claims and our decisions: shown as evidence and offered as a " +
			"prefill.\n\n" +
			"What a document adds over what the scanner already reports is the " +
			"reasoning. The status is in the fix state already.\n\n" +
			"Uploading a later revision of the same document sets aside what the earlier one " +
			"said rather than deleting it, so what an approval was granted on the strength of " +
			"stays readable. Another document from the same publisher replaces nothing of this " +
			"one, and of the publisher's statements about one product and vulnerability, the " +
			"newest stands, whichever document carried it: by the statement's own time, its " +
			"`last_updated` else its `timestamp`, else its document's, else the upload order; a " +
			"time after the upload is none. A " +
			"document is its publisher and its own identifier: an OpenVEX `@id` or a CSAF " +
			"tracking id. The publisher is the `publisher` parameter, else the one the " +
			"document names: an OpenVEX author or a CSAF publisher name. A document naming none " +
			"is refused unless the parameter names one.\n\n" +
			"OpenVEX and CSAF-VEX are both read, and a statement in either becomes the same " +
			"claim. The format is detected from the document; anything else is refused with " +
			"a sentence and nothing of it is read.\n\n" +
			"A CSAF security advisory is refused here; send it to the supplier-advisory " +
			"endpoint, where a later upload replaces the advisory of the same name." +
			"\n\nAnswers 503 with `Retry-After` when the deployment is already reading as many " +
			"uploads as it takes at once; send again after that many seconds.",
		Tags: []string{"Ingest"}, DefaultStatus: http.StatusCreated,
		MaxBodyBytes: core.MaxUpload(in.Limits),
		Middlewares:  suppliedForm(api, in, finding.FromVex),
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Publisher string `query:"publisher" maxLength:"191" doc:"The publisher, in place of the one the document names. Required where the document names none. At most 191 characters"`
		RawBody   huma.MultipartFormFiles[statementParts]
	}) (*struct{ Body StatementsTakenBody }, error) {
		named := strings.TrimSpace(attach.Visible(input.Publisher))
		took, err := takeSupplied(ctx, core.Of(ctx, in), input.Product,
			input.RawBody.Data().Statements, finding.FromVex,
			func(r io.Reader, lim sbom.Limits) (suppliedDocument, error) {
				said, err := sbom.ReadStatements(r, lim)
				return suppliedDocument{
					Publisher: said.Publisher, Identifier: said.Identifier,
					SaidAt: said.SaidAt, Claims: said.Claims,
				}, err
			},
			func(from *finding.Supplied) error {
				// The publisher is the key a later upload supersedes on, and
				// it is an indexed column of a fixed width. Refused rather
				// than shortened: two publishers agreeing for the width of the
				// column would collapse into one, and the later upload would
				// set aside statements it has nothing to do with.
				//
				// The request names it first, so one publisher's documents
				// can be kept apart by release; else the document's own
				// author. The file name never stands in: two publishers'
				// files of one name would set aside each other's statements,
				// and a revision under a new name would set aside nothing.
				if named != "" {
					from.Publisher = named
				}
				// What a later upload replaces is a revision of the same
				// document: the publisher and the document's own identifier,
				// matched exactly, because it is read out of the document
				// every time. One longer than the column is held as its
				// digest: an OpenVEX identifier is an IRI of any length, and a
				// revision states the same one, so its digest keys it as well.
				if utf8.RuneCountInString(from.Identifier) > finding.MostDocumentName {
					sum := sha256.Sum256([]byte(from.Identifier))
					from.Identifier = "sha256:" + hex.EncodeToString(sum[:])
				}
				if from.Publisher == "" {
					return huma.Error422UnprocessableEntity(
						"the document names no publisher; name it with ?publisher=")
				}
				if utf8.RuneCountInString(from.Publisher) > finding.MostPublisher {
					return huma.Error422UnprocessableEntity(fmt.Sprintf(
						"who published it is longer than the %d characters this records; "+
							"name it with ?publisher=", finding.MostPublisher))
				}
				return nil
			},
			func(from finding.Supplied) string { return "VEX statements from " + from.Publisher })
		if err != nil {
			return nil, err
		}

		return &struct{ Body StatementsTakenBody }{Body: StatementsTakenBody{
			Publisher: took.From.Publisher, Recorded: took.Recorded, Superseded: took.Superseded,
			Digest: took.From.Digest,
		}}, nil
	})
}

// statementsOf is what a publisher's document says, one statement for each
// component each claim names.
func statementsOf(said []sbom.Suppression) []finding.Statement {
	statements := make([]finding.Statement, 0, len(said))
	for _, one := range said {
		for _, at := range one.Targets {
			statements = append(statements, finding.StatementOf(one, at))
		}
	}
	return statements
}

// recordSupplied records what an uploaded document says about a product, in
// place of what the same document said before, and notes the upload in the
// trail under about. It answers how many statements it recorded and how many
// earlier ones it set aside.
//
// The product is resolved by name inside the write. The caller's lookup before
// parsing is an early refusal, and the one here decides, so a product renamed
// or retired while the document was read is what a retry reads.
func recordSupplied(ctx context.Context, in core.Deps, by access.Subject, productName string,
	from finding.Supplied, said []sbom.Suppression, about string) (int, int, error) {

	statements := statementsOf(said)
	var recorded, superseded int
	if err := finding.EnsureStatementsLock(ctx, in.DB); err != nil {
		return 0, 0, core.NotRecorded(in.Log(), err)
	}
	if err := core.Changing(ctx, in.DB, func(ctx context.Context, tx bun.Tx) error {
		in := core.Of(ctx, in)
		if err := finding.TakeStatements(ctx, tx); err != nil {
			return core.NotRecorded(in.Logger, err)
		}
		product, err := catalog.NewStore(tx).ProductByName(ctx, productName)
		if err != nil {
			return core.Absent(in.Logger, err, "that product could not be looked up", core.NoSuchProduct)
		}
		recorded, superseded, err = finding.NewStore(tx).RecordStatements(ctx, by,
			product.ID, from, statements)
		if err != nil {
			return core.Asked(in.Logger, err)
		}
		if err := core.Noted(ctx, tx, trail.Setting, about,
			nil, trail.Said(from.Document, true)); err != nil {
			return core.NotRecorded(in.Logger, err)
		}
		return nil
	}); err != nil {
		return 0, 0, err
	}
	return recorded, superseded, nil
}

// documentName is the file name a document is recorded under: the client's,
// made safe and bounded the way an attachment's is, and empty where the client
// gave none. It is stored on every statement the document makes.
func documentName(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return attach.SafeName(name)
}
