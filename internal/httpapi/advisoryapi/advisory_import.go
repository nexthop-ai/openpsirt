// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// advisoryParts is a supplier's security advisory arriving.
type advisoryParts struct {
	// The declared content type is permissive for the reason an inventory's
	// is: a part's type is decided by reading it rather than by the label a
	// client put on it.
	Advisory huma.FormFile `form:"advisory" contentType:"application/json,application/octet-stream" required:"true"`
}

// AdvisoryTakenBody is the record of what one supplier advisory changed.
type AdvisoryTakenBody struct {
	Publisher  string `json:"publisher" doc:"The publisher the document names"`
	Identifier string `json:"identifier" doc:"The name the publisher gave the advisory"`
	Title      string `json:"title,omitempty" doc:"What the publisher called it"`
	Recorded   int    `json:"recorded" doc:"Claims taken from it"`
	Superseded int    `json:"superseded" doc:"Claims set aside rather than deleted: those an earlier upload of this same advisory made and this one does not, and the publisher's older claims about a product and vulnerability this advisory states newer"`
	Digest     string `json:"digest" doc:"The document's digest, which is how a revision is noticed later"`
}

func registerAdvisoryImport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "upload-supplier-advisory", Method: http.MethodPost,
		Path:    "/v1/products/{product}/supplier-advisories",
		Summary: "Upload a supplier security advisory",
		Description: "Takes one CSAF security advisory a supplier has published about their " +
			"own products, where those products are components this product ships.\n\n" +
			"A supplier's statement that its own product, at the version a build ships, is " +
			"not affected closes the finding where every route to it runs through that " +
			"product, at the next scan. Everything else that arrives is a third layer beside " +
			"the build's own claims and our decisions: shown as evidence and offered as a " +
			"prefill.\n\n" +
			"An advisory is about the versions it names. Where it says a vulnerability is " +
			"fixed in one version, that is not a statement about another, so a claim naming " +
			"a version is shown against every version of that component and offers a " +
			"prefill only at the version it named.\n\n" +
			"Uploading the same advisory again sets its earlier claims aside rather than " +
			"deleting them, so what an approval was granted on the strength of stays " +
			"readable. It is matched on the name the publisher gave it, so everything else " +
			"that publisher has issued stays standing.\n\n" +
			"A VEX document is refused here and taken by the VEX endpoint instead." +
			"\n\nAnswers 503 with `Retry-After` when the deployment is already reading as many " +
			"uploads as it takes at once; send again after that many seconds.",
		Tags: []string{"Ingest"}, DefaultStatus: http.StatusCreated,
		MaxBodyBytes: core.MaxUpload(in.Limits),
		Middlewares:  suppliedForm(api, in, finding.FromAdvisory),
	}, core.DeploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		RawBody huma.MultipartFormFiles[advisoryParts]
	}) (*struct{ Body AdvisoryTakenBody }, error) {
		var title string
		took, err := takeSupplied(ctx, core.Of(ctx, in), input.Product,
			input.RawBody.Data().Advisory, finding.FromAdvisory,
			func(r io.Reader, lim sbom.Limits) (suppliedDocument, error) {
				advisory, err := sbom.ReadAdvisory(r, lim)
				title = advisory.Title
				return suppliedDocument{
					Publisher: advisory.Publisher, Identifier: advisory.Identifier,
					SaidAt: advisory.SaidAt, Claims: advisory.Claims,
				}, err
			},
			func(from *finding.Supplied) error {
				// Both names are part of the key a later upload supersedes
				// on, and both are stored in a column of a fixed width.
				// Refused rather than shortened: two advisories agreeing for
				// the width of the column would collapse into one, and a
				// revision of one would set aside claims it has nothing to do
				// with. Taken from the document rather than from the request,
				// because a security advisory names its publisher and its own
				// identifier and is not a conforming advisory without them.
				if utf8.RuneCountInString(from.Publisher) > finding.MostPublisher {
					return huma.Error422UnprocessableEntity(fmt.Sprintf(
						"who published it is longer than the %d characters this records",
						finding.MostPublisher))
				}
				if utf8.RuneCountInString(from.Identifier) > finding.MostDocumentName {
					return huma.Error422UnprocessableEntity(fmt.Sprintf(
						"the name the publisher gave it is longer than the %d characters this records",
						finding.MostDocumentName))
				}
				return nil
			},
			func(from finding.Supplied) string {
				return "Advisory " + from.Identifier + " from " + from.Publisher
			})
		if err != nil {
			return nil, err
		}

		return &struct{ Body AdvisoryTakenBody }{Body: AdvisoryTakenBody{
			Publisher: took.From.Publisher, Identifier: took.From.Identifier,
			Title: title, Recorded: took.Recorded, Superseded: took.Superseded,
			Digest: took.From.Digest,
		}}, nil
	})
}
