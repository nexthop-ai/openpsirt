package httpapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/trail"
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
	Superseded int    `json:"superseded" doc:"Claims from an earlier upload of this same advisory, set aside rather than deleted"`
	Digest     string `json:"digest" doc:"The document's digest, which is how a revision is noticed later"`
}

func registerAdvisoryImport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "upload-supplier-advisory", Method: http.MethodPost,
		Path:    "/v1/products/{product}/supplier-advisories",
		Summary: "Upload a supplier security advisory",
		Description: "Takes one CSAF security advisory a supplier has published about their " +
			"own products, where those products are components this product ships.\n\n" +
			"Nothing is applied. What arrives is a third layer beside the build's own " +
			"claims and our decisions: shown as evidence, offered as a prefill, and never " +
			"standing as our judgment by itself.\n\n" +
			"An advisory is about the versions it names. Where it says a vulnerability is " +
			"fixed in one version, that is not a statement about another, so a claim naming " +
			"a version is shown against every version of that component and offers a " +
			"prefill only at the version it named.\n\n" +
			"Uploading the same advisory again sets its earlier claims aside rather than " +
			"deleting them, so what an approval was granted on the strength of stays " +
			"readable. It is matched on the name the publisher gave it, so everything else " +
			"that publisher has issued stays standing — which is the difference from a VEX " +
			"document, where a publisher's whole statement set is replaced at once.\n\n" +
			"A VEX document is refused here and taken by the VEX endpoint instead.",
		Tags: []string{"Ingest"}, DefaultStatus: http.StatusCreated,
		// A published document is somebody else's output arriving over a link
		// we do not control, exactly as a scan file is, and this is the first
		// place it can be stopped. Without it huma's default does not apply —
		// it is not consulted for multipart at all — so the whole body is
		// spooled to disk before any of this endpoint's own checks run.
		MaxBodyBytes: maxUpload(in.Limits),
		Middlewares:  huma.Middlewares{boundedForm(api, maxUpload(in.Limits))},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		RawBody huma.MultipartFormFiles[advisoryParts]
	}) (*struct{ Body AdvisoryTakenBody }, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, input.Product)
		if err != nil {
			return nil, absent(in.Logger, err, "that product could not be looked up", noSuchProduct)
		}

		file := input.RawBody.Data().Advisory
		var advisory sbom.Advisory
		digest, err := uploaded(in, file, func(r io.Reader) error {
			var err error
			advisory, err = sbom.ReadAdvisory(r, in.Limits.OrDefault())
			return err
		})
		if err != nil {
			return nil, err
		}

		// Both names are part of the key a later upload supersedes on, and
		// both are stored in a column of a fixed width. Refused rather than
		// shortened: two advisories agreeing for the width of the column would
		// collapse into one, and a revision of one would set aside claims it
		// has nothing to do with.
		//
		// Taken from the document rather than from the request, because a
		// security advisory names its publisher and its own identifier and is
		// not a conforming advisory without them.
		if utf8.RuneCountInString(advisory.Publisher) > finding.MostPublisher {
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
				"who published it is longer than the %d characters this records",
				finding.MostPublisher))
		}
		if utf8.RuneCountInString(advisory.Identifier) > finding.MostDocumentName {
			return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
				"the name the publisher gave it is longer than the %d characters this records",
				finding.MostDocumentName))
		}

		statements := make([]finding.Statement, 0, len(advisory.Claims))
		for _, one := range advisory.Claims {
			for _, at := range one.Targets {
				statements = append(statements, finding.Statement{
					Vulnerability: one.Vulnerability,
					Purl:          at.Purl,
					About:         versionNamed(at),
					Component:     componentNamed(at),
					Status:        string(one.Status),
					Justification: one.Justification,
					Statement:     one.Statement,
				})
			}
		}
		var recorded, superseded int
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
			var err error
			recorded, superseded, err = finding.NewStore(tx).RecordStatements(ctx, by,
				product.ID, finding.Supplied{
					Source:     finding.FromAdvisory,
					Identifier: advisory.Identifier,
					Publisher:  advisory.Publisher,
					Document:   file.Filename,
					Digest:     digest,
				}, statements)
			if err != nil {
				return asked(in.Logger, err)
			}
			if err := noted(ctx, tx, trail.Setting, "Advisory "+advisory.Identifier+
				" from "+advisory.Publisher, nil, trail.Said(file.Filename, true)); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}

		return &struct{ Body AdvisoryTakenBody }{Body: AdvisoryTakenBody{
			Publisher: advisory.Publisher, Identifier: advisory.Identifier,
			Title: advisory.Title, Recorded: recorded, Superseded: superseded,
			Digest: digest,
		}}, nil
	})
}
