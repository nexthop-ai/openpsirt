package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// registerRetained reads back a document a build sent.
//
// **Retaining it was the point.** A tag's documents are kept precisely so a
// release can be re-scanned later, and nothing returned one — so
// "send me the SBOM you scanned for v2.4" was answered from the build system,
// which is the copy that may have moved since.
func registerRetained(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "fetch-scan-document", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/scans/{scan}/documents/{document}",
		Summary: "Fetch a scan document",
		Description: "Returns the bytes as they arrived, byte for byte: the hash on the receipt " +
			"is over what comes back from here, so a copy can be checked against what was " +
			"actually read.\n\n" +
			"**A tagged release keeps its documents and a branch build does not.** A nightly " +
			"build's contents are let go once they have been read, because keeping them costs " +
			"storage that grows with the calendar; a tag's are kept because re-scanning it " +
			"years from now needs both what it contained and what the build had already argued " +
			"about its own patches. One that was let go answers **410**, which says the bytes " +
			"went on purpose — the record of what arrived is still on the receipt.\n\n" +
			"Named through the scan it belongs to rather than on its own, so whoever may read " +
			"the receipt may read what it describes and there is one rule rather than two.",
		Tags: []string{"Ingest"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product  string `path:"product"`
		Stream   string `path:"stream"`
		Variant  string `path:"variant"`
		Scan     int64  `path:"scan" doc:"The upload, as the receipt names it"`
		Document int64  `path:"document" doc:"Which of its documents, as the receipt names it"`
	}) (*huma.StreamResponse, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		names := catalog.NewStore(in.DB.DB)
		named, err := names.LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, noSuchProduct()
		}
		if subject.Kind == access.Pipeline &&
			!subject.MaySend(named.ProductID, named.StreamID, named.VariantID) {
			return nil, huma.Error403Forbidden("not authorized")
		}
		target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
		if err != nil {
			return nil, nothingScannedThere()
		}
		// The scan has to be this build's, and one this caller may see: a key
		// reads back what it sent and nothing more, which is the rule the
		// receipts list applies. Asked of the store rather than here, so the
		// two endpoints cannot come to differ about it.
		var sender string
		if subject.Kind == access.Pipeline {
			sender = subject.Identity
		}
		if _, err := ingest.NewStore(in.DB.DB).Of(ctx, subject, target.ID,
			input.Scan, sender); err != nil {
			return nil, huma.Error404NotFound("no such scan on this build")
		}

		documents := ingest.NewDocuments(in.DB.DB)
		doc, err := documents.Held(ctx, input.Scan, input.Document)
		switch {
		case errors.Is(err, ingest.ErrLetGo):
			return nil, huma.Error410Gone("the contents of that document were let go once it " +
				"had been read, which is what happens to a branch build's. The receipt still " +
				"says what arrived and what its bytes hashed to")
		case errors.Is(err, ingest.ErrNoDocument):
			return nil, huma.Error404NotFound("no such document on that scan")
		case err != nil:
			return nil, wentWrong(in.Logger, "that document could not be read", err)
		}

		body := documents.Open(ctx, doc.ID)
		return &huma.StreamResponse{Body: func(hc huma.Context) {
			// The bytes as they arrived, and named as such. Not parsed and not
			// re-serialized: the hash on the receipt is over what was
			// received, so anything this rewrote would fail the one check the
			// hash exists for.
			hc.SetHeader("Content-Type", "application/octet-stream")
			hc.SetHeader("Content-Disposition", "attachment; filename=\""+
				string(doc.Kind)+"-"+strconv.FormatInt(doc.ID, 10)+".json\"")
			hc.SetHeader("Content-Length", strconv.FormatInt(doc.SizeBytes, 10))
			hc.SetHeader("Cache-Control", "private, no-store")
			hc.SetStatus(http.StatusOK)
			if _, err := io.Copy(hc.BodyWriter(), body); err != nil {
				in.Logger.ErrorContext(ctx, "sending a retained document stopped part way",
					"error", err, "document", doc.ID)
			}
		}}, nil
	})
}
