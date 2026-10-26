// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// UploadKindBody is one kind of upload a build takes.
type UploadKindBody struct {
	Type   core.UploadType   `json:"type" doc:"The kind of upload: an SBOM, a static analysis run in SARIF, a VEX document, or a supplier security advisory"`
	Total  int               `json:"total" doc:"How many the kind's own list holds. A VEX document or supplier advisory turned away is listed and counted. An SBOM or static analysis run turned away is not, because only the last refusal of each is kept"`
	Latest *UploadLatestBody `json:"latest,omitempty" doc:"The newest upload of this kind. Absent where none has arrived"`
}

// UploadLatestBody is what became of the newest upload of one kind.
type UploadLatestBody struct {
	ReceivedAt string            `json:"received_at" format:"date-time" doc:"When it arrived"`
	Status     core.UploadStatus `json:"status" doc:"What became of it: still being read or applied, completed, failed after it was accepted, or turned away when it arrived"`
	Reason     string            `json:"reason,omitempty" doc:"Why it failed or was turned away, as the sender was told"`
}

// UploadsOutput is every kind of upload one build takes, with the newest of
// each.
type UploadsOutput struct {
	Body struct {
		Items []UploadKindBody `json:"items" doc:"One per kind the caller may read, in a fixed order"`
	}
}

func registerUploads(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-uploads", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/uploads",
		Summary: "List upload types and their status",
		Description: "Returns each kind of upload a build takes, with how many are held and what " +
			"became of the newest: SBOMs and static analysis runs sent to this build, and VEX " +
			"documents and supplier advisories uploaded to its product. Each kind's own list " +
			"carries the uploads themselves.\n\n" +
			"A kind the caller may not read is left out. An API key reads the SBOMs and the " +
			"static analysis runs of a build it may upload to. A person reads static analysis " +
			"runs where they read internal findings in the product.",
		Tags: []string{"Ingest"},
	}, core.AnySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
	}) (*UploadsOutput, error) {
		subject, named, err := core.ReadableBuild(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		out := &UploadsOutput{}
		out.Body.Items = []UploadKindBody{}

		target, err := catalog.NewStore(in.DB.DB).ExistingTarget(ctx, named.StreamID, named.VariantID)
		switch {
		case errors.Is(err, catalog.ErrNotFound):
			// Declared, and nothing has ever been sent to it.
			out.Body.Items = append(out.Body.Items, kindOf(ingest.UploadSBOM, 0))
			if series.ReadsReceipts(subject, named.ProductID, analysis.OpensAt) {
				out.Body.Items = append(out.Body.Items, kindOf(ingest.UploadSARIF, 0))
			}
		case err != nil:
			return nil, core.WentWrong(in.Logger, "that build could not be looked up", err)
		default:
			sbom, err := sbomUploads(ctx, in, subject, target.ID)
			if errors.Is(err, access.ErrDenied) {
				return nil, core.NothingScannedThere()
			}
			if err != nil {
				return nil, core.WentWrong(in.Logger, "the SBOMs could not be read", err)
			}
			out.Body.Items = append(out.Body.Items, sbom)
			sarif, err := sarifUploads(ctx, in, subject, named.ProductID, target.ID)
			switch {
			case errors.Is(err, access.ErrDenied):
			case err != nil:
				return nil, core.WentWrong(in.Logger, "the static analysis runs could not be read", err)
			default:
				out.Body.Items = append(out.Body.Items, sarif)
			}
		}

		for _, each := range []struct {
			kind   ingest.UploadType
			source string
		}{
			{ingest.UploadVEX, finding.FromVex}, {ingest.UploadAdvisory, finding.FromAdvisory},
		} {
			held, total, err := finding.NewStore(in.DB.DB).Uploads(ctx, subject, named.ProductID,
				each.source, 1, 0)
			switch {
			case errors.Is(err, access.ErrDenied):
				continue
			case err != nil:
				return nil, core.WentWrong(in.Logger, "the documents could not be read", err)
			}
			body := kindOf(each.kind, total)
			if len(held) > 0 {
				// A document is recorded as it is taken or turned away, so
				// nothing of one is still being read.
				newest := held[0]
				body.Latest = latestOf(newest.ReceivedAt, ingest.UploadCompleted, "")
				if newest.Status == finding.UploadTurnedAway {
					body.Latest = latestOf(newest.ReceivedAt, ingest.UploadRefused,
						core.OrBlank(newest.Reason))
				}
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}

// kindOf is one kind of upload, with how many of it are held.
func kindOf(kind ingest.UploadType, total int) UploadKindBody {
	return UploadKindBody{Type: core.UploadType(kind), Total: total}
}

// latestOf is the newest upload of a kind.
func latestOf(at time.Time, status ingest.UploadStatus, reason string) *UploadLatestBody {
	return &UploadLatestBody{
		ReceivedAt: core.Stamp(at), Status: core.UploadStatus(status), Reason: reason,
	}
}

// sbomUploads is the SBOMs sent to a build, with the newest of them: the
// newest receipt, or the upload turned away after it.
func sbomUploads(ctx context.Context, in core.Deps, subject access.Subject,
	targetID int64) (UploadKindBody, error) {

	store := ingest.NewStore(in.DB.DB)
	receipts, total, err := store.Receipts(ctx, subject, targetID, 1, 0)
	if err != nil {
		return UploadKindBody{}, err
	}
	body := kindOf(ingest.UploadSBOM, total)
	var takenAt time.Time
	if len(receipts) > 0 {
		r := receipts[0]
		takenAt = r.Scan.ReceivedAt
		body.Latest = latestOf(takenAt, map[ingest.Progress]ingest.UploadStatus{
			ingest.Reading: ingest.UploadInProgress, ingest.Scanning: ingest.UploadInProgress,
			ingest.Scanned: ingest.UploadCompleted, ingest.Refused: ingest.UploadFailed,
		}[r.State], r.Failure)
	}
	refused, err := store.LastRefusal(ctx, subject, targetID)
	if err != nil {
		return UploadKindBody{}, err
	}
	if refused != nil {
		body.Latest = refusedAfter(body.Latest, takenAt, refused.At, refused.Reason)
	}
	return body, nil
}

// sarifUploads is the static analysis runs sent to a build, with the newest of
// them: the newest run, or the upload turned away after it.
func sarifUploads(ctx context.Context, in core.Deps, subject access.Subject,
	productID, targetID int64) (UploadKindBody, error) {

	store := series.NewStore(in.DB.DB)
	sent, total, err := store.Receipts(ctx, subject, productID, targetID,
		kind.Analysis, analysis.OpensAt, 1, 0)
	if err != nil {
		return UploadKindBody{}, err
	}
	body := kindOf(ingest.UploadSARIF, total)
	var takenAt time.Time
	if len(sent) > 0 {
		s := sent[0]
		takenAt = s.ReceivedAt
		body.Latest = latestOf(takenAt, map[series.Status]ingest.UploadStatus{
			series.Queued: ingest.UploadInProgress, series.Waiting: ingest.UploadInProgress,
			series.Applied: ingest.UploadCompleted, series.Superseded: ingest.UploadCompleted,
			series.Failed: ingest.UploadFailed,
		}[series.Status(s.Status)], s.Failure)
	}
	refusals, err := store.RefusalsOf(ctx, targetID, kind.Analysis)
	if err != nil {
		return UploadKindBody{}, err
	}
	if len(refusals) > 0 {
		body.Latest = refusedAfter(body.Latest, takenAt, refusals[0].At, refusals[0].Reason)
	}
	return body, nil
}

// refusedAfter is the newer of the newest upload taken, at takenAt, and one
// turned away at a moment.
func refusedAfter(latest *UploadLatestBody, takenAt, at time.Time, reason string) *UploadLatestBody {
	if latest != nil && !at.After(takenAt) {
		return latest
	}
	return latestOf(at, ingest.UploadRefused, reason)
}
