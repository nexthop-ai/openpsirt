// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// ReceiptBody is the record of one upload.
type ReceiptBody struct {
	ScanID     int64  `json:"scan_id" doc:"The scan this upload became"`
	Serial     string `json:"serial,omitempty" doc:"The identity the inventory carries for itself"`
	BuiltAt    string `json:"built_at,omitempty" doc:"The build time the producer states, or the time the upload arrived where it states none"`
	ReceivedAt string `json:"received_at" doc:"The moment it arrived here"`
	State      string `json:"state" enum:"reading,scanning,scanned,failed" doc:"The state it has reached"`
	// Failure is the producer's own text back at them — what could not be read
	// and where. It is not a fault in this deployment, so it is reported
	// rather than logged away.
	Failure string `json:"failure,omitempty" doc:"The reason it could not be used, where it could not"`
	// Caution qualifies the answer rather than saying there is none, so it is
	// reported beside a scan that succeeded rather than instead of one.
	Caution string `json:"caution,omitempty" doc:"The scanner's own words while still succeeding — a qualification on what it found rather than a failure. Usually empty: the scan runs over an inventory written from what is held here, so most of what a scanner would warn about a producer's document it has no grounds to say about ours"`
	// Opened is what the run covering this upload changed, counted as
	// issues at components rather than as places. Absent where no run has
	// covered it yet, and absent on an upload whose run was already
	// reported against a newer one: a run covers a build rather than an
	// upload.
	//
	// Pointers, because a run that changed nothing and an upload whose
	// numbers are reported on another receipt are different answers and zero
	// is only the first of them. Sent as a number they were the same value,
	// and the screen drew both as a dash — which reads as "this upload opened
	// nothing" against an upload nothing was read from.
	Opened *int `json:"opened,omitempty" doc:"Issues this run found that were not open before. Absent where this upload's run is reported against a newer one, or where none has covered it yet"`
	Closed *int `json:"closed,omitempty" doc:"Issues that were open and are not any more. Absent for the same reasons as the count beside it"`
	// Sent is the documents the upload was made of. It outlives the files
	// themselves: a branch build's contents are let go once they have been
	// read, and this still says what arrived and what its bytes hashed to.
	Sent []SentBody `json:"sent,omitempty" doc:"The documents this upload was made of"`
	// Components and Placed are what the inventory described, and how much of
	// it anything said the position of. Absent until it has been read.
	//
	// The pair is what says whether an inventory is a graph or a list. A
	// document that places none of its components produces findings that are
	// each correct and cannot answer "why is this here" about any of them —
	// and nothing else on this screen tells the two apart.
	Components *int `json:"components,omitempty" doc:"The number of components the inventory described"`
	Placed     *int `json:"placed,omitempty" doc:"The number of them something placed in the graph"`
	// Inventory is what this upload made of the inventory the one before it
	// described. A fact about the documents rather than about what is wrong
	// with them, which is why a key that reads no findings still gets it:
	// the pipeline that sent the document is who the answer is for.
	//
	// Absent on the first upload a build ever had read, which is a picture
	// rather than a change to one, and absent until this one has been read.
	Inventory *InventoryBody `json:"inventory,omitempty" doc:"What this upload changed about the build's inventory. Absent on the first upload read for a build, and until this one has been read"`
	// Measured is what the run answering *this* upload was made with,
	// rather than what the newest run was. On every receipt the run
	// answers, unlike opened and closed: the versions are a property of
	// the run rather than a change it made, and a page spanning a scanner
	// upgrade or a vulnerability database that stopped moving is exactly
	// what somebody reads this screen to notice.
	Measured *core.MeasuredBody `json:"measured,omitempty" doc:"The tools the run answering this upload was measured with. Absent until a run has covered it"`
	// RunID is the run that answered this upload, so what it did can be
	// asked for. On every receipt that run answers, like the versions beside
	// it — the counts above are the thing that belongs to one upload only.
	RunID int64 `json:"run_id,omitempty" doc:"The run that answered this upload. Absent until one has"`
}

// InventoryBody is what one upload changed about what a build is made of.
//
// Counted by name rather than by component: an upgrade is one dependency that
// moved, and counted as components it would be one arrival and one departure.
// A name shipped at two versions at once is one entry however many of them
// move.
type InventoryBody struct {
	Added   int `json:"added" doc:"Names this upload's inventory holds and the one before it did not"`
	Removed int `json:"removed" doc:"Names the one before it held and this one does not"`
	Changed int `json:"changed" doc:"Names both hold at a different set of versions"`
}

// SentBody is one document an upload was made of, as a record rather than as
// contents.
//
// The hash is here so a build can check a file it is asked to send again
// against the one that was read. That is the whole point of keeping it: a
// re-parse means asking for the file back, and without something to compare
// against, the second copy is taken on trust.
type SentBody struct {
	// DocumentID is what to ask for to read the bytes back. Present
	// whether or not they are still here, because it is also what a caller
	// names to be told the contents were let go rather than guessing from a
	// 404.
	DocumentID int64  `json:"document_id" doc:"The name that reads this document back"`
	Kind       string `json:"kind" enum:"inventory,suppressions" doc:"The kind of document"`
	SizeBytes  int64  `json:"size_bytes" doc:"Its size"`
	Hash       string `json:"hash" doc:"SHA-256 of the bytes as they arrived"`
	// Held says the contents are still here. A tagged release keeps them,
	// because re-scanning it years from now needs what it contained; a branch
	// build's are let go, because the next night supersedes them.
	Held bool `json:"held" doc:"Whether the contents are still kept"`
}

// ReceiptsOutput is a page of what has been filed against a build.
type ReceiptsOutput struct {
	Body struct {
		Items []ReceiptBody `json:"items"`
		Total int           `json:"total"`
		// MeasuredAgainst describes the build's last finished run rather than
		// any one upload, which is why it sits beside the page instead of on
		// each row.
		MeasuredAgainst *core.MeasuredBody `json:"measured_against,omitempty" doc:"The tools the last completed run was measured with"`
	}
}

func registerReceipts(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-scans", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/scans",
		Summary: "List uploaded scans and their status",
		Description: "Returns uploads newest first, each with its state: `reading` (accepted, not " +
			"yet parsed), `scanning` (parsed, vulnerability scan pending), `scanned` (complete), " +
			"or `failed` with the reason.\n\n" +
			"Because uploads return 202 before parsing, this is how a build pipeline finds out " +
			"whether its SBOM was usable. An API key sees only the uploads it sent itself.",
		Tags: []string{"Ingest"},
	}, core.AnySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number returned"`
		Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*ReceiptsOutput, error) {
		subject, err := core.Requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}

		// Resolved and authorized together, so a build somebody may not reach
		// reads as one that was never declared.
		names := catalog.NewStore(in.DB.DB)
		named, err := names.LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, core.Undeclared(in.Logger, err, "that build could not be looked up")
		}

		if subject.Kind == access.Pipeline &&
			!subject.MaySend(named.ProductID, named.StreamID, named.VariantID) {
			return nil, huma.Error403Forbidden("not authorized")
		}

		target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
		out := &ReceiptsOutput{}
		out.Body.Items = []ReceiptBody{}
		switch {
		case errors.Is(err, catalog.ErrNotFound):
			// Declared, and nothing has ever been filed against it.
			return out, nil
		case err != nil:
			return nil, core.WentWrong(in.Logger, "that build could not be looked up", err)
		}

		// A key sees the receipts for what it sent and nothing more, which
		// the store decides from the subject.
		scans := ingest.NewStore(in.DB.DB)
		receipts, total, err := scans.Receipts(ctx, subject, target.ID, input.Limit, input.Offset)
		switch {
		case errors.Is(err, access.ErrDenied):
			// The answer a build nobody declared gets. A 500 here against a
			// 404 for a stranger says which builds exist, one name at a time
			// — and the reach that meets it is a case collaborator, who holds
			// nothing on the product and may reach the one finding they were
			// brought in on.
			return nil, core.NothingScannedThere()
		case err != nil:
			return nil, core.WentWrong(in.Logger, "the scans could not be read", err)
		}
		// The change each run made, in one pair of statements for the page. A
		// scan that says only "scanned" leaves the reason to read it — what it
		// did — to a second screen.
		runs := make([]int64, 0, len(receipts))
		for _, r := range receipts {
			if r.RunID != nil {
				runs = append(runs, *r.RunID)
			}
		}
		changed, err := finding.NewStore(in.DB.DB).Changes(ctx, subject, target.ID, runs)
		switch {
		case errors.Is(err, access.ErrDenied):
			// The receipts above were this caller's to read, so a refusal here
			// is of the counts alone: a pipeline key reading back its own
			// uploads reads no findings, and its receipts carry no counts.
			changed = nil
		case err != nil:
			return nil, core.WentWrong(in.Logger, "what the scans changed could not be read", err)
		}

		// The contents of each upload, for the page at once. The record
		// survives the contents, so a branch build reads back as what it sent
		// rather than as nothing, which is indistinguishable from an upload
		// that stored nothing at all.
		ids := make([]int64, 0, len(receipts))
		for _, r := range receipts {
			ids = append(ids, r.Scan.ID)
		}
		sent, err := ingest.NewDocuments(in.DB.DB).Sent(ctx, ids)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what the scans arrived with could not be read", err)
		}

		// What each upload made of the build's inventory, for the page at
		// once. Worked out from the intervals the scan already wrote rather
		// than stored beside them: the rows that answer it are the rows
		// applying the scan produced.
		deltas, err := graph.NewStore(in.DB.DB).Deltas(ctx, subject, target.ID, ids)
		switch {
		case errors.Is(err, access.ErrDenied):
			return nil, core.NothingScannedThere()
		case err != nil:
			return nil, core.WentWrong(in.Logger,
				"what the scans changed about the inventory could not be read", err)
		}

		for _, r := range receipts {
			body := ReceiptBody{
				ScanID:     r.Scan.ID,
				Serial:     r.Scan.Serial,
				BuiltAt:    core.Stamp(r.Scan.BuiltAt),
				ReceivedAt: core.Stamp(r.Scan.ReceivedAt),
				State:      string(r.State),
				Failure:    r.Failure,
				Caution:    r.Caution,
			}
			// Only where the counts are this reader's to have. A reader who
			// reaches the receipts and reads no findings in the product — a
			// pipeline key is one — is told nothing about what a run changed,
			// which is not the same as being told it changed nothing.
			if r.RunID != nil {
				if change, counted := changed[*r.RunID]; counted {
					opened, closed := change.Opened, change.Closed
					body.Opened, body.Closed = &opened, &closed
				}
			}
			body.Components, body.Placed = r.Scan.Components, r.Scan.Placed
			// Only for an upload that has been read. Until then there is no
			// inventory to have changed anything, and a run of zeros would
			// say this one changed nothing.
			if r.Scan.Components != nil {
				if moved, answered := deltas[r.Scan.ID]; answered {
					body.Inventory = &InventoryBody{
						Added: moved.Added, Removed: moved.Removed, Changed: moved.Changed,
					}
				}
			}
			if r.Measured != nil {
				body.RunID = r.Measured.ID
				body.Measured = &core.MeasuredBody{
					Scanner: r.Measured.Scanner, ScannerVersion: r.Measured.ScannerVersion,
					DatabaseVersion: r.Measured.DatabaseVersion, RanHere: r.Measured.RanHere,
				}
				if r.Measured.FinishedAt != nil {
					body.Measured.RanAt = core.Stamp(*r.Measured.FinishedAt)
				}
			}
			for _, doc := range sent[r.Scan.ID] {
				body.Sent = append(body.Sent, SentBody{
					DocumentID: doc.ID,
					Kind:       string(doc.Kind), SizeBytes: doc.SizeBytes,
					Hash: doc.ContentHash, Held: doc.DiscardedAt == nil,
				})
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		out.Body.Total = total

		// The tools those numbers were arrived at with. Read separately
		// because it describes the build rather than any upload, and absent
		// rather than invented where nothing has finished running yet. Not for
		// a key, which sees its own uploads and nothing more: a key that has
		// uploaded nothing would otherwise still learn when the build was last
		// scanned and with what, which is a report about the product rather
		// than an acknowledgement of its own upload.
		if subject.Kind == access.Pipeline {
			return out, nil
		}
		last, err := finding.NewStore(in.DB.DB).LatestRun(ctx, subject, target.ID)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the last run could not be read", err)
		}
		if last != nil {
			out.Body.MeasuredAgainst = &core.MeasuredBody{
				Scanner:         last.Scanner,
				ScannerVersion:  last.ScannerVersion,
				DatabaseVersion: last.DatabaseVersion,
			}
			if last.FinishedAt != nil {
				out.Body.MeasuredAgainst.RanAt = core.Stamp(*last.FinishedAt)
			}
		}
		return out, nil
	})
}
