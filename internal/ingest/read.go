package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// Reader turns an accepted scan into the graph it describes.
//
// It runs after the response rather than inside it. A large inventory takes
// long enough to read that holding a request open for it would tie up the
// producer's build as well as ours, and a build waiting on our parser is a
// build that fails when we are slow.
type Reader struct {
	db     *database.DB
	queue  *queue.Queue
	limits sbom.Limits
	logger *slog.Logger
	// name identifies this worker in a claim, so a job held by a process that
	// has since died can be told apart from one being worked on.
	name string
}

// NewReader returns a reader over db.
func NewReader(db *database.DB, q *queue.Queue, limits sbom.Limits, logger *slog.Logger, name string) *Reader {
	return &Reader{db: db, queue: q, limits: limits, logger: logger, name: name}
}

// Result is what reading one scan did.
type Result struct {
	ScanID       int64
	Applied      graph.Applied
	Components   int
	Suppressions int
	// What the document stated that we tolerated rather than refused. Each is
	// a number that should be stable build to build, so a change in one says
	// the producer changed — which is the thing that would otherwise be
	// silent.
	Unrooted       int
	Unversioned    int
	DanglingEdges  int
	SelfReferences int
	// ClaimsOpened and ClaimsClosed are what changed in the build's arguments
	// since its last scan. A build argues the same things night after night,
	// so both being zero is the ordinary case.
	ClaimsOpened int
	ClaimsClosed int
	// Superseded says a newer scan for this target was applied first, so this
	// one was read no further. It is not a failure: the newer picture is the
	// current one, and applying an older one over it would reopen everything
	// the newer one closed.
	Superseded bool
	// Retained says whether the documents were kept. A tagged release keeps
	// them so it can be re-scanned years later against data that did not
	// exist when it was built.
	Retained bool
}

// Once claims one scan and reads it, reporting whether there was anything to
// do.
func (r *Reader) Once(ctx context.Context) (*Result, error) {
	job, err := r.queue.Claim(ctx, r.name, queue.Parse)
	if err != nil {
		return nil, err
	}
	if job == nil {
		return nil, nil
	}

	// The claim is renewed while the read runs. A scan document measured in
	// tens of megabytes legitimately takes longer than a claim is honored for
	// with nothing heard from the worker, and without renewal a second worker
	// would take the job over and read the same document alongside this one.
	working, release := r.queue.Holding(ctx, job.ID, r.name, r.logger)
	result, err := r.read(working, job.Reference)
	taken := release()

	// What became of the scan is recorded whatever ended the reading. A
	// shutdown cancels the read, and the cancellation must not also stop the
	// job being handed back — otherwise it stays claimed by a process that
	// has gone until the claim goes stale, half an hour later.
	settled, done := queue.Settling(ctx)
	defer done()
	var ended error
	if err != nil {
		// The failure is recorded against the scan as well as the job. A
		// producer sending files nothing can read has to be visible as that,
		// rather than as a queue that keeps retrying for reasons only an
		// operator reading logs would ever see.
		//
		// Not on a cancellation, though: nothing is wrong with the document,
		// and the job goes back to be read once the process is running again.
		// Nor when the job went to another worker, which is reading the same
		// document and will record what became of it.
		if ctx.Err() == nil && taken == nil {
			if marked := r.markFailed(settled, job.Reference, err); marked != nil {
				r.logger.Error("could not record why a scan failed", "scan", job.Reference, "error", marked)
			} else if err := r.reinstate(settled, job.Reference); err != nil {
				r.logger.Error("could not bring back the scan this one had overtaken",
					"scan", job.Reference, "error", err)
			}
		}
		ended = r.queue.Fail(settled, job.ID, r.name, err)
	} else {
		ended = r.queue.Succeed(settled, job.ID, r.name)
	}
	switch {
	case errors.Is(ended, queue.ErrNoLongerHeld):
		// The claim went stale while the read ran and another worker took
		// the job over. What was stored stands; the job's ending is the other
		// worker's to write, so there is nothing to retry here — but a read
		// that outran its claim is worth knowing about.
		r.logger.Warn("a job was finished by a worker that no longer held it",
			"job", job.ID, "scan", job.Reference)
	case ended != nil:
		r.logger.Warn("could not record how a job ended", "job", job.ID, "error", ended)
		if err == nil {
			return result, ended
		}
	}
	if taken != nil {
		// The read was stopped because the job went to another worker, so the
		// error it ended with describes that rather than anything about the
		// document. There is nothing to retry and nothing to report: the job
		// is in hand elsewhere. It is logged because a claim that went stale
		// under a running read means the renewals were not landing.
		r.logger.Warn("a read was stopped because another worker took its job over",
			"job", job.ID, "scan", job.Reference)
		return nil, nil
	}
	return result, err
}

// Run reads scans until the context ends.
//
// Polling rather than listening: a notification mechanism exists on one of the
// four supported engines and nothing portable replaces it, so the queue is
// asked. The interval is what a producer waits to see its scan reflected,
// which is not a number anybody is watching a clock for.
func (r *Reader) Run(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		// Keep going while there is work, so a backlog drains at the speed of
		// the work rather than at the speed of the poll.
		for {
			result, err := r.Once(ctx)
			if err != nil {
				// A read cut short by shutdown is not a fault in the scan or
				// in this process; it is handed back and read again later.
				if ctx.Err() == nil {
					r.logger.Error("reading a scan", "error", err)
				}
				break
			}
			if result == nil {
				break
			}
			if result.Superseded {
				r.logger.Info("skipped a scan a newer one had already replaced", "scan", result.ScanID)
				continue
			}
			r.logger.Info("read a scan",
				"scan", result.ScanID, "components", result.Components,
				"nodes_opened", result.Applied.NodesOpened, "nodes_closed", result.Applied.NodesClosed,
				"edges_opened", result.Applied.EdgesOpened, "edges_closed", result.Applied.EdgesClosed,
				"suppressions", result.Suppressions,
				"claims_opened", result.ClaimsOpened, "claims_closed", result.ClaimsClosed,
				// Tolerated rather than refused. A change in any of these says
				// the producer changed.
				"unrooted", result.Unrooted, "unversioned", result.Unversioned,
				"dangling_edges", result.DanglingEdges, "self_references", result.SelfReferences,
				"documents_retained", result.Retained)
		}
		timer.Reset(interval)
	}
}

// read turns one accepted scan into stored graph.
func (r *Reader) read(ctx context.Context, reference string) (*Result, error) {
	scanID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("job names %q, which is not a scan: %w", reference, err)
	}

	scans := NewStore(r.db.DB)
	scan, err := scans.ByID(ctx, scanID)
	if err != nil {
		return nil, err
	}

	target, err := catalog.NewStore(r.db.DB).Describe(ctx, scan.TargetID)
	if err != nil {
		return nil, err
	}

	documents := NewDocuments(r.db.DB)
	held, err := documents.List(ctx, scanID)
	if err != nil {
		return nil, err
	}

	var inventory *Document
	for i := range held {
		if held[i].Kind == InventoryKind {
			inventory = &held[i]
			break
		}
	}
	if inventory == nil {
		return nil, fmt.Errorf("scan %d has no inventory to read", scanID)
	}

	// Uploads are accepted in the order they arrive and read in whatever order
	// workers pick them up, so a scan can reach here after a newer one has
	// already been applied. Applying it then would replace today's picture
	// with yesterday's and reopen everything the newer one closed — the same
	// harm the arrival check prevents at the door, arriving from behind.
	newest, err := scans.Newest(ctx, scan.TargetID)
	if err != nil {
		return nil, err
	}
	if newest != nil && newest.ID != scanID && !scan.BuiltAt.After(newest.BuiltAt) {
		return &Result{ScanID: scanID, Superseded: true}, nil
	}

	doc, err := sbom.Read(documents.Open(ctx, inventory.ID), r.limits)
	if err != nil {
		return nil, fmt.Errorf("scan %d: %w", scanID, err)
	}

	// The suppression documents are read and kept here. Applying them waits on
	// the scan, which runs later and again on a schedule — so a claim left in
	// the document it arrived in would be gone by the time anything needed it,
	// because a nightly scan's documents are discarded once read.
	//
	// Reading them now also means a document that cannot be read is a fault in
	// what the build sent, found while the producer still has the build in
	// front of them.
	claims := doc.Suppressions
	for _, held := range held {
		if held.Kind != SuppressionsKind {
			continue
		}
		read, err := sbom.ReadSuppressions(documents.Open(ctx, held.ID), r.limits)
		if err != nil {
			return nil, fmt.Errorf("scan %d: %w", scanID, err)
		}
		claims = append(claims, read...)
	}

	// A document that names no component of its own is filed against what it
	// was sent for. The product is what stands in: a root's own name and
	// version are excluded from identity and expiry anyway, so what matters is
	// only that it is stable for this variant.
	stand := graph.Described{Name: target.Product}
	applied, err := graph.NewStore(r.db.DB).Apply(ctx, scan.TargetID, scanID, doc.Snapshot(stand))
	if err != nil {
		return nil, fmt.Errorf("scan %d: %w", scanID, err)
	}

	// What the build argued is stored against the target, not against the
	// scan, because it is what the next scan run has to apply.
	claimed, err := finding.NewStore(r.db.DB).RecordClaims(ctx, scan.TargetID, scanID, claims)
	if err != nil {
		return nil, fmt.Errorf("scan %d: %w", scanID, err)
	}

	result := &Result{
		ScanID: scanID, Applied: applied,
		Components: len(doc.Components), Suppressions: len(claims),
		Unrooted:       doc.Unrooted,
		Unversioned:    doc.Unversioned,
		DanglingEdges:  doc.DanglingEdges,
		SelfReferences: doc.SelfReferences,
		ClaimsOpened:   claimed.Opened, ClaimsClosed: claimed.Closed,
		Retained: !target.Moves,
	}

	// What the inventory was made of, kept on the scan so a receipt can say
	// it. The log line said it and nothing else did, which meant an operator
	// could only learn that a document placed none of its components by going
	// and finding the line — on the screen that exists to answer what became
	// of an upload.
	components, placed := len(doc.Components), len(doc.Components)-doc.Unrooted
	if err := scans.Made(ctx, scanID, components, placed); err != nil {
		return nil, fmt.Errorf("scan %d: %w", scanID, err)
	}

	// What was just stored has to be scanned: the inventory is new, and the
	// vulnerability data has moved since whatever last looked at this target.
	// The work is left behind rather than done here because it is a different
	// job with a different rhythm — an inventory is read once and scanned
	// again and again.
	if _, err := r.queue.Add(ctx, queue.Scan, strconv.FormatInt(scan.TargetID, 10)); err != nil {
		return nil, fmt.Errorf("scan %d: leave the scanning to be done: %w", scanID, err)
	}

	// A branch is superseded by the next night's build, so what it sent is not
	// kept. A tag is not superseded by anything, and re-scanning it years from
	// now needs both what it contained and what the build had already argued
	// about its own patches.
	if target.Moves {
		if err := documents.Discard(ctx, scanID); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// markFailed records that a scan could not be read.
func (r *Reader) markFailed(ctx context.Context, reference string, cause error) error {
	scanID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		return nil
	}
	return NewStore(r.db.DB).MarkFailed(ctx, scanID, cause)
}

// reinstate brings back the scan a failed one had overtaken.
//
// An older scan read while a newer one was accepted is set aside as
// superseded, on the strength of the newer one's row alone — the newer one
// may not have been read yet. If it then cannot be read, the build is left
// showing whatever came before both: the older scan's job is done and nothing
// will read it again, and its receipt waits for a scan run that never comes.
// So once a scan has failed, the newest that still stands is read again where
// the build does not already show it and nothing is on its way to reading it.
func (r *Reader) reinstate(ctx context.Context, reference string) error {
	failedID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		return nil
	}
	scans := NewStore(r.db.DB)
	failed, err := scans.ByID(ctx, failedID)
	if err != nil {
		return err
	}
	// The failed one is no longer accepted, so this is what stands in its
	// place — or nothing, where it was the only scan.
	newest, err := scans.Newest(ctx, failed.TargetID)
	if err != nil || newest == nil {
		return err
	}

	var shown int64
	if err := r.db.NewSelect().
		TableExpr("target AS t").
		ColumnExpr("COALESCE(t.last_scan_id, 0)").
		Where("t.id = ?", failed.TargetID).
		Scan(ctx, &shown); err != nil {
		return fmt.Errorf("read what the build shows: %w", err)
	}
	if shown == newest.ID {
		return nil
	}

	pending, err := r.db.NewSelect().Model((*queue.Job)(nil)).
		Where("kind = ?", queue.Parse).
		Where("reference = ?", strconv.FormatInt(newest.ID, 10)).
		Where("state IN (?)", bun.List([]queue.State{queue.Pending, queue.Running})).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("read whether the scan is still to be read: %w", err)
	}
	if pending > 0 {
		return nil
	}
	if _, err := r.queue.Add(ctx, queue.Parse, strconv.FormatInt(newest.ID, 10)); err != nil {
		return err
	}
	r.logger.Info("reading an overtaken scan again, because the one that overtook it failed",
		"scan", newest.ID, "failed", failedID)
	return nil
}
