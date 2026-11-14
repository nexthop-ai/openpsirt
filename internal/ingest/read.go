// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/chunked"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
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
	// told carries an applied inventory to whoever works out whether anybody
	// should hear about what it changed.
	//
	// A hook rather than a call, for the reason the scanner's is one: reading
	// a document has no business knowing how anybody is notified, and the
	// package that notifies reads what has been ingested, so reaching it from
	// here would close a cycle between the two.
	told func(context.Context, Stored)
	// beforeApply runs between the parse and the transaction that applies
	// it, which is where a newer scan can overtake this one. Set by tests.
	beforeApply func()
}

// Stored is an inventory that has been applied, as the fact that something
// happened to a build.
//
// Two identifiers and nothing worked out: what the upload changed is read
// where the decision to say anything is made, so that a policy about what is
// worth telling somebody is in one place rather than half here.
type Stored struct {
	BuildID int64
	ScanID  int64
}

// NewReader returns a reader over db.
func NewReader(db *database.DB, q *queue.Queue, limits sbom.Limits, logger *slog.Logger, name string) *Reader {
	return &Reader{db: db, queue: q, limits: limits, logger: logger, name: name}
}

// Telling is the instruction for an inventory that has been applied.
//
// Left unset a reader tells nobody, which is what every test and every
// single-purpose invocation wants; the deployment wires it once.
func (r *Reader) Telling(tell func(context.Context, Stored)) *Reader {
	r.told = tell
	return r
}

// Result is what reading one scan did.
type Result struct {
	ScanID       int64
	Applied      graph.Applied
	Components   int
	Suppressions int
	// Unrooted is what the document stated that we tolerated rather than
	// refused. Each is a number that should be stable build to build, so a
	// change in one says the producer changed — which is the thing that
	// would otherwise be silent.
	Unrooted       int
	Unversioned    int
	DanglingEdges  int
	FileReferences int
	SelfReferences int
	// ClaimsOpened and ClaimsClosed are what changed in the build's arguments
	// since its last scan. A build argues the same things night after night,
	// so both being zero is the ordinary case.
	ClaimsOpened int
	ClaimsClosed int
	// ClaimsUnstated counts what this scan's format could not have restated,
	// so it was carried forward rather than read as withdrawn.
	ClaimsUnstated int
	// Superseded says a newer scan for this build was applied first, so this
	// one was read no further. It is not a failure: the newer picture is the
	// current one, and applying an older one over it would reopen everything
	// the newer one closed.
	Superseded bool
	// AlreadyApplied says the build already shows this scan, so the read
	// changed nothing. A job runs again where its worker stopped after the
	// apply committed and before the job was marked done; the branch's
	// documents are gone by then, and the scan is applied either way.
	AlreadyApplied bool
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

	// A failure is recorded against the scan as well as the job. A producer
	// sending files nothing can read has to be visible as that, rather than
	// as a queue that keeps retrying for reasons only an operator reading
	// logs would ever see. Passed as the recovery rather than done here,
	// because it is the one part of settling a job the two workers differ on:
	// it must not run on a cancellation, where nothing is wrong with the
	// document, nor where the job went to another worker, which is reading
	// the same document and will record what became of it.
	//
	// The scan it overtook is brought back only once this job will not run
	// again. A job with attempts left is retried, and a retry that succeeds
	// applies this scan. An older scan read in between is applied first and
	// reopens what this one closes.
	last := job.Attempts >= job.MaxAttempts
	ending := r.queue.Settle(ctx, job, r.name, "scan", r.logger, err, taken,
		func(settled context.Context) error {
			// Logged here rather than handed back, because the two failures
			// are different things an operator acts on differently and the
			// queue has no words for either.
			if marked := r.markFailed(settled, job.Reference, err); marked != nil {
				// What it sent is kept, because the failure is not recorded.
				r.logger.Error("could not record why a scan failed",
					"scan", job.Reference, "error", marked)
				return nil
			}
			if !last {
				return nil
			}
			if back := r.reinstate(settled, job.Reference); back != nil {
				r.logger.Error("could not bring back the scan this one had overtaken",
					"scan", job.Reference, "error", back)
			}
			// Nothing reads a refused scan again: a re-send of the same bytes
			// writes them anew, and a job put back is told to ask for them.
			// One that failed for a fault of this server keeps them, since a
			// job put back can still read them; the build's next applied scan
			// lets go of them.
			if refusal.In(err) {
				r.letGoFailed(settled, job.Reference)
			}
			return nil
		})
	if ending.HandedOver {
		return nil, nil
	}
	return result, ending.Err
}

// betweenReads is how long an idle reader waits before asking for work again
// where the caller says nothing. Short: it is what a producer waits to see its
// scan reflected.
const betweenReads = 5 * time.Second

// Run reads scans until the context ends.
//
// Polling rather than listening: a notification mechanism exists on one of the
// four supported engines and nothing portable replaces it, so the queue is
// asked. The interval is what a producer waits to see its scan reflected,
// which is not a number anybody is watching a clock for.
func (r *Reader) Run(ctx context.Context, interval time.Duration) {
	background.Drain(ctx, interval, betweenReads, func(ctx context.Context) (bool, error) {
		result, err := r.Once(ctx)
		if err != nil || result == nil {
			return false, err
		}
		if result.Superseded {
			r.logger.Info("skipped a scan a newer one had already replaced", "scan", result.ScanID)
			return true, nil
		}
		if result.AlreadyApplied {
			r.logger.Info("skipped a scan the build already shows", "scan", result.ScanID)
			return true, nil
		}
		r.logger.Info("read a scan",
			"scan", result.ScanID, "components", result.Components,
			"nodes_opened", result.Applied.NodesOpened, "nodes_closed", result.Applied.NodesClosed,
			"edges_opened", result.Applied.EdgesOpened, "edges_closed", result.Applied.EdgesClosed,
			"image_versions_opened", result.Applied.VersionsOpened,
			"image_versions_closed", result.Applied.VersionsClosed,
			"suppressions", result.Suppressions,
			"claims_opened", result.ClaimsOpened, "claims_closed", result.ClaimsClosed,
			"claims_unstated", result.ClaimsUnstated,
			// Tolerated rather than refused. A change in any of these says
			// the producer changed.
			"unrooted", result.Unrooted, "unversioned", result.Unversioned,
			"dangling_edges", result.DanglingEdges, "file_references", result.FileReferences,
			"self_references", result.SelfReferences,
			"documents_retained", result.Retained)
		return true, nil
	}, func(err error) { r.logger.Error("reading a scan", "error", err) })
}

// read turns one accepted scan into stored graph.
func (r *Reader) read(ctx context.Context, reference string) (*Result, error) {
	scanID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("job names %q, which is not a scan: %w", reference, err)
	}
	result, err := r.readScan(ctx, scanID)
	if err == nil {
		return result, nil
	}
	// A newer scan applied while this one was read lets go of what this one
	// sent, so the read fails part way, and the scan is recorded as
	// overtaken. Any other failure is the scan's own: a refusal of what the
	// sender sent is told on its receipt whether or not a newer scan has
	// since applied.
	var sentLetGo letGoError
	if !errors.Is(err, chunked.ErrReleased) && !errors.As(err, &sentLetGo) {
		return nil, err
	}
	if scan, found := NewStore(r.db.DB).ByID(ctx, scanID); found == nil {
		if last, read := lastApplied(ctx, r.db.DB, scan.BuildID); read == nil && last > scanID {
			return &Result{ScanID: scanID, Superseded: true}, nil
		}
	}
	return nil, err
}

// letGoError refuses a scan whose documents were let go before it was read.
type letGoError struct{ scanID int64 }

func (e letGoError) Error() string {
	return fmt.Sprintf("what scan %d sent was let go after its last attempt failed; "+
		"send the inventory again", e.scanID)
}

// Refused marks it as the sender's to act on.
func (letGoError) Refused() {}

// readScan reads one scan and applies it.
func (r *Reader) readScan(ctx context.Context, scanID int64) (*Result, error) {
	scans := NewStore(r.db.DB)
	scan, err := scans.ByID(ctx, scanID)
	if errors.Is(err, ErrNoScan) {
		// A failed attempt sent again is written as a new scan and the failed
		// row removed, so a job still waiting to retry it has been overtaken.
		return &Result{ScanID: scanID, Superseded: true}, nil
	}
	if err != nil {
		return nil, err
	}

	build, err := catalog.NewStore(r.db.DB).Describe(ctx, scan.BuildID)
	if err != nil {
		return nil, err
	}

	// The graph reads scan identifiers as time, so a scan older than the one
	// the build last applied is never applied, and nothing reads what it sent
	// again. One the build already shows was applied by an attempt whose job
	// was not marked done; its branch documents are gone, so it is answered
	// before they are looked for.
	last, err := lastApplied(ctx, r.db.DB, scan.BuildID)
	if err != nil {
		return nil, err
	}
	if last >= scanID {
		if last == scanID {
			r.letGoThrough(ctx, build.Moves, scan.BuildID, scanID)
		} else {
			r.letGo(ctx, build.Moves, scan.BuildID, scanID)
		}
		return &Result{ScanID: scanID, Superseded: last > scanID, AlreadyApplied: last == scanID}, nil
	}

	// Uploads are accepted in the order they arrive and read in whatever order
	// workers pick them up, so a scan can reach here after a newer one has
	// already been applied. Applying it then would replace today's picture
	// with yesterday's and reopen everything the newer one closed — the same
	// harm the arrival check prevents at the door, arriving from behind.
	//
	// What it sent is kept: the newer one may not have been read yet, and if
	// it fails this one is read again.
	newest, err := scans.Newest(ctx, scan.BuildID)
	if err != nil {
		return nil, err
	}
	if passedBy(scan, newest) {
		return &Result{ScanID: scanID, Superseded: true}, nil
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
		if sent, err := documents.Sent(ctx, []int64{scanID}); err == nil && len(sent[scanID]) > 0 {
			return nil, letGoError{scanID: scanID}
		}
		return nil, fmt.Errorf("scan %d has no inventory to read", scanID)
	}

	doc, err := sbom.Read(documents.Open(ctx, inventory), r.limits)
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
	//
	// The claim budget is spent across the documents rather than per document.
	// Passed whole to each of them, a producer sending fifty attachments each
	// inside the limit made this hold fifty times what the limit was set to
	// allow — in the background reader, after the upload was answered 202.
	claims := doc.Suppressions
	limits := r.limits.OrDefault()
	left := limits.MaxStatements - len(claims)
	documentsRead := 0
	for _, held := range held {
		if held.Kind != SuppressionsKind {
			continue
		}
		documentsRead++
		if documentsRead > limits.MaxDocuments {
			return nil, refusal.Errorf("scan %d: more suppression documents than the %d limit",
				scanID, limits.MaxDocuments)
		}
		if left <= 0 {
			return nil, refusal.Errorf("scan %d: more claims than the %d limit",
				scanID, limits.MaxStatements)
		}
		within := limits
		within.MaxStatements = left
		read, err := sbom.ReadSuppressions(documents.Open(ctx, &held), within)
		if err != nil {
			return nil, fmt.Errorf("scan %d: %w", scanID, err)
		}
		left -= len(read)
		claims = append(claims, read...)
	}

	// A document that names no component of its own is filed against what it
	// was sent for. The product is what stands in: a root's own name and
	// version are excluded from identity and expiry anyway, so what matters is
	// only that it is stable for this variant.
	stand := graph.Described{Name: build.Product}
	snapshot := doc.Snapshot(stand)

	// The build's own argument is stored against the build, not against the
	// scan, because it is what the next scan run has to apply.
	//
	// The places this scan could have made a claim are passed with it. A claim
	// in a document of its own can always be restated, so not restating one is
	// a withdrawal; a claim attached to a component can only be restated by a
	// format that can attach one, and one of the two cannot. Without that, a
	// product's first scan in the other format closes every carried patch it
	// had and reopens every finding they suppressed.
	stated := map[sbom.Origin]bool{
		sbom.FromStatement: true,
		sbom.FromPedigree:  doc.Format.StatesCarriedPatches(),
	}
	// The documents the inventory was made of, kept on the scan so a receipt
	// can say it. The log line said it and nothing else did, which meant an
	// operator could only learn that a document placed none of its components
	// by going and finding the line — on the screen that exists to answer what
	// became of an upload.
	components, placed := len(doc.Components), len(doc.Components)-doc.Unrooted
	// The document's own name for the thing it is about, which a published
	// advisory offers a reader to match a release against.
	//
	// Read off the document rather than off the snapshot, and that is the
	// whole of the condition: the snapshot puts the tracked unit in the root's
	// place where the document named none, and what stands in is ours rather
	// than the producer's. A reader given that would look for a name their own
	// copy of the inventory does not carry. It is empty where the document
	// declared nothing, because a reader sets the root and says it declared one
	// in the same breath — and equally where it declared a root and gave it no
	// package identifier, which is the same answer for the same reason. It is
	// stored as the root's node holds it, without a credential, since the
	// published documents name the build by it.
	rootIdentifier := graph.StoredPurl(doc.Root.Purl)

	// The three writes are one act. Applied separately, a graph stored beside
	// claims that were not recorded reads as a build that has withdrawn every
	// patch it carries, and reopens every finding those patches suppressed —
	// with the scan marked failed and the graph it described current.
	var applied graph.Applied
	var claimed finding.ClaimsApplied
	var overtaken, backlogged bool
	if r.beforeApply != nil {
		r.beforeApply()
	}
	if err := database.InTransaction(ctx, r.db.DB,
		func(ctx context.Context, tx bun.Tx) error {
			overtaken, backlogged = false, false
			// Asked again with the build held. The answer above was read
			// before a parse that can take minutes, and a newer scan applied
			// meanwhile is replaced by this one if nothing asks. The build's
			// row is taken first, as the graph's apply takes it, so a newer
			// scan being applied has committed before this reads. A fresh
			// value, because MySQL and MariaDB skip a write that changes
			// nothing and a cluster never certifies a row nothing changed.
			if _, err := tx.NewUpdate().Table("build").
				Set(`"taken_by" = ?`, rand.Text()).
				Where(`"id" = ?`, scan.BuildID).Exec(ctx); err != nil {
				return fmt.Errorf("take the build: %w", err)
			}
			newest, err := NewStore(tx).Newest(ctx, scan.BuildID)
			if err != nil {
				return err
			}
			if passedBy(scan, newest) {
				overtaken = true
				return nil
			}
			last, err := lastApplied(ctx, tx, scan.BuildID)
			if err != nil {
				return err
			}
			if last > scanID {
				overtaken = true
				return nil
			}
			if applied, err = graph.ApplyWithin(ctx, tx, scan.BuildID, scanID, snapshot); err != nil {
				return err
			}
			if claimed, err = finding.RecordClaimsWithin(ctx, tx, scan.BuildID, scanID,
				claims, stated); err != nil {
				return err
			}
			if err := NewStore(tx).Made(ctx, scanID, components, placed, rootIdentifier); err != nil {
				return err
			}
			// The inventory just stored has to be scanned: it is new, and the
			// vulnerability data has moved since whatever last looked at this
			// build. Queued in the transaction that stores it, so the job and
			// the graph it describes commit together. Queued afterwards, a
			// failure to queue is reported as the read failing after the read
			// committed, which marks an applied scan failed and reinstates the
			// one it overtook.
			if _, err := r.queue.AddTx(ctx, tx, queue.Scan,
				strconv.FormatInt(scan.BuildID, 10)); err != nil {
				// A full backlog is not this scan's failure, and what is due
				// stays due: the periodic pass asks again once the queue has
				// drained, which is what it does for a re-scan it could not
				// queue either.
				if !errors.Is(err, queue.ErrBacklogFull) {
					return fmt.Errorf("leave the scanning to be done: %w", err)
				}
				backlogged = true
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("scan %d: %w", scanID, err)
	}
	if overtaken {
		return &Result{ScanID: scanID, Superseded: true}, nil
	}

	// What the upload did to the build's inventory, for whoever decides
	// whether that is worth telling anybody. After the writes have committed,
	// because what it reads is the rows they wrote.
	if r.told != nil {
		r.told(ctx, Stored{BuildID: scan.BuildID, ScanID: scanID})
	}

	result := &Result{
		ScanID: scanID, Applied: applied,
		Components: len(doc.Components), Suppressions: len(claims),
		Unrooted:       doc.Unrooted,
		Unversioned:    doc.Unversioned,
		DanglingEdges:  doc.DanglingEdges,
		FileReferences: doc.FileReferences,
		SelfReferences: doc.SelfReferences,
		ClaimsOpened:   claimed.Opened, ClaimsClosed: claimed.Closed,
		ClaimsUnstated: claimed.Unstated,
		Retained:       !build.Moves,
	}

	if backlogged {
		r.logger.Warn("an inventory was stored with nothing queued to scan it because the "+
			"queue is full", "scan", scanID, "build", scan.BuildID)
	}

	// A branch is superseded by the next night's build, so what it sent is not
	// kept, nor what the scans this one passed sent: none of them is applied
	// once the build shows this one. Those set aside while this one waited to
	// be read kept theirs in case it failed. A tag is not superseded by
	// anything, and re-scanning it years from now needs both what it contained
	// and what the build had already argued about its own patches.
	//
	// After the apply has committed, so a failure here is not the read's: the
	// scan is applied, and reported as failed it would be marked so and the
	// scan it overtook read again over it. The documents are then kept, which
	// costs storage and changes no answer, and the log line is what says so.
	r.letGoThrough(ctx, build.Moves, scan.BuildID, scanID)
	return result, nil
}

// letGoThrough releases what a branch scan the build shows sent, and what
// every scan it passed sent. A worker stopping after the apply commits leaves
// both held, so the attempt that finds the scan already applied releases them
// too.
func (r *Reader) letGoThrough(ctx context.Context, moves bool, buildID, scanID int64) {
	if !moves {
		return
	}
	passed, err := NewDocuments(r.db.DB).heldBefore(ctx, buildID, scanID)
	if err != nil {
		r.logger.Error("could not read which passed scans still hold documents",
			"scan", scanID, "build", buildID, "error", err)
	}
	r.letGo(ctx, moves, buildID, append(passed, scanID)...)
}

// lastApplied returns the scan the build last applied, or zero.
func lastApplied(ctx context.Context, db bun.IDB, buildID int64) (int64, error) {
	var last int64
	if err := db.NewSelect().
		TableExpr(`"build" AS "t"`).
		ColumnExpr(`COALESCE("t"."last_scan_id", 0)`).
		Where(`"t"."id" = ?`, buildID).
		Scan(ctx, &last); err != nil {
		return 0, fmt.Errorf("read what the build last applied: %w", err)
	}
	return last, nil
}

// letGo releases what branch scans sent, once nothing will read it again.
// A failure is logged, because the scan's outcome stands either way: kept
// documents cost storage and change no answer.
func (r *Reader) letGo(ctx context.Context, moves bool, buildID int64, scanIDs ...int64) {
	if !moves {
		return
	}
	documents := NewDocuments(r.db.DB)
	for _, scanID := range scanIDs {
		if err := documents.Discard(ctx, scanID); err != nil {
			r.logger.Error("could not let go of what a branch scan sent", "scan", scanID,
				"build", buildID, "error", err)
		}
	}
}

// letGoFailed releases what a branch scan sent once its last attempt failed.
func (r *Reader) letGoFailed(ctx context.Context, reference string) {
	scanID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		return
	}
	scan, err := NewStore(r.db.DB).ByID(ctx, scanID)
	if err != nil {
		if !errors.Is(err, ErrNoScan) {
			r.logger.Error("could not read the failed scan to let go of what it sent",
				"scan", scanID, "error", err)
		}
		return
	}
	build, err := catalog.NewStore(r.db.DB).Describe(ctx, scan.BuildID)
	if err != nil {
		r.logger.Error("could not read the failed scan's build to let go of what it sent",
			"scan", scanID, "build", scan.BuildID, "error", err)
		return
	}
	r.letGo(ctx, build.Moves, scan.BuildID, scanID)
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
	newest, err := scans.Newest(ctx, failed.BuildID)
	if err != nil || newest == nil {
		return err
	}

	shown, err := lastApplied(ctx, r.db.DB, failed.BuildID)
	if err != nil {
		return err
	}
	if shown == newest.ID {
		return nil
	}

	pending, err := r.db.NewSelect().Model((*queue.Job)(nil)).
		Where(`"kind" = ?`, queue.Parse).
		Where(`"reference" = ?`, strconv.FormatInt(newest.ID, 10)).
		Where(`"state" IN (?)`, bun.List([]queue.State{queue.Pending, queue.Running})).
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
