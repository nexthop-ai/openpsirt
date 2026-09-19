package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// Ingest carries everything the upload endpoint runs on.
type Ingest struct {
	DB     *database.DB
	Queue  *queue.Queue
	Limits sbom.Limits
	// Access resolves the caller. A nil resolver authorizes nothing, the only
	// safe answer from a process with no way to identify a caller.
	Access *access.Resolver
	// Logger records a fault where an operator can read it, rather than
	// describing it to whoever asked.
	Logger *slog.Logger
	// Replica names this process where several run the same binary, so work
	// that must happen once can be held by one of them. Empty is a deployment
	// of one: a test, and a development run.
	Replica string
	// PlainHTTP serves this deployment without TLS, the ordinary shape of a
	// local run. It only ever loosens a cookie, so it is
	// named for what it is rather than for what it switches off.
	PlainHTTP bool
	// Interface is the built web interface, where this binary was built with
	// one. Zero serves the API alone: a development build, or a deployment
	// that offers the API and nothing else.
	Interface Interface
	// Providers are the ways somebody may sign in, by the name a URL uses.
	// Empty means none is configured, and the sign-in paths are not mounted at
	// all rather than mounted and answering that nothing is available.
	Providers map[string]signin.Provider
	// BaseURL is the address people arrive on, which behind a proxy differs
	// from this process's own name for itself. A provider compares the callback
	// against what it was registered with, so this has to be the outside one.
	BaseURL string
	// SessionLifetime bounds a sign-in. Zero takes the default.
	SessionLifetime time.Duration
	// Publisher is who an advisory says issued it. Unstated means no advisory
	// is generated, and the refusal says which part is missing — a document
	// naming no publisher is not a CSAF document, and handing one over would
	// fail wherever somebody took it next.
	Publisher publisher.Named
	// Ours is the set this deployment calls its own, and so never sends to a
	// public package index. The same value the asking pass holds, derived
	// once where the configuration is read: two derivations of one boundary
	// are two boundaries the first time either moves.
	Ours currency.Ours
	// Mode says where roles come from. Read per request rather than held, so
	// an administrator turning group binding off takes effect at once.
	Mode func(context.Context) access.Mode
	// Files is where attachments are kept. Nil is a deployment that holds
	// none, which is ordinary: attachments are off and everything else
	// works.
	Files attach.Storage
}

// attachments returns a store over the files this deployment holds, or nothing
// where there is no database. A nil Storage inside it is the deployment that
// configured none, and every path through it refuses in the same words.
func (in Ingest) attachments() *attach.Store {
	if in.DB == nil {
		return nil
	}
	return attach.NewStore(in.DB.DB, in.Files)
}

// catalog returns a store over the handle it is given, or nothing when there
// is none — which is the process that only renders the API document.
//
// The handle is the transaction an administrative act is being made in, or
// this deployment's pooled one where the route only reads.
func (in Ingest) catalog(db bun.IDB) *catalog.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return catalog.NewStore(db)
}

// settings returns a store over what an operator has set, or nothing where
// there is no database.
func (in Ingest) settings(db bun.IDB) *setting.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return setting.NewStore(db)
}

// logger is where this process writes, and never nil.
//
// A handler that logs must not have to remember. Sixty-three sites guard the
// field with `if in.Logger != nil` and two do not, so a process built without
// one — the one that renders the API document — panics into the recovery
// middleware and answers 500 where the route has words for a refusal. A no-op
// logger makes the omission impossible rather than rare.
func (in Ingest) logger() *slog.Logger {
	if in.Logger != nil {
		return in.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// groupsReachable reports a source of group membership: a provider carrying
// one, or a trusted proxy that states it.
//
// Asked before roles are switched to group-bound. Without a source every
// arrival belongs to nothing, so nobody derives any role and the deployment
// locks itself out — including whoever made the change.
func (in Ingest) groupsReachable() bool {
	for _, provider := range in.Providers {
		if provider.GroupsSource() {
			return true
		}
	}
	return in.Access != nil && in.Access.ReportsGroups()
}

// rights returns a store over who may do what, built over the handle it is
// given, or nothing where there is none.
func (in Ingest) rights(db bun.IDB) *access.Store {
	if in.DB == nil || db == nil {
		return nil
	}
	return access.NewStore(db)
}

// handle is the database a read-only route builds its stores over.
//
// Named rather than written as in.DB at each site: a nil *database.DB handed
// to an interface parameter is an interface that is not nil, so every check
// below it reads as a database that is there.
func (in Ingest) handle() bun.IDB {
	if in.DB == nil {
		return nil
	}
	return in.DB.DB
}

// uploadParts are the documents a build sends.
//
// One request carries the whole picture. A build whose inventory lands and
// whose suppressions do not has every carried patch reported as an outstanding
// vulnerability, which is worse than a failed upload.
type uploadParts struct {
	// Inventory is what the build shipped.
	//
	// The declared content type is deliberately permissive. A part's type is
	// decided by reading it, not by the label a client put on it — and
	// the labels vary: a build pushing a file with an ordinary command-line
	// client sends it as opaque bytes, which is not wrong and is not worth
	// refusing an otherwise good scan over.
	Inventory huma.FormFile `form:"inventory" contentType:"application/json,application/octet-stream" required:"true"`
	// Suppressions are what the build has already argued does not apply to
	// it. A build's suppressions are a directory rather than a file, so this
	// repeats — and a build that carries no patches sends none, so it is
	// optional.
	Suppressions []huma.FormFile `form:"suppressions" contentType:"application/json,application/octet-stream" required:"false"`
}

// UploadInput is an arriving scan.
type UploadInput struct {
	Product string `path:"product" doc:"The declared product this build is of"`
	Stream  string `path:"stream" doc:"The declared branch or tag"`
	Variant string `path:"variant" doc:"The declared way that stream is built"`
	RawBody huma.MultipartFormFiles[uploadParts]
}

// UploadOutput is the record of what became of it.
type UploadOutput struct {
	Status int
	Body   UploadResult
}

// UploadResult is the producer's answer.
type UploadResult struct {
	ScanID int64 `json:"scan_id" doc:"The scan this upload became, or the one it matched"`
	// Outcome says what happened, in the producer's terms rather than ours.
	Outcome string `json:"outcome" enum:"queued,already_held" doc:"Whether this upload was taken or matched one already held"`
	Serial  string `json:"serial,omitempty" doc:"The identity the inventory carries for itself"`
	BuiltAt string `json:"built_at,omitempty" doc:"The build time the producer states"`
}

func registerScans(api huma.API, in Ingest) {
	// Registered whether or not there is a database behind it. The OpenAPI
	// document is generated from these registrations by a process that never
	// opens one, and an operation missing from the document because of how the
	// document is generated is the drift generating it exists to prevent.
	huma.Register(api, requiring(huma.Operation{
		OperationID: "upload-scan",
		Method:      http.MethodPost,
		Path:        "/v1/products/{product}/streams/{stream}/variants/{variant}/scans",
		Summary:     "Upload an SBOM and its VEX documents",
		Description: "Accepts a CycloneDX 1.x, SPDX 2.x or SPDX 3.x SBOM and any number of " +
			"OpenVEX documents as multipart form fields named `inventory` and " +
			"`suppressions`. The format is taken from the document itself; a major version " +
			"this does not read is rejected by name.\n\n" +
			"The product, branch and variant must already exist; an upload naming something " +
			"undeclared is rejected and the error says which part is missing.\n\n" +
			"Returns 202 before the documents are parsed. A success here means they were " +
			"accepted for processing, not that they were valid. Poll `GET .../scans` to find out " +
			"whether they parsed and what the scan found.",
		Tags: []string{"Ingest"},
		// A scan file is somebody else's output arriving over a link we do not
		// control, and this is the first place it can be stopped.
		MaxBodyBytes:  maxUpload(in.Limits),
		Middlewares:   huma.Middlewares{boundedForm(api, maxUpload(in.Limits))},
		DefaultStatus: http.StatusAccepted,
	}, perProduct, "A pipeline key covering this product, branch and variant sends without any "+
		"of these, and is how a build sends.", triageRights()...), func(ctx context.Context, input *UploadInput) (*UploadOutput, error) {
		return upload(ctx, in, input)
	})
}

// boundedForm caps how much of a multipart request is read at all.
//
// The operation's body limit applies to a body read whole. A form is read as
// it streams, part by part, with nothing above it: a part larger than the
// limit is spooled to the temporary directory in full before the document
// limit ever sees a byte of it, which is a disk somebody fills from outside.
// So the request body itself is capped here, and the form is parsed here,
// before the operation's own parsing runs — which then finds the form already
// read and reads nothing more. Anything other than the cap is left for that
// parsing to report, in its own terms.
func boundedForm(api huma.API, limit int64) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, w := humachi.Unwrap(ctx)
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			var tooLarge *http.MaxBytesError
			if err := r.ParseMultipartForm(humachi.MultipartMaxMemory); errors.As(err, &tooLarge) {
				_ = huma.WriteErr(api, ctx, http.StatusRequestEntityTooLarge,
					fmt.Sprintf("the request is larger than the %d bytes an upload may be", limit))
				return
			}
		}
		next(ctx)
	}
}

// maxUpload bounds a whole request, which is more than one document.
//
// A build sends an inventory and however many suppression documents it has, so
// the request ceiling is not the document ceiling. Twice leaves room for the
// suppressions without letting a request be unbounded.
func maxUpload(limits sbom.Limits) int64 {
	return 2 * limits.OrDefault().MaxBytes
}

func upload(ctx context.Context, in Ingest, input *UploadInput) (*UploadOutput, error) {
	if in.DB == nil || in.Queue == nil {
		return nil, noDatabase(in.Logger)
	}
	parts := input.RawBody.Data()

	// The number of documents one scan may carry, refused before any row is
	// written. Each one is read within the bounds a document is read within,
	// and without a ceiling on the count those bounds are multiplied by a
	// number nothing decides.
	limits := in.Limits.OrDefault()
	var sent int
	for _, part := range parts.Suppressions {
		if part.IsSet {
			sent++
		}
	}
	if sent > limits.MaxDocuments {
		return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
			"that scan carries %d suppression documents, and this deployment reads %d",
			sent, limits.MaxDocuments))
	}

	// The sender, before anything is read or written.
	subject, err := requester(ctx)
	if err != nil {
		return nil, err
	}

	// The names are resolved to things before the pair is recorded, so that
	// whether this sender may file against them is decided first. Recording
	// and then refusing would leave a row created by a request that failed.
	catalog := catalog.NewStore(in.DB.DB)
	named, err := catalog.LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
	if err != nil {
		// The message names which part is missing, which is what whoever sees
		// the failed upload needs in order to declare it — and a target this
		// sender may not file against is reported as not declared, so that a
		// stolen key cannot be used to read the shipping catalog one guess at
		// a time.
		return nil, undeclared(in.Logger, err, "that build could not be looked up")
	}

	// A key authorizes an upload; it does not describe one. Every
	// constraint it carries must match what this upload says it is for,
	// and a mismatch is refused rather than redirected — a key covering
	// one release must never quietly accept a scan of another.
	//
	// Refused here rather than answered as not-declared, deliberately.
	// Told apart, the two let a key learn which releases and variants
	// exist inside the product it already sends to, which is a bounded
	// thing to give somebody holding a working credential for that product
	// — and the alternative costs a pipeline the message that says what
	// actually went wrong. Another product stays invisible to it either
	// way.
	//
	// A person may send too, where they hold triage on the product:
	// somebody re-uploading a build by hand is doing triage work, not
	// administration.
	switch {
	case subject.Kind == access.Pipeline:
		if !subject.MaySend(named.ProductID, named.StreamID, named.VariantID) {
			return nil, huma.Error403Forbidden("not authorized")
		}
	case !subject.Triages(access.Public, named.ProductID):
		return nil, huma.Error403Forbidden("not authorized")
	}

	// Refusing before storing. Deciding costs a query; deciding afterwards
	// costs however long it takes to store tens of megabytes we then throw
	// away, on a deployment already behind on its work. It happens after
	// authorization so that how far behind we are is not something an
	// unauthorized sender can measure.
	depth, err := in.Queue.Depth(ctx, queue.Parse)
	if err != nil {
		return nil, wentWrong(in.Logger, "cannot tell how much work is waiting", err)
	}
	// The limit in force, not the one this binary was built with. Refusing
	// against the built-in number makes the effective limit the smaller of the
	// two, so raising the setting changes nothing for the producer the setting
	// exists for.
	limit, err := in.Queue.Backlog(ctx)
	if err != nil {
		return nil, wentWrong(in.Logger, "cannot tell how much work may wait", err)
	}
	if depth >= limit {
		return nil, huma.NewError(http.StatusServiceUnavailable,
			fmt.Sprintf("%d scans are already waiting to be read; try again shortly", depth))
	}

	target, err := catalog.TargetFor(ctx, named.StreamID, named.VariantID)
	if err != nil {
		return nil, wentWrong(in.Logger, "the target could not be recorded", err)
	}

	// The submission and its digest: what it says about
	// itself comes from the inventory, and whether we already hold it is
	// asked of everything that arrived.
	// Every door that turns an upload away records it, not only the last one.
	// A producer posting a document nothing can read never reaches the arm
	// below, so the build draws as quiet-and-never-refused — which the coverage
	// report reads as a pipeline nobody wired up, telling the wrong person
	// about the commoner of the two failures this record exists for.
	note := func(reason string, builtAt *time.Time, hash *string) {
		if in.DB == nil {
			return
		}
		if noted := ingest.NewStore(in.DB.DB).Refused(ctx, subject, ingest.Refusal{
			TargetID: target.ID, Reason: reason, BuiltAt: builtAt, ContentHash: hash,
		}); noted != nil {
			// Best-effort, and the one place that is right: a note about
			// something that already failed, where failing the failure would
			// turn a refusal the producer needs to read into a fault they
			// cannot.
			in.logger().ErrorContext(ctx, "could not record that an upload was refused",
				"error", noted, "product", input.Product)
		}
	}

	header, contentHash, inventoryHash, err := describe(parts, in.Limits)
	if err != nil {
		refused := huma.Error422UnprocessableEntity("the upload could not be read", err)
		note(refused.Error(), nil, nil)
		return nil, refused
	}

	// A document that does not say when it was built cannot be ordered against
	// anything, and taking it is worse than refusing it: the zero time is
	// older than every real one, so the first such upload is accepted and
	// every later scan for that target is refused as not newer. The target
	// takes no further scans at all, which is the same wedge the future-clock
	// check exists to prevent, arriving through a door nobody guarded.
	if header.BuiltAt.IsZero() {
		refused := huma.Error400BadRequest(
			"the inventory does not say when it was built, and that is what orders scans against each other")
		note(refused.Error(), nil, &contentHash)
		return nil, refused
	}

	arriving := ingest.Arriving{
		TargetID:      target.ID,
		ContentHash:   contentHash,
		InventoryHash: inventoryHash,
		Serial:        header.Serial,
		BuiltAt:       header.BuiltAt,
		ParserVersion: version.Get().Version,
		// The credential that sent this, recorded alongside the parser
		// version, so the provenance of the data has an answer.
		Credential: subject.Identity,
	}

	var (
		result  UploadResult
		outcome ingest.Outcome
	)
	err = database.InTransaction(ctx, in.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		scan, taken, err := ingest.NewStore(tx).Record(ctx, arriving)
		// Recorded before the error is checked: a refusal carries the reason
		// in the outcome, and that is what decides which answer the producer
		// gets back.
		outcome = taken
		if err != nil {
			return err
		}
		// Through the package's own helper, and unconditionally: an inventory
		// with no build time is refused above, so a branch here asks a question
		// already answered.
		result = UploadResult{
			ScanID: scan.ID, Serial: header.Serial, BuiltAt: stamp(header.BuiltAt),
		}
		if taken != ingest.Accept && taken != ingest.Retake {
			return nil
		}

		// Everything from here commits together. A scan row without its
		// documents is unreadable, documents without a job are work nobody
		// picks up, and a job without either is a worker failing on something
		// that was never there.
		documents := ingest.NewDocuments(tx)
		if taken == ingest.Retake {
			// These are the bytes that are already stored against that scan,
			// since a submission is identified by all of it — so what the
			// attempt that failed left behind is replaced rather than added
			// to. Added to, the reader would find two inventories and read
			// the first of them.
			if err := documents.Remove(ctx, scan.ID); err != nil {
				return err
			}
		}
		if err := store(ctx, documents, scan.ID, ingest.InventoryKind, 0, parts.Inventory); err != nil {
			return err
		}
		for i, part := range parts.Suppressions {
			if !part.IsSet {
				continue
			}
			if err := store(ctx, documents, scan.ID, ingest.SuppressionsKind, i, part); err != nil {
				return err
			}
		}
		_, err = in.Queue.AddTx(ctx, tx, queue.Parse, fmt.Sprint(scan.ID))
		return err
	})

	switch {
	case errors.Is(err, queue.ErrBacklogFull):
		return nil, huma.NewError(http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, ingest.ErrRejected):
		// Recorded here, because nothing else records it. Without this a
		// refused upload leaves no server-side trace: the producer is told and
		// the deployment is not, so "our scans stopped arriving" has nowhere to
		// be looked up. Info rather than a warning — a producer refusing to
		// stop retrying writes a line per attempt, and the serial is what
		// makes those readable rather than alarming.
		in.logger().InfoContext(ctx, "an upload was refused",
			"outcome", outcome, "serial", header.Serial, "product", input.Product)
		// And beside the log, a row the coverage report can read. A log line
		// answers somebody already holding a terminal; the report is what says
		// a build has gone quiet, and without this it cannot say whether
		// anybody is trying. Those are different people and different faults:
		// a pipeline nobody wired up, against one failing nightly and telling
		// its own log it succeeded.
		refused := rejection(outcome, err)
		note(refused.Error(), &header.BuiltAt, &contentHash)
		return nil, refused
	case err != nil:
		return nil, wentWrong(in.Logger, "the upload could not be recorded", err)
	}

	out := &UploadOutput{Status: http.StatusAccepted, Body: result}
	if outcome == ingest.AlreadyHave {
		// Answered with success, not an error. The ordinary case is a retry
		// after a timeout that had in fact succeeded, and failing it turns a
		// landed scan into a red build.
		out.Status = http.StatusOK
		out.Body.Outcome = "already_held"
		return out, nil
	}
	out.Body.Outcome = "queued"
	return out, nil
}

// rejection turns a refusal into the status that describes it.
func rejection(outcome ingest.Outcome, err error) error {
	if outcome == ingest.BuiltInFuture {
		// The producer's own clock is wrong, which is a fault in the request
		// rather than a conflict with anything we hold.
		return huma.Error400BadRequest(err.Error())
	}
	return huma.NewError(http.StatusConflict, err.Error())
}

// describe reads what an inventory says about itself, and hashes the whole
// submission.
//
// The hash covers the suppression documents as well as the inventory. A
// submission is identified by everything in it: an unchanged inventory
// arriving beside judgments that have changed is a new submission, and
// fingerprinting one half of it would answer success to a build whose
// arguments about itself were then discarded.
//
// The claim digests are sorted before they are folded in, so a re-send of
// byte-identical documents still deduplicates however the parts were ordered,
// and each goes in under the name of what it is, on a line of its own — two
// digests cannot run together into a third, and an inventory whose digest
// happens to equal a claim's is still a different submission.
//
// The inventory's own digest comes back beside the submission's, because the
// arrival decision needs both: what we hold is a submission, and what makes
// one arriving at a build time already taken the same build re-argued rather
// than a second document claiming that time is the inventory alone.
func describe(parts *uploadParts, limits sbom.Limits) (sbom.Header, string, string, error) {
	header, inventory, err := readInventory(parts.Inventory, limits)
	if err != nil {
		return sbom.Header{}, "", "", err
	}
	claims := make([]string, 0, len(parts.Suppressions))
	for _, part := range parts.Suppressions {
		if !part.IsSet {
			continue
		}
		digest, err := hashOf(part)
		if err != nil {
			return sbom.Header{}, "", "", fmt.Errorf("a suppression document could not be read: %w", err)
		}
		claims = append(claims, digest)
	}
	slices.Sort(claims)

	whole := sha256.New()
	whole.Write([]byte("inventory " + inventory + "\n"))
	for _, digest := range claims {
		whole.Write([]byte("suppressions " + digest + "\n"))
	}
	return header, hex.EncodeToString(whole.Sum(nil)), inventory, nil
}

// readInventory reads what an inventory says about itself, and hashes it.
//
// Both in one pass: the file is seekable, but a second pass over tens of
// megabytes buys nothing.
func readInventory(file huma.FormFile, limits sbom.Limits) (sbom.Header, string, error) {
	if !file.IsSet {
		return sbom.Header{}, "", fmt.Errorf("no inventory was sent")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return sbom.Header{}, "", err
	}
	digest := sha256.New()
	header, err := sbom.ReadHeader(io.TeeReader(file, digest), limits)
	if err != nil {
		return sbom.Header{}, "", err
	}
	// The header may be answered before the end of the file, and the hash has
	// to cover all of it.
	if _, err := io.Copy(digest, file); err != nil {
		return sbom.Header{}, "", err
	}
	return header, hex.EncodeToString(digest.Sum(nil)), nil
}

// hashOf digests a part as it arrived.
func hashOf(file huma.FormFile) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// store rewinds a part and puts it away.
func store(ctx context.Context, documents *ingest.Documents, scanID int64, kind ingest.Kind, ordinal int, file huma.FormFile) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := documents.Write(ctx, scanID, kind, ordinal, file)
	return err
}

// ReceiptBody is the record of one upload.
type ReceiptBody struct {
	ScanID     int64  `json:"scan_id" doc:"The scan this upload became"`
	Serial     string `json:"serial,omitempty" doc:"The identity the inventory carries for itself"`
	BuiltAt    string `json:"built_at,omitempty" doc:"The build time the producer states"`
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
	// themselves:
	// a branch build's contents are let go once they have been read, and this
	// still says what arrived and what its bytes hashed to.
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
	// Measured is what the run answering *this* upload was made with,
	// rather than what the newest run was. On every receipt the run
	// answers, unlike opened and closed: the versions are a property of
	// the run rather than a change it made, and a page spanning a scanner
	// upgrade or a vulnerability database that stopped moving is exactly
	// what somebody reads this screen to notice.
	Measured *MeasuredBody `json:"measured,omitempty" doc:"The tools the run answering this upload was measured with. Absent until a run has covered it"`
	// RunID is the run that answered this upload, so what it did can be
	// asked for. On every receipt that run answers, like the versions beside
	// it — the counts above are the thing that belongs to one upload only.
	RunID int64 `json:"run_id,omitempty" doc:"The run that answered this upload. Absent until one has"`
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

// MeasuredBody is the tooling a build's numbers were produced with.
//
// Not decoration. A build reporting nothing wrong and a build last measured
// against a vulnerability database from March look identical on every screen
// without this, and they are not the same statement at all.
type MeasuredBody struct {
	Scanner         string `json:"scanner" doc:"The scanner that produced the findings"`
	ScannerVersion  string `json:"scanner_version,omitempty"`
	DatabaseVersion string `json:"database_version,omitempty" doc:"The vulnerability database it read"`
	RanAt           string `json:"ran_at,omitempty" doc:"The moment that run finished"`
	// RanHere says we ran it rather than a build sending what its own scanner
	// found. Counts are only comparable between builds measured the same way,
	// so a report mixing the two without saying would be a rumor.
	RanHere bool `json:"ran_here,omitempty" doc:"We ran the scanner, rather than the build sending what its own found"`
	// The rest of the chain, for a report read against what shipped: the
	// upload, the inventory inside it, and where to fetch that inventory. An
	// auditor follows shipped artifact, inventory, run, scanner and database,
	// disposition — and a report naming only the run is the last two links of
	// five.
	//
	// Absent where the caller is describing a run alone, which is what a
	// finding and a receipt do.
	Run          int64  `json:"run,omitempty" doc:"The scanner run these came from"`
	Scan         int64  `json:"scan,omitempty" doc:"The upload the build's contents came from, as the receipt names it"`
	ScanHash     string `json:"scan_hash,omitempty" doc:"The hash of what was uploaded"`
	BuiltAt      string `json:"built_at,omitempty" doc:"The build time it describes"`
	Document     int64  `json:"document,omitempty" doc:"The inventory that was read, as the receipt names it"`
	DocumentHash string `json:"document_hash,omitempty" doc:"The hash of the inventory as it arrived"`
	// DocumentHeld distinguishes an inventory whose bytes were let go from one
	// nothing knows about: a tagged release keeps its documents and a branch
	// build does not, and a hash nobody can fetch the bytes for is a claim
	// rather than evidence.
	DocumentHeld *bool  `json:"document_held,omitempty" doc:"Whether the inventory itself is still here"`
	DocumentAt   string `json:"document_at,omitempty" doc:"The address of the inventory that was read. Absent where its contents were let go"`
}

// ReceiptsOutput is a page of what has been filed against a build.
type ReceiptsOutput struct {
	Body struct {
		Items []ReceiptBody `json:"items"`
		Total int           `json:"total"`
		// MeasuredAgainst describes the build's last finished run rather than
		// any one upload, which is why it sits beside the page instead of on
		// each row.
		MeasuredAgainst *MeasuredBody `json:"measured_against,omitempty" doc:"The tools the last completed run was measured with"`
	}
}

func registerReceipts(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-scans", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/scans",
		Summary: "List uploaded scans and their status",
		Description: "Returns uploads newest first, each with its state: `reading` (accepted, not " +
			"yet parsed), `scanning` (parsed, vulnerability scan pending), `scanned` (complete), " +
			"or `failed` with the reason.\n\n" +
			"Because uploads return 202 before parsing, this is how a build pipeline finds out " +
			"whether its SBOM was usable. An API key sees only the uploads it sent itself.",
		Tags: []string{"Ingest"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number returned"`
		Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*ReceiptsOutput, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}

		// Resolved and authorized together, so a build somebody may not reach
		// reads as one that was never declared.
		names := catalog.NewStore(in.DB.DB)
		named, err := names.LocateVisible(ctx, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, undeclared(in.Logger, err, "that build could not be looked up")
		}

		if subject.Kind == access.Pipeline &&
			!subject.MaySend(named.ProductID, named.StreamID, named.VariantID) {
			return nil, huma.Error403Forbidden("not authorized")
		}

		target, err := names.ExistingTarget(ctx, named.StreamID, named.VariantID)
		out := &ReceiptsOutput{}
		out.Body.Items = []ReceiptBody{}
		if err != nil {
			// Declared, and nothing has ever been filed against it.
			return out, nil
		}

		// A key sees the receipts for what it sent and nothing more. Reading
		// back one's own upload is the other half of the acceptance, not a
		// report about the product.
		var sender string
		if subject.Kind == access.Pipeline {
			sender = subject.Identity
		}
		scans := ingest.NewStore(in.DB.DB)
		receipts, total, err := scans.Receipts(ctx, subject, target.ID, sender, input.Limit, input.Offset)
		switch {
		case errors.Is(err, access.ErrDenied):
			// The answer a build nobody declared gets. A 500 here against a
			// 404 for a stranger says which builds exist, one name at a time
			// — and the reach that meets it is a case collaborator, who holds
			// nothing on the product and may reach the one finding they were
			// brought in on.
			return nil, nothingScannedThere()
		case err != nil:
			return nil, wentWrong(in.Logger, "the scans could not be read", err)
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
			return nil, nothingScannedThere()
		case err != nil:
			return nil, wentWrong(in.Logger, "what the scans changed could not be read", err)
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
			return nil, wentWrong(in.Logger, "what the scans arrived with could not be read", err)
		}

		for _, r := range receipts {
			body := ReceiptBody{
				ScanID:     r.Scan.ID,
				Serial:     r.Scan.Serial,
				BuiltAt:    stamp(r.Scan.BuiltAt),
				ReceivedAt: stamp(r.Scan.ReceivedAt),
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
			if r.Measured != nil {
				body.RunID = r.Measured.ID
				body.Measured = &MeasuredBody{
					Scanner: r.Measured.Scanner, ScannerVersion: r.Measured.ScannerVersion,
					DatabaseVersion: r.Measured.DatabaseVersion, RanHere: r.Measured.RanHere,
				}
				if r.Measured.FinishedAt != nil {
					body.Measured.RanAt = stamp(*r.Measured.FinishedAt)
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
		// rather than
		// invented where nothing has finished running yet.
		// Not for a credential that is only allowed to see its own uploads.
		// This endpoint deliberately narrows receipts to what a key sent —
		// "a key sees the receipts for what it sent and nothing more" — and a
		// key that has uploaded nothing would otherwise still learn when the
		// build was last scanned and with what, which is a report about the
		// product rather than an acknowledgement of its own upload.
		if sender != "" {
			return out, nil
		}
		last, err := finding.NewStore(in.DB.DB).LatestRun(ctx, subject, target.ID)
		if err != nil {
			return nil, wentWrong(in.Logger, "the last run could not be read", err)
		}
		if last != nil {
			out.Body.MeasuredAgainst = &MeasuredBody{
				Scanner:         last.Scanner,
				ScannerVersion:  last.ScannerVersion,
				DatabaseVersion: last.DatabaseVersion,
			}
			if last.FinishedAt != nil {
				out.Body.MeasuredAgainst.RanAt = stamp(*last.FinishedAt)
			}
		}
		return out, nil
	})
}

// stamp renders a time the one way the API states times.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// coverageOutput carries the rows and what was asked of them, because "quiet"
// is a judgment against a threshold and a reader cannot check the judgment
// without the threshold.
type coverageOutput struct {
	Body struct {
		Items []CoverageBody `json:"items"`
		// Quiet is how many of the rows are, so a caller can say so without
		// counting them again.
		Quiet int `json:"quiet" doc:"The number gone quiet, across every build and not only this page"`
		// Never and Unsupported are counted here for the same reason, and
		// because a caller recomputing either from the page it was handed
		// states a figure about the page under a heading about the estate.
		Never          int `json:"never" doc:"The number in support never scanned, across every build and not only this page"`
		Unsupported    int `json:"unsupported" doc:"The number out of support, across every build and not only this page. Silence there is expected, so these are never counted as quiet"`
		Total          int `json:"total" doc:"The number of builds to report on"`
		QuietAfterDays int `json:"quiet_after_days" doc:"The span this deployment allows, in days"`
	}
}

// CoverageBody is one declared build and when a scan last arrived for it.
type CoverageBody struct {
	Product    string `json:"product"`
	Stream     string `json:"stream"`
	StreamKind string `json:"stream_kind" enum:"branch,tag" doc:"Whether this line moves"`
	Variant    string `json:"variant"`
	// LastReceivedAt is absent where nothing has ever been filed against this
	// build, which is a different situation from a scan that failed.
	LastReceivedAt string `json:"last_received_at,omitempty" doc:"The moment a scan last arrived. Absent where none ever has"`
	// LastRefusedAt tells a build nobody uploads to apart from one whose
	// uploads are being turned away. Both are quiet and they are different
	// faults: a pipeline nobody wired up, against one failing nightly and
	// telling its own log that it succeeded.
	LastRefusedAt  string `json:"last_refused_at,omitempty" doc:"The moment an upload against this build was last turned away. Absent where none has been"`
	RefusedBecause string `json:"refused_because,omitempty" doc:"The words the producer was given the last time one was turned away, in the same words they were given"`
	QuietDays      int    `json:"quiet_days" doc:"The span since, in days, measured from the last arrival or from when the build was declared"`
	Quiet          bool   `json:"quiet,omitempty" doc:"Whether that is longer than this deployment allows"`
	// Retired is reported rather than the row being left out. A release that
	// stopped being scanned because it stopped being supported is expected
	// rather than a fault, but "not scanned, and that is fine" and "not
	// listed" are different answers.
	Retired bool `json:"retired,omitempty" doc:"Whether this build's release is out of support, in which case silence is expected and it is never reported as quiet"`
}

func registerCoverage(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-scanning", Method: http.MethodGet, Path: "/v1/scanning",
		Summary: "List when each build was last scanned",
		Description: "Returns every build you can see, longest-silent first, with when a scan " +
			"last arrived for it and whether that is longer ago than this deployment allows.\n\n" +
			"A build that stops being scanned reports no new findings and fails nothing, so it " +
			"looks healthier than one that is still being scanned. A build nothing has ever " +
			"been filed against is measured from when it was declared.\n\n" +
			"How long counts as quiet is the `scanning.quiet-after` setting.",
		Tags: []string{"Scans"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Limit  int `query:"limit" default:"200" minimum:"1" maximum:"500" doc:"The number returned. Quietest first, so the default is the answer for any estate somebody reads by hand"`
		Offset int `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*coverageOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		quietAfter, err := setting.NewStore(in.DB.DB).Duration(ctx, setting.QuietAfter, setting.DefaultQuietAfter)
		if err != nil {
			return nil, wentWrong(in.Logger, "the settings could not be read", err)
		}

		rows, err := ingest.NewStore(in.DB.DB).Scanning(ctx, subject, scope, quietAfter)
		if err != nil {
			// The last scan of a build by anybody is a person's
			// question, and the store says so. Answered as a fault, it reads
			// as the deployment being broken rather than as this credential
			// not being the one to ask.
			return nil, refused(in.Logger, err, "what has been scanned could not be read")
		}

		out := &coverageOutput{}
		out.Body.QuietAfterDays = int(quietAfter.Hours() / 24)
		out.Body.Total = len(rows)
		// Counted before the page is cut, and the quiet ones counted across
		// the whole answer rather than the page: a badge saying "3" because
		// three quiet builds fall on the first page answers a different
		// question from the one it appears to.
		for _, row := range rows {
			if row.Quiet {
				out.Body.Quiet++
			}
			if row.Retired {
				out.Body.Unsupported++
				continue
			}
			if row.LastReceivedAt == nil {
				out.Body.Never++
			}
		}
		if input.Offset < len(rows) {
			rows = rows[input.Offset:]
		} else {
			rows = nil
		}
		if len(rows) > input.Limit {
			rows = rows[:input.Limit]
		}
		out.Body.Items = make([]CoverageBody, 0, len(rows))
		for _, row := range rows {
			body := CoverageBody{
				Product:    row.Product,
				Stream:     row.Stream,
				StreamKind: row.StreamKind,
				Variant:    row.Variant,
				QuietDays:  int(row.Since.Hours() / 24),
				Quiet:      row.Quiet,
				Retired:    row.Retired,
			}
			if row.LastReceivedAt != nil {
				body.LastReceivedAt = stamp(*row.LastReceivedAt)
			}
			if row.LastRefusedAt != nil {
				body.LastRefusedAt = stamp(*row.LastRefusedAt)
			}
			if row.RefusedBecause != nil {
				body.RefusedBecause = *row.RefusedBecause
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}

// registerCoverageExport writes coverage out as a file.
//
// Coverage is the report whose whole point is what is *not* there, and the
// people who ask for it — an auditor, a release manager, whoever owns the
// pipeline that stopped — are usually not the people with an account here.
//
// The threshold is stated in the file. A `quiet` column of true and false
// means nothing six months later without the number it was computed against,
// and a spreadsheet has nowhere else to carry it.
func registerCoverageExport(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-scanning", Method: http.MethodGet,
		Path:    "/v1/scanning.{format}",
		Summary: "Export when each build was last scanned",
		Description: "Every build you can see, longest-silent first, as a file: when a scan " +
			"last arrived, how long it has been, and whether that is longer than this " +
			"deployment allows.\n\n" +
			"`quiet_days` is measured from the last arrival, or from when the build was " +
			"declared where nothing has ever been filed against it — `last_received_at` is " +
			"empty in that case, which is a different situation from a scan that failed.\n\n" +
			"A build whose release is out of support is in the file, marked `retired`, and is " +
			"never reported as quiet: silence there is expected. Leaving it out and saying " +
			"nothing would be a different answer.\n\n" +
			"The threshold `quiet` was computed against is stated in the file.",
		Tags: []string{"Scans"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		ScopeQuery
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		quietAfter, err := setting.NewStore(in.DB.DB).Duration(ctx, setting.QuietAfter, setting.DefaultQuietAfter)
		if err != nil {
			return nil, wentWrong(in.Logger, "the settings could not be read", err)
		}
		// Read once and paged out of the slice, because the reader answers
		// whole: asking it again per page would re-run the same statement and
		// re-sort the same estate for every two hundred rows.
		rows, err := ingest.NewStore(in.DB.DB).Scanning(ctx, subject, scope, quietAfter)
		if err != nil {
			// The last scan of a build by anybody is a person's
			// question, and the store says so. Answered as a fault, it reads
			// as the deployment being broken rather than as this credential
			// not being the one to ask.
			return nil, refused(in.Logger, err, "what has been scanned could not be read")
		}
		out := Exporting{
			What:  "scanning",
			About: []Stated{{"quiet after days", strconv.Itoa(int(quietAfter.Hours() / 24))}},
			Header: []string{
				"product", "stream", "kind", "variant",
				"last_received_at", "last_refused_at", "refused_because",
				"quiet_days", "quiet", "retired",
			},
			Rows: func(_ context.Context, limit, offset int) ([][]string, error) {
				if offset >= len(rows) {
					return nil, nil
				}
				page := rows[offset:]
				if len(page) > limit {
					page = page[:limit]
				}
				written := make([][]string, 0, len(page))
				for _, row := range page {
					last := ""
					if row.LastReceivedAt != nil {
						last = stamp(*row.LastReceivedAt)
					}
					refused, why := "", ""
					if row.LastRefusedAt != nil {
						refused = stamp(*row.LastRefusedAt)
					}
					if row.RefusedBecause != nil {
						why = *row.RefusedBecause
					}
					written = append(written, []string{
						row.Product, row.Stream, row.StreamKind, row.Variant, last,
						refused, why,
						strconv.Itoa(int(row.Since.Hours() / 24)),
						strconv.FormatBool(row.Quiet),
						strconv.FormatBool(row.Retired),
					})
				}
				return written, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "scanning", out)
		}}, nil
	})
}
