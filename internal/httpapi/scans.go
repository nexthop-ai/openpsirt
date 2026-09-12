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
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// Ingest is what the upload endpoint needs to do its job.
type Ingest struct {
	DB     *database.DB
	Queue  *queue.Queue
	Limits sbom.Limits
	// Access resolves who is asking. A nil resolver means nothing is
	// authorized, which is what a process that cannot tell who is asking
	// should answer.
	Access *access.Resolver
	// Logger records a fault where an operator can read it, rather than
	// describing it to whoever asked.
	Logger *slog.Logger
	// Replica names this process where several run the same binary, so work
	// that must happen once can be held by one of them. Empty is a deployment
	// of one, which is what a test and a development run both are.
	Replica string
	// PlainHTTP says this deployment is served without TLS, which is what
	// running it locally looks like. It only ever loosens a cookie, so it is
	// named for what it is rather than for what it switches off.
	PlainHTTP bool
	// Interface is the built web interface, where this binary was built with
	// one. Zero serves the API alone, which is what a development build and an
	// API-only deployment both look like.
	Interface Interface
	// Providers are the ways somebody may sign in, by the name a URL uses.
	// Empty means none is configured, and the sign-in paths are not mounted at
	// all rather than mounted and answering that nothing is available.
	Providers map[string]signin.Provider
	// BaseURL is the address people arrive on, which behind a proxy is not
	// what this process thinks it is called. A provider compares the callback
	// against what it was registered with, so this has to be the outside one.
	BaseURL string
	// SessionLifetime bounds a sign-in. Zero takes the default.
	SessionLifetime time.Duration
	// Publisher is who an advisory says issued it. Unstated means no advisory
	// is generated, and the refusal says which part is missing — a document
	// naming no publisher is not a CSAF document, and handing one over would
	// fail wherever somebody took it next.
	Publisher publisher.Named
	// Mode says where roles come from. Read per request rather than held, so
	// an administrator turning group binding off takes effect at once.
	Mode func(context.Context) access.Mode
	// Files is where attachments are kept. Nil is a deployment that holds
	// none, which is ordinary: attachments are off and everything else
	// works .
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

// catalog returns a store over this deployment's database, or nothing when
// there is no database — which is the process that only renders the API
// document.
func (in Ingest) catalog() *catalog.Store {
	if in.DB == nil {
		return nil
	}
	return catalog.NewStore(in.DB.DB)
}

// trail returns a store over what has been changed administratively, or
// nothing where there is no database.
func (in Ingest) trail() *trail.Store {
	if in.DB == nil {
		return nil
	}
	return trail.NewStore(in.DB.DB)
}

// rights returns a store over who may do what, or nothing where there is no
// database.
func (in Ingest) rights() *access.Store {
	if in.DB == nil {
		return nil
	}
	return access.NewStore(in.DB.DB)
}

// uploadParts are the documents a build sends.
//
// One request carries the whole picture. A build whose inventory landed and
// whose suppressions did not would have every carried patch reported as an
// outstanding vulnerability, which is worse than the upload having failed.
type uploadParts struct {
	// Inventory is what the build shipped.
	//
	// The declared content type is deliberately permissive. What a part is
	// gets decided by reading it, not by the label a client put on it — and
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

// UploadOutput reports what became of it.
type UploadOutput struct {
	Status int
	Body   UploadResult
}

// UploadResult is what a producer gets back.
type UploadResult struct {
	ScanID int64 `json:"scan_id" doc:"The scan this upload became, or the one it matched"`
	// Outcome says what happened, in the producer's terms rather than ours.
	Outcome string `json:"outcome" enum:"queued,already_held" doc:"Whether this upload was taken or matched one already held"`
	Serial  string `json:"serial,omitempty" doc:"The identity the inventory carries for itself"`
	BuiltAt string `json:"built_at,omitempty" doc:"When the producer says the build was made"`
}

func registerScans(api huma.API, in Ingest) {
	// Registered whether or not there is a database behind it. The OpenAPI
	// document is generated from these registrations by a process that never
	// opens one, and an operation missing from the document because of how it
	// was generated is exactly the drift generating it is meant to prevent.
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
			"**Returns 202 before the documents are parsed.** A success here means they were " +
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

	// Who is sending, before anything is read or written.
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
		return nil, huma.Error404NotFound(err.Error())
	}

	// A key authorizes an upload; it does not describe one. Every
	// constraint it carries must match what this upload says it is for,
	// and a mismatch is refused rather than redirected — a key covering
	// one release must never quietly accept a scan of another.
	//
	// Refused here rather than answered as not-declared, deliberately.
	// Telling the two apart lets a key learn which releases and variants
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
	depth, err := in.Queue.Depth(ctx)
	if err != nil {
		return nil, wentWrong(in.Logger, "cannot tell how much work is waiting", err)
	}
	if depth >= in.Queue.MaxBacklog() {
		return nil, huma.NewError(http.StatusServiceUnavailable,
			fmt.Sprintf("%d scans are already waiting to be read; try again shortly", depth))
	}

	target, err := catalog.TargetFor(ctx, named.StreamID, named.VariantID)
	if err != nil {
		return nil, wentWrong(in.Logger, "the target could not be recorded", err)
	}

	// One pass over the inventory answers both questions asked of an arriving
	// scan: what it is, and whether we already hold it.
	header, contentHash, err := describe(parts.Inventory, in.Limits)
	if err != nil {
		return nil, huma.Error422UnprocessableEntity("the inventory could not be read", err)
	}

	// A document that does not say when it was built cannot be ordered against
	// anything, and taking it is worse than refusing it: the zero time is
	// older than every real one, so the first such upload is accepted and
	// every later scan for that target is refused as not newer. The target
	// takes no further scans at all, which is the same wedge the future-clock
	// check exists to prevent, arriving through a door nobody guarded.
	if header.BuiltAt.IsZero() {
		return nil, huma.Error400BadRequest(
			"the inventory does not say when it was built, and that is what orders scans against each other")
	}

	arriving := ingest.Arriving{
		TargetID:      target.ID,
		ContentHash:   contentHash,
		Serial:        header.Serial,
		BuiltAt:       header.BuiltAt,
		ParserVersion: version.Get().Version,
		// Which credential sent this. Recorded alongside the parser version so
		// that "where did this data come from" has an answer.
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
		result = UploadResult{ScanID: scan.ID, Serial: header.Serial}
		if !header.BuiltAt.IsZero() {
			result.BuiltAt = header.BuiltAt.UTC().Format(time.RFC3339)
		}
		if taken != ingest.Accept {
			return nil
		}

		// Everything from here commits together. A scan row without its
		// documents is unreadable, documents without a job are work nobody
		// picks up, and a job without either is a worker failing on something
		// that was never there.
		documents := ingest.NewDocuments(tx)
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
		return nil, rejection(outcome, err)
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

// describe reads what an inventory says about itself, and hashes it.
//
// Both in one pass: the file is seekable, but a second pass over tens of
// megabytes buys nothing.
func describe(file huma.FormFile, limits sbom.Limits) (sbom.Header, string, error) {
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

// store rewinds a part and puts it away.
func store(ctx context.Context, documents *ingest.Documents, scanID int64, kind ingest.Kind, ordinal int, file huma.FormFile) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := documents.Write(ctx, scanID, kind, ordinal, file)
	return err
}

// ReceiptBody is what became of one upload.
type ReceiptBody struct {
	ScanID     int64  `json:"scan_id" doc:"The scan this upload became"`
	Serial     string `json:"serial,omitempty" doc:"The identity the inventory carries for itself"`
	BuiltAt    string `json:"built_at,omitempty" doc:"When the producer says the build was made"`
	ReceivedAt string `json:"received_at" doc:"When it arrived here"`
	State      string `json:"state" enum:"reading,scanning,scanned,failed" doc:"How far it has got"`
	// Failure is the producer's own text back at them — what could not be read
	// and where. It is not a fault in this deployment, so it is reported
	// rather than logged away.
	Failure string `json:"failure,omitempty" doc:"Why it could not be used, where it could not"`
	// Caution qualifies the answer rather than saying there is none, so it is
	// reported beside a scan that succeeded rather than instead of one.
	Caution string `json:"caution,omitempty" doc:"What the scanner said while still succeeding — a qualification on what it found rather than a failure. Usually empty: the scan runs over an inventory written from what is held here, so most of what a scanner would warn about a producer's document it has no grounds to say about ours"`
	// What the run covering this upload changed, counted as issues at
	// components rather than as places. Absent where no run has covered it
	// yet, and absent on an upload whose run was already reported against a
	// newer one: a run covers a build rather than an upload.
	//
	// Pointers, because a run that changed nothing and an upload whose
	// numbers are reported on another receipt are different answers and zero
	// is only the first of them. Sent as a number they were the same value,
	// and the screen drew both as a dash — which reads as "this upload opened
	// nothing" against an upload nothing was read from.
	Opened *int `json:"opened,omitempty" doc:"Issues this run found that were not open before. Absent where this upload's run is reported against a newer one, or where none has covered it yet"`
	Closed *int `json:"closed,omitempty" doc:"Issues that were open and are not any more. Absent for the same reasons as the count beside it"`
	// Sent is what the upload was made of. It outlives the files themselves:
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
	Components *int `json:"components,omitempty" doc:"How many components the inventory described"`
	Placed     *int `json:"placed,omitempty" doc:"How many of them something placed in the graph"`
	// Measured is what the run answering *this* upload was made with,
	// rather than what the newest run was. On every receipt the run
	// answers, unlike opened and closed: the versions are a property of
	// the run rather than a change it made, and a page spanning a scanner
	// upgrade or a vulnerability database that stopped moving is exactly
	// what somebody reads this screen to notice.
	Measured *MeasuredBody `json:"measured,omitempty" doc:"What the run answering this upload was measured with. Absent until a run has covered it"`
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
	DocumentID int64  `json:"document_id" doc:"What to name to read this document back"`
	Kind       string `json:"kind" enum:"inventory,suppressions" doc:"What the document is"`
	SizeBytes  int64  `json:"size_bytes" doc:"How large it was"`
	Hash       string `json:"hash" doc:"SHA-256 of the bytes as they arrived"`
	// Held says the contents are still here. A tagged release keeps them,
	// because re-scanning it years from now needs what it contained; a branch
	// build's are let go, because the next night supersedes them.
	Held bool `json:"held" doc:"Whether the contents are still kept"`
}

// MeasuredBody is what the numbers on a build were arrived at with.
//
// Not decoration. A build reporting nothing wrong and a build last measured
// against a vulnerability database from March look identical on every screen
// without this, and they are not the same statement at all.
type MeasuredBody struct {
	Scanner         string `json:"scanner" doc:"Which scanner produced the findings"`
	ScannerVersion  string `json:"scanner_version,omitempty"`
	DatabaseVersion string `json:"database_version,omitempty" doc:"The vulnerability database it read"`
	RanAt           string `json:"ran_at,omitempty" doc:"When that run finished"`
	// RanHere says we ran it rather than a build sending what its own scanner
	// found. Counts are only comparable between builds measured the same way,
	// so a report mixing the two without saying would be a rumor.
	RanHere bool `json:"ran_here,omitempty" doc:"We ran the scanner, rather than the build sending what its own found"`
}

// ReceiptsOutput is a page of what has been filed against a build.
type ReceiptsOutput struct {
	Body struct {
		Items []ReceiptBody `json:"items"`
		Total int           `json:"total"`
		// MeasuredAgainst describes the build's last finished run rather than
		// any one upload, which is why it sits beside the page instead of on
		// each row.
		MeasuredAgainst *MeasuredBody `json:"measured_against,omitempty" doc:"What the last completed run was measured with"`
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
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"How many to return"`
		Offset  int    `query:"offset" minimum:"0" doc:"How many to skip"`
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
			return nil, huma.Error404NotFound(err.Error())
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
		if err != nil {
			return nil, wentWrong(in.Logger, "the scans could not be read", err)
		}
		// What each run changed, in one pair of statements for the page. A
		// scan that says only "scanned" leaves the reason to read it — what it
		// did — to a second screen.
		runs := make([]int64, 0, len(receipts))
		for _, r := range receipts {
			if r.RunID != nil {
				runs = append(runs, *r.RunID)
			}
		}
		changed, err := finding.NewStore(in.DB.DB).Changes(ctx, subject, target.ID, runs)
		if err != nil {
			return nil, wentWrong(in.Logger, "what the scans changed could not be read", err)
		}

		// What each upload was made of, for the page at once. The record
		// survives the contents, so a branch build reads back as what it sent
		// rather than as nothing — which is what it looked like before, and
		// looks identical to an upload that failed to store anything.
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

		// What those numbers were arrived at with. Read separately because it
		// describes the build rather than any upload, and absent rather than
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
		Quiet          int `json:"quiet" doc:"How many have gone quiet, across every build and not only this page"`
		Total          int `json:"total" doc:"How many builds there are to report on"`
		QuietAfterDays int `json:"quiet_after_days" doc:"How long this deployment allows, in days"`
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
	LastReceivedAt string `json:"last_received_at,omitempty" doc:"When a scan last arrived. Absent where none ever has"`
	QuietDays      int    `json:"quiet_days" doc:"How long it has been, in days, measured from the last arrival or from when the build was declared"`
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
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Limit  int `query:"limit" default:"200" minimum:"1" maximum:"500" doc:"How many to return. Quietest first, so the default is the answer for any estate somebody reads by hand"`
		Offset int `query:"offset" minimum:"0" doc:"How many to skip"`
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
			return nil, wentWrong(in.Logger, "what has been scanned could not be read", err)
		}

		out := &coverageOutput{}
		out.Body.QuietAfterDays = int(quietAfter.Hours() / 24)
		out.Body.Total = len(rows)
		// Counted before the page is cut, and the quiet ones counted across
		// the whole answer rather than the page: a badge that said "3" because
		// three quiet builds happened to fall on the first page would be
		// answering a different question from the one it looks like.
		for _, row := range rows {
			if row.Quiet {
				out.Body.Quiet++
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
// **The threshold is stated in the file.** A `quiet` column of true and false
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
	}, anySubject, "Exports only what you may see."), func(ctx context.Context, input *struct {
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
			return nil, wentWrong(in.Logger, "what has been scanned could not be read", err)
		}
		out := Exporting{
			About: [2]string{"quiet after days", strconv.Itoa(int(quietAfter.Hours() / 24))},
			Header: []string{
				"product", "stream", "kind", "variant",
				"last_received_at", "quiet_days", "quiet", "retired",
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
					written = append(written, []string{
						row.Product, row.Stream, row.StreamKind, row.Variant, last,
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
