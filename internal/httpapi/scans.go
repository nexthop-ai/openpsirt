// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

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
	BuiltAt string `json:"built_at,omitempty" doc:"The build time the producer states, or the time the upload arrived where it states none"`
	// DatedOnArrival says the build time is the arrival time, because the
	// inventory stated none.
	DatedOnArrival bool `json:"dated_on_arrival,omitempty" doc:"Whether the inventory stated no build time, so the time it arrived orders it instead"`
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
	case !subject.TriagesIn(named.ProductID):
		return nil, huma.Error403Forbidden("not authorized")
	}

	// A retired product, release or variant takes no scan. It is the other
	// half of retiring one: the lists stop offering it and this stops a
	// pipeline still configured for it filing against it anyway. The refusal
	// says what to do, because what has to change is a build script somebody
	// maintains.
	//
	// After authorization, so that a sender who may not file against this
	// product cannot learn from the refusal that the name exists at all.
	//
	// The outermost first: a product retired with its releases still in use is
	// answered about the product, which is the thing somebody has to bring
	// back. Spelled back as the sender sent it, because what they have to go
	// and change is their own configuration.
	var retired string
	switch {
	case named.ProductRetired:
		retired = fmt.Sprintf("product %q", input.Product)
	case named.StreamRetired:
		retired = fmt.Sprintf("release %q of %q", input.Stream, input.Product)
	case named.VariantRetired:
		retired = fmt.Sprintf("variant %q of %q", input.Variant, input.Product)
	}
	if retired != "" {
		return nil, huma.NewError(http.StatusConflict, fmt.Sprintf(
			"%s is retired and takes no scan; declare it again to bring it back", retired))
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

	// The submission and its digest: what it says about itself comes from the
	// inventory, and whether we already hold it is asked of everything that
	// arrived. Every door that turns an upload away records it, not only the
	// last one. A producer posting a document nothing can read never reaches
	// the arm below, so the build draws as quiet-and-never-refused — which the
	// coverage report reads as a pipeline nobody wired up, telling the wrong
	// person about the commoner of the two failures this record exists for.
	note := func(reason string, builtAt *time.Time, hash *string) {
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

	// A document that does not say when it was built is ordered by when it
	// arrived, since both formats leave the build time optional. The store
	// dates it, because the store knows whether these bytes are already held.
	dated := header.BuiltAt.IsZero()
	stated := &header.BuiltAt
	if dated {
		stated = nil
	}

	arriving := ingest.Arriving{
		TargetID:      target.ID,
		ContentHash:   contentHash,
		InventoryHash: inventoryHash,
		Serial:        header.Serial,
		BuiltAt:       header.BuiltAt,
		ParserVersion: version.Get().Version,
		// Who sent this, recorded alongside the parser version, so the
		// provenance of the data has an answer.
		Credential: ingest.Sender(subject),
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
		// with no build time is dated on arrival above, so a branch here asks a
		// question already answered.
		result = UploadResult{
			ScanID: scan.ID, Serial: header.Serial, BuiltAt: stamp(scan.BuiltAt),
			DatedOnArrival: dated,
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
		note(refused.Error(), stated, &contentHash)
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

// stamp renders a time the one way the API states times.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
