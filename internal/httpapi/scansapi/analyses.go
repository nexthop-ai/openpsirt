// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// analysisParts is what an analyzer's run arrives as: its documents, and what
// it says about itself where the documents do not.
type analysisParts struct {
	SARIF []huma.FormFile `form:"sarif" contentType:"application/sarif+json,application/json,application/gzip,application/octet-stream" required:"true"`
	// The values below fill what the documents leave unstated. Numbers are
	// sent as text so that an absent one and a zero are told apart.
	Series        string   `form:"series" required:"false" doc:"Which analysis this is, the same for every build: the tool and its configuration"`
	Commit        string   `form:"commit" required:"false" doc:"The commit analyzed, at the top of the checkout"`
	Built         string   `form:"built" required:"false" doc:"When the build was made, in RFC 3339. Runs are ordered by it"`
	ToolVersion   string   `form:"tool-version" required:"false" doc:"The analyzer's version"`
	Rules         []string `form:"rules" required:"false" doc:"The rules enabled, one identifier per field"`
	UnitsExpected string   `form:"units-expected" required:"false" doc:"How many translation units the run was meant to analyze, as a whole number"`
	UnitsAnalyzed string   `form:"units-analyzed" required:"false" doc:"How many it analyzed, as a whole number"`
	ExitStatus    string   `form:"exit-status" required:"false" doc:"The analyzer's exit status, as a whole number"`
	SourceRoot    string   `form:"source-root" required:"false" doc:"The checkout's absolute path on the build host, which every path is placed against"`
	ThirdParty    []string `form:"third-party" required:"false" doc:"A path, relative to the checkout, holding code the product did not write"`
}

// AnalysisInput is an arriving analyzer run.
type AnalysisInput struct {
	Product string `path:"product" doc:"The declared product this build is of"`
	Stream  string `path:"stream" doc:"The declared branch or tag"`
	Variant string `path:"variant" doc:"The declared way that stream is built"`
	RawBody huma.MultipartFormFiles[analysisParts]
}

// AnalysisOutput is what became of it.
type AnalysisOutput struct {
	Status int
	Body   AnalysisResult
}

// AnalysisResult is the pipeline's answer.
type AnalysisResult struct {
	RunID          int64  `json:"run_id" doc:"The run this upload became, or the one it matched"`
	Outcome        string `json:"outcome" enum:"queued,already_held" doc:"Whether this upload was taken or matched one already held"`
	Series         string `json:"series" doc:"The series the run belongs to"`
	BuiltAt        string `json:"built_at" doc:"The build time the run states, or the time it arrived where it states none"`
	DatedOnArrival bool   `json:"dated_on_arrival,omitempty" doc:"Whether the run stated no build time, so the time it arrived orders it instead"`
}

func registerAnalyses(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "upload-analysis",
		Method:      http.MethodPost,
		Path:        "/v1/products/{product}/streams/{stream}/variants/{variant}/analyses",
		Summary:     "Upload static analysis results",
		Description: "Accepts one analyzer run as SARIF 2.1.0 documents in repeated multipart fields " +
			"named `sarif`, each optionally compressed with gzip. The other fields fill what the " +
			"documents leave unstated; where both state a value, the documents win.\n\n" +
			"The series names the analysis and is required, in the `series` field or as the part " +
			"of each run's `automationDetails.id` before its last slash.\n\n" +
			"Returns 202 once the documents are read and their results placed and stored, before any result " +
			"is applied. The documents themselves are not stored. " +
			"Poll `GET .../analyses` for what the run did. The same documents for the same series " +
			"and build answer 200 with the run they match.\n\n" +
			"A dependency or secret scanner's run is left out and named on the receipt; this " +
			"upload takes static analysis alone, and refuses one holding nothing else.",
		Tags:         []string{"Ingest"},
		MaxBodyBytes: analysisLimits(in).MaxBytes + core.Envelope,
		Middlewares: huma.Middlewares{core.BoundedForm(api, in, core.Admission{
			Admit: func(hc huma.Context) error {
				_, _, err := admittedAnalysis(hc.Context(), in, hc.Param("product"), hc.Param("stream"), hc.Param("variant"))
				return err
			},
			Limit:   core.Fixed(analysisLimits(in).MaxBytes + core.Envelope),
			Refused: analysisRefusedBeforeReading(in),
		})},
		DefaultStatus: http.StatusAccepted,
	}, core.PerProduct, "A pipeline key covering this product, branch and variant sends without it, "+
		"and is how a build sends.", access.InternalTriage), func(ctx context.Context, input *AnalysisInput) (*AnalysisOutput, error) {
		return uploadAnalysis(ctx, in, input)
	})
}

// analysisLimits is what an analyzer's documents are read within here.
func analysisLimits(in core.Deps) sarif.Limits { return in.Analysis.OrDefault() }

// analysisDocuments is how many documents one upload may carry.
func analysisDocuments(in core.Deps) int {
	if in.AnalysisDocuments > 0 {
		return in.AnalysisDocuments
	}
	return sarif.DefaultDocuments
}

func uploadAnalysis(ctx context.Context, in core.Deps, input *AnalysisInput) (*AnalysisOutput, error) {
	parts := input.RawBody.Data()
	subject, named, err := admittedAnalysis(ctx, in, input.Product, input.Stream, input.Variant)
	if err != nil {
		return nil, err
	}
	// Every refusal past this point is recorded against the build and the
	// series, as far as the upload got in naming it.
	seriesName := strings.TrimSpace(parts.Series)
	refused := func(answer error) error {
		var said huma.StatusError
		if errors.As(answer, &said) && said.GetStatus() < http.StatusInternalServerError {
			analysisRefused(ctx, in, subject, named, seriesName, answer.Error())
		}
		return answer
	}

	var files []huma.FormFile
	for _, part := range parts.SARIF {
		if part.IsSet {
			files = append(files, part)
		}
	}
	if most := analysisDocuments(in); len(files) > most {
		return nil, refused(huma.Error422UnprocessableEntity(fmt.Sprintf(
			"that run carries %d documents, and this deployment reads %d; merge a tool's per-unit documents into one before sending",
			len(files), most)))
	}

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
		return nil, refused(huma.NewError(http.StatusConflict, fmt.Sprintf(
			"%s is retired and takes no analysis; declare it again to bring it back", retired)))
	}

	depth, err := in.Queue.Depth(ctx, queue.Analyze)
	if err != nil {
		return nil, core.WentWrong(in.Logger, "cannot tell how much work is waiting", err)
	}
	limit, err := in.Queue.Backlog(ctx)
	if err != nil {
		return nil, core.WentWrong(in.Logger, "cannot tell how much work may wait", err)
	}
	if depth >= limit {
		return nil, huma.NewError(http.StatusServiceUnavailable,
			fmt.Sprintf("%d analyzer runs are already waiting to be applied; try again shortly", depth))
	}

	given, err := statedBeside(parts)
	if err != nil {
		return nil, refused(huma.Error422UnprocessableEntity(err.Error()))
	}
	logs, digests, err := readAnalysis(files, analysisLimits(in))
	var turned refusal.Refusal
	switch {
	case errors.As(err, &turned):
		return nil, refused(huma.Error422UnprocessableEntity("the upload could not be read: " + err.Error()))
	case err != nil:
		return nil, core.WentWrong(in.Logger, "the upload could not be read", err)
	}
	stated := analysis.Describe(logs, given)
	seriesName = strings.TrimSpace(stated.Series)
	hash := analysis.RunHash(digests, stated.BuiltAt)
	repositories, err := sourcelink.NewStore(in.DB.DB).Config(ctx, named.ProductID)
	if err != nil {
		return nil, core.WentWrong(in.Logger, "the product's repository settings could not be read", err)
	}
	placed, err := analysis.Place(logs, strings.TrimSpace(parts.SourceRoot), analysisLimits(in).MaxBytes,
		repositories.Snippets)
	switch {
	case errors.As(err, &turned):
		return nil, refused(huma.Error422UnprocessableEntity("the upload could not be read: " + err.Error()))
	case err != nil:
		return nil, core.WentWrong(in.Logger, "the upload could not be placed", err)
	}
	dated := stated.BuiltAt.IsZero()
	if dated {
		stated.BuiltAt = time.Now().UTC()
	}

	target, err := catalog.NewStore(in.DB.DB).TargetFor(ctx, named.StreamID, named.VariantID)
	if err != nil {
		return nil, core.WentWrong(in.Logger, "the target could not be recorded", err)
	}

	var (
		run    *series.Run
		repeat bool
	)
	err = database.InTransaction(ctx, in.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		store := series.NewStore(tx)
		var err error
		run, repeat, err = store.Receive(ctx, series.Arriving{
			ProductID: named.ProductID, TargetID: target.ID, Kind: kind.Analysis,
			Series: stated.Series, ContentHash: hash, Commit: stated.Commit, BuiltAt: stated.BuiltAt,
			Credential: access.Sender(subject), Params: stated.Params,
		})
		if err != nil || repeat {
			return err
		}
		if err := placed.Hold(ctx, store, run.ID); err != nil {
			return err
		}
		_, err = in.Queue.AddTx(ctx, tx, queue.Analyze, strconv.FormatInt(run.ID, 10))
		return err
	})
	switch {
	case errors.Is(err, queue.ErrBacklogFull):
		return nil, huma.NewError(http.StatusServiceUnavailable, err.Error())
	case errors.As(err, &turned):
		return nil, refused(huma.Error422UnprocessableEntity(err.Error()))
	case err != nil:
		return nil, core.WentWrong(in.Logger, "the upload could not be recorded", err)
	}

	out := &AnalysisOutput{Status: http.StatusAccepted, Body: AnalysisResult{
		RunID: run.ID, Outcome: "queued", Series: strings.TrimSpace(stated.Series),
		BuiltAt: core.Stamp(run.BuiltAt), DatedOnArrival: dated && !repeat,
	}}
	if repeat {
		out.Status, out.Body.Outcome = http.StatusOK, "already_held"
	}
	return out, nil
}

// statedBeside is what the request's fields say about the run.
func statedBeside(parts *analysisParts) (analysis.Stated, error) {
	out := analysis.Stated{Series: strings.TrimSpace(parts.Series), Commit: strings.TrimSpace(parts.Commit)}
	if built := strings.TrimSpace(parts.Built); built != "" {
		t, err := time.Parse(time.RFC3339, built)
		if err != nil {
			return out, fmt.Errorf("built is %q, which is not an RFC 3339 time", built)
		}
		out.BuiltAt = t
	}
	out.Params.ToolVersion = strings.TrimSpace(parts.ToolVersion)
	out.Params.RulesDigest, out.Params.RulesCount = analysis.RuleSet(parts.Rules)
	for _, n := range []struct {
		name  string
		value string
		into  **int
	}{
		{"units-expected", parts.UnitsExpected, &out.Params.UnitsExpected},
		{"units-analyzed", parts.UnitsAnalyzed, &out.Params.UnitsAnalyzed},
		{"exit-status", parts.ExitStatus, &out.Params.ExitStatus},
	} {
		value := strings.TrimSpace(n.value)
		if value == "" {
			continue
		}
		v, err := strconv.Atoi(value)
		if err != nil {
			return out, fmt.Errorf("%s is %q, which is not a whole number", n.name, value)
		}
		*n.into = &v
	}
	if (out.Params.UnitsExpected == nil) != (out.Params.UnitsAnalyzed == nil) {
		return out, fmt.Errorf("units-expected and units-analyzed are sent together or not at all")
	}
	var paths []string
	for _, p := range parts.ThirdParty {
		// Cleaned as a path from the top of the checkout, which is how a
		// lead's path is compared against it: "./src/vendor" and
		// "src//vendor/" are "src/vendor", and nothing climbs above the top.
		if p = strings.Trim(path.Clean("/"+strings.TrimSpace(p)), "/"); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) > 0 {
		slices.Sort(paths)
		said, err := json.Marshal(slices.Compact(paths))
		if err != nil {
			return out, err
		}
		out.Params.ThirdParty = string(said)
	}
	return out, nil
}

// readAnalysis reads each document within one budget for the upload, and
// digests each as it arrived.
func readAnalysis(files []huma.FormFile, limits sarif.Limits) ([]sarif.Log, []string, error) {
	logs := make([]sarif.Log, 0, len(files))
	digests := make([]string, 0, len(files))
	upload := sarif.NewUpload(limits)
	for i, file := range files {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, nil, err
		}
		digest := sha256.New()
		log, err := upload.Read(io.TeeReader(file, digest))
		if err != nil {
			return nil, nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		if _, err := io.Copy(digest, file); err != nil {
			return nil, nil, err
		}
		logs = append(logs, log)
		digests = append(digests, hex.EncodeToString(digest.Sum(nil)))
	}
	return logs, digests, nil
}

// analysisRefused records that an analyzer upload to a build was turned away,
// against the series as far as the upload named it.
//
// Best-effort, as a scan refusal is: a note about something that already
// failed, where failing the failure would turn a refusal the sender needs to
// read into a fault they cannot.
func analysisRefused(ctx context.Context, in core.Deps, subject access.Subject, named *catalog.Named,
	name, reason string) {

	target, err := catalog.NewStore(in.DB.DB).TargetFor(ctx, named.StreamID, named.VariantID)
	if err == nil {
		var credential *string
		if sender := access.Sender(subject); sender != "" {
			credential = &sender
		}
		err = series.NewStore(in.DB.DB).Refused(ctx, series.Refusal{
			TargetID: target.ID, Series: name, Kind: kind.Analysis, Reason: reason, Credential: credential,
		})
	}
	if err != nil {
		in.Log().ErrorContext(ctx, "could not record that an analyzer upload was refused",
			"error", err, "product", named.Product)
	}
}

// analysisRefusedBeforeReading records an analyzer upload the form bound
// turned away before the operation ran. The bound asks it only once the
// sender has been admitted to the build.
func analysisRefusedBeforeReading(in core.Deps) func(huma.Context, string) {
	return func(hctx huma.Context, reason string) {
		ctx := hctx.Context()
		subject, named, err := admittedAnalysis(ctx, in, hctx.Param("product"), hctx.Param("stream"),
			hctx.Param("variant"))
		if err != nil {
			return
		}
		analysisRefused(ctx, in, subject, named, "", reason)
	}
}

// admittedAnalysis is the sender and the build an analyzer upload names. A
// person sends where they triage internal findings in the product, which is
// what every result opens as.
func admittedAnalysis(ctx context.Context, in core.Deps, product, stream, variant string) (
	access.Subject, *catalog.Named, error) {

	subject, named, err := admitted(ctx, in, product, stream, variant)
	if err != nil {
		return access.Subject{}, nil, err
	}
	if subject.Kind != access.Pipeline && !subject.Triages(analysis.OpensAt, named.ProductID) {
		return access.Subject{}, nil, huma.Error403Forbidden("not authorized")
	}
	return subject, named, nil
}
