// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// coverageOutput carries the rows and what was asked of them, because "quiet"
// is a judgment against a threshold and a reader cannot check the judgment
// without the threshold.
type coverageOutput struct {
	Body struct {
		Items []CoverageBody `json:"items"`
		// Quiet is how many of the rows are, so a caller can say so without
		// counting them again.
		Quiet int `json:"quiet" doc:"The number gone quiet, across every build and not only this page"`
		// The rest are counted here for the same reason, and because a caller
		// recomputing any of them from the page it was handed states a figure
		// about the page under a heading about the estate.
		Never          int `json:"never" doc:"The number in support and in use never scanned, across every build and not only this page. Those gone quiet are among the quiet as well"`
		Unsupported    int `json:"unsupported" doc:"The number out of support, across every build and not only this page. Silence there is expected, so these are never counted as quiet"`
		Retired        int `json:"retired" doc:"The number in support and taken out of use, across every build and not only this page. Nothing may be filed against these, so they are never counted as quiet"`
		Scanned        int `json:"scanned" doc:"The number in support and in use that a scan has reached and that have not gone quiet, across every build and not only this page"`
		Total          int `json:"total" doc:"The number of builds to report on"`
		QuietAfterDays int `json:"quiet_after_days" doc:"The span this deployment allows, in days"`
	}
}

// CoverageBody is one declared build and when a scan last arrived for it.
type CoverageBody struct {
	Product    string        `json:"product"`
	Stream     string        `json:"stream"`
	StreamKind core.LineKind `json:"stream_kind" doc:"Whether this line moves"`
	Variant    string        `json:"variant"`
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
	// OutOfSupport is reported rather than the row being left out. A release that
	// stopped being scanned because it stopped being supported is expected
	// rather than a fault, but "not scanned, and that is fine" and "not
	// listed" are different answers.
	OutOfSupport bool `json:"out_of_support,omitempty" doc:"Whether this build's release is out of support, in which case silence is expected and it is never reported as quiet"`
	// RetiredFromUse is the other reason silence is expected, and a different
	// one: nothing may be filed against this build at all.
	RetiredFromUse bool `json:"retired,omitempty" doc:"Whether the product, release or variant has been taken out of use. No scan may be filed against it, so it is never reported as quiet"`
}

// coverageCounts is the estate a coverage answer counts, by the one state each
// build is in. Quiet is the exception: a build in use and never scanned can be
// quiet too, and is counted in both.
type coverageCounts struct {
	quiet, never, unsupported, retired, scanned int
}

// countCoverage sorts every build into the state it is in. Out of support
// comes first and taken out of use second, because silence is expected of
// both; of what is left, a build a scan has never reached is never scanned,
// and one reached and not quiet is scanned.
func countCoverage(rows []ingest.Coverage) coverageCounts {
	var out coverageCounts
	for _, row := range rows {
		if row.Quiet {
			out.quiet++
		}
		switch {
		case row.OutOfSupport:
			out.unsupported++
		case row.RetiredFromUse:
			out.retired++
		case row.LastReceivedAt == nil:
			out.never++
		case !row.Quiet:
			out.scanned++
		}
	}
	return out
}

func registerCoverage(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-scanning", Method: http.MethodGet, Path: "/v1/scanning",
		Summary: "List when each build was last scanned",
		Description: "Returns every build you can see, longest-silent first, with when a scan " +
			"last arrived for it and whether that is longer ago than this deployment allows.\n\n" +
			"A build that stops being scanned reports no new findings and fails nothing, so it " +
			"looks healthier than one that is still being scanned. A build nothing has ever " +
			"been filed against is measured from when it was declared.\n\n" +
			"How long counts as quiet is the `scanning.quiet-after` setting.",
		Tags: []string{"Scans"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		core.ScopeQuery
		Limit  int `query:"limit" default:"200" minimum:"1" maximum:"500" doc:"The number returned. Quietest first, so the default is the answer for any estate somebody reads by hand"`
		Offset int `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*coverageOutput, error) {
		rows, quietAfter, err := scanningRows(ctx, in, input.ScopeQuery)
		if err != nil {
			return nil, err
		}

		out := &coverageOutput{}
		out.Body.QuietAfterDays = int(quietAfter.Hours() / 24)
		out.Body.Total = len(rows)
		// Counted before the page is cut, and across the whole answer rather
		// than the page: a badge saying "3" because three quiet builds fall
		// on the first page answers a different question from the one it
		// appears to.
		counted := countCoverage(rows)
		out.Body.Quiet, out.Body.Never = counted.quiet, counted.never
		out.Body.Unsupported, out.Body.Retired = counted.unsupported, counted.retired
		out.Body.Scanned = counted.scanned
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
				Product:        row.Product,
				Stream:         row.Stream,
				StreamKind:     core.LineKind(row.StreamKind),
				Variant:        row.Variant,
				QuietDays:      int(row.Since.Hours() / 24),
				Quiet:          row.Quiet,
				OutOfSupport:   row.OutOfSupport,
				RetiredFromUse: row.RetiredFromUse,
			}
			if row.LastReceivedAt != nil {
				body.LastReceivedAt = core.Stamp(*row.LastReceivedAt)
			}
			if row.LastRefusedAt != nil {
				body.LastRefusedAt = core.Stamp(*row.LastRefusedAt)
			}
			if row.RefusedBecause != nil {
				body.RefusedBecause = *row.RefusedBecause
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}

// scanningRows is when each build the reader may see in the scope was last
// scanned, with the threshold past which a build counts as quiet.
func scanningRows(ctx context.Context, in core.Deps, q core.ScopeQuery) ([]ingest.Coverage, time.Duration, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return nil, 0, err
	}
	if in.DB == nil {
		return nil, 0, core.NoDatabase(in.Logger)
	}
	scope, err := core.Scoped(ctx, in, subject, q)
	if err != nil {
		return nil, 0, err
	}
	quietAfter, err := setting.NewStore(in.DB.DB).Duration(ctx, setting.QuietAfter, setting.DefaultQuietAfter)
	if err != nil {
		return nil, 0, core.WentWrong(in.Logger, "the settings could not be read", err)
	}
	rows, err := ingest.NewStore(in.DB.DB).Scanning(ctx, subject, scope, quietAfter)
	if err != nil {
		// The last scan of a build by anybody is a person's question, and the
		// store says so. Answered as a fault, it reads as the deployment being
		// broken rather than as this credential not being the one to ask.
		return nil, 0, core.Refused(in.Logger, err, "what has been scanned could not be read")
	}
	return rows, quietAfter, nil
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
func registerCoverageExport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-scanning", Method: http.MethodGet,
		Path:    "/v1/scanning.{format}",
		Summary: "Export when each build was last scanned",
		Description: "Every build you can see, longest-silent first, as a file: when a scan " +
			"last arrived, how long it has been, and whether that is longer than this " +
			"deployment allows.\n\n" +
			"`quiet_days` is measured from the last arrival, or from when the build was " +
			"declared where nothing has ever been filed against it — `last_received_at` is " +
			"empty in that case, which is a different situation from a scan that failed.\n\n" +
			"A build whose release is out of support is in the file, marked `out_of_support`, " +
			"and is never reported as quiet. A build taken out of use is marked `retired` and " +
			"is never reported as quiet either.\n\n" +
			"The threshold `quiet` was computed against is stated in the file.",
		Tags: []string{"Scans"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		core.ScopeQuery
	}) (*huma.StreamResponse, error) {
		// Read once and paged out of the slice, because the reader answers
		// whole: asking it again per page would re-run the same statement and
		// re-sort the same estate for every two hundred rows.
		rows, quietAfter, err := scanningRows(ctx, in, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		out := core.Exporting{
			What:  "scanning",
			About: []core.Stated{{Label: "quiet after days", Value: strconv.Itoa(int(quietAfter.Hours() / 24))}},
			Header: []string{
				"product", "stream", "kind", "variant",
				"last_received_at", "last_refused_at", "refused_because",
				"quiet_days", "quiet", "out_of_support", "retired",
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
						last = core.Stamp(*row.LastReceivedAt)
					}
					refused, why := "", ""
					if row.LastRefusedAt != nil {
						refused = core.Stamp(*row.LastRefusedAt)
					}
					if row.RefusedBecause != nil {
						why = *row.RefusedBecause
					}
					written = append(written, []string{
						row.Product, row.Stream, row.StreamKind, row.Variant, last,
						refused, why,
						strconv.Itoa(int(row.Since.Hours() / 24)),
						strconv.FormatBool(row.Quiet),
						strconv.FormatBool(row.OutOfSupport),
						strconv.FormatBool(row.RetiredFromUse),
					})
				}
				return written, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, "scanning", out)
		}}, nil
	})
}
