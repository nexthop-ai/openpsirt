// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// RunChangeBody is the change one run made, by the rating in force.
//
// Named for the run rather than "Changed", because the schema registry keys
// types by their bare name and a report already has one — two types called the
// same thing in one schema is a collision that surfaces as a panic at start-up.
type RunChangeBody struct {
	Total    int `json:"total" doc:"Issues at components, the unit every count here uses"`
	Critical int `json:"critical,omitempty"`
	High     int `json:"high,omitempty"`
	Medium   int `json:"medium,omitempty" doc:"Includes anything rated by a word nothing recognizes, which is treated as unknown rather than as harmless"`
	Low      int `json:"low,omitempty"`
}

// RunBody is one run of the scanner and what it did.
type RunBody struct {
	RunID           int64  `json:"run_id"`
	Scanner         string `json:"scanner"`
	ScannerVersion  string `json:"scanner_version,omitempty"`
	DatabaseVersion string `json:"database_version,omitempty" doc:"The vulnerability database it read"`
	RanHere         bool   `json:"ran_here,omitempty" doc:"We ran the scanner, rather than the build sending what its own found"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at,omitempty" doc:"Absent while it is still going"`
	Failure         string `json:"failure,omitempty" doc:"The reason it produced nothing"`
	Caution         string `json:"caution,omitempty" doc:"The scanner's own words while succeeding — a qualification on what it found rather than a failure"`

	Opened RunChangeBody `json:"opened"`
	Closed RunChangeBody `json:"closed"`
	// OpenedExploited is the one number that decides whether a jump of four
	// thousand is an evening's work or a night's.
	OpenedExploited int `json:"opened_exploited,omitempty" doc:"The number it opened that somebody is known to be exploiting"`
}

// registerRun answers what one run of the scanner did.
func registerRun(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-scan-run", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/runs/{run}",
		Summary: "Show what one run of the scanner did",
		Description: "One run, with what it was measured with and what it changed — broken " +
			"down by the rating in force, and with how much of what it opened is known to be " +
			"exploited.\n\n" +
			"A receipt says a run happened; this says what it did. A row reading \"7,604 " +
			"opened\" is a number with no shape, and somebody looking at a build that jumped " +
			"overnight is asking which of them matter.\n\n" +
			"Counted as issues at components, the unit every other count here uses: a " +
			"component reached twenty ways carries the same issue twenty times, so counting " +
			"rows would report how much the dependency graph shares rather than how much " +
			"changed.\n\n" +
			"Derived when it is asked for rather than stored, so it moves as findings close " +
			"and reopen — and narrowed by what you may see, like every other count here.",
		Tags: []string{"Ingest"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Run     int64  `path:"run" doc:"The run, as a receipt or a finding names it"`
	}) (*struct{ Body RunBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := locatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.logger())
		}
		ran, err := finding.NewStore(in.DB.DB).Ran(ctx, subject, target.ID, input.Run)
		if err != nil {
			return nil, absent(in.Logger, err, "that run could not be looked up",
				func() error { return huma.Error404NotFound("no such run on this build") })
		}
		body := RunBody{
			RunID: ran.RunID, Scanner: ran.Scanner, ScannerVersion: ran.ScannerVersion,
			DatabaseVersion: ran.DatabaseVersion, RanHere: ran.RanHere,
			StartedAt: stamp(ran.StartedAt),
			Failure:   ran.Failure, Caution: ran.Caution,
			Opened:          runChangeBody(ran.Opened, ran.OpenedBy),
			Closed:          runChangeBody(ran.Closed, ran.ClosedBy),
			OpenedExploited: ran.OpenedExploited,
		}
		if ran.FinishedAt != nil {
			body.FinishedAt = stamp(*ran.FinishedAt)
		}
		return &struct{ Body RunBody }{Body: body}, nil
	})
}

// runChangeBody turns a run's counts into the shape the screen reads.
func runChangeBody(total int, by map[string]int) RunChangeBody {
	return RunChangeBody{
		Total:    total,
		Critical: by["critical"], High: by["high"],
		Medium: by["medium"], Low: by["low"],
	}
}
