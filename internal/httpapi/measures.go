// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// SpreadBody is a set of waits said in the three ways worth saying.
type SpreadBody struct {
	Band   string  `json:"band" doc:"The severity these were rated at. 'unrated' is what nobody scored"`
	Count  int     `json:"count" doc:"The number of observations behind it"`
	Median float64 `json:"median_days" doc:"The middle one, in days"`
	P90    float64 `json:"p90_days" doc:"The span nine in ten came in under, in days. Nearest-rank rather than interpolated: these are waits something actually had"`
	Worst  float64 `json:"worst_days" doc:"The longest single one, in days"`
}

// WorkedBody is one person's throughput.
type WorkedBody struct {
	Person    string `json:"person"`
	Proposed  int    `json:"proposed" doc:"Claims they made in the window"`
	Approved  int    `json:"approved" doc:"Claims they agreed to, dated by the agreement: an approver's week is the week they approved in"`
	Withdrawn int    `json:"withdrawn" doc:"Claims of theirs they took back"`
}

// MeasuresBody is the state of triage, against what is open.
type MeasuresBody struct {
	Since    string       `json:"since"`
	Until    string       `json:"until"`
	ToDecide []SpreadBody `json:"time_to_decide" doc:"The wait before anybody proposed anything, per severity"`
	ToAgree  []SpreadBody `json:"time_to_agree" doc:"The wait for a second person, per severity"`
	Worked   []WorkedBody `json:"throughput" doc:"Each person's throughput, most first"`
	SentBack int          `json:"sent_back" doc:"Claims an approver asked more of in the window. Counted for the deployment rather than per person: the record holds that a claim was sent back and not by whom"`
	Sampled  int          `json:"sampled" doc:"The number of observations behind the two spans"`
	Capped   bool         `json:"capped,omitempty" doc:"The ceiling was reached, so the spans describe the most recent part of the window rather than all of it"`
}

// registerMeasures answers how triage is going.
//
// Every one of these is in the record already and none of them is added up
// anywhere else. The wait before anybody says anything, the wait for a second
// person, each person's throughput and how much came back: four questions a
// manager asks constantly, and without this the answer to all four is a screen
// somebody counts rows on.
func registerMeasures(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-measures", Method: http.MethodGet, Path: "/v1/measures",
		Summary: "Show how long triage is taking and who is doing it",
		Description: "Four figures about how this deployment is working, as against what it " +
			"holds: how long a finding sits before anybody proposes anything, how long a " +
			"claim waits for a second person, what each person got through, and how much " +
			"came back.\n\n" +
			"The two waits come back three ways each — the middle, what nine in ten came " +
			"in under, and the longest — so a caller reads three numbers per wait rather " +
			"than one.\n\n" +
			"Per severity, because a critical waiting a week and a low waiting a week " +
			"are not the same fact.\n\n" +
			"A period or a rolling window. `from` and `to` name the stretch a manager or " +
			"an auditor is reporting on; `days` is the rolling window, and the two are ways " +
			"of saying the same thing so only one may be sent.\n\n" +
			"Bounded, and it says so. The two waits are worked out from at most the most " +
			"recent few thousand claims in the window; `sampled` says how many and `capped` " +
			"says whether the ceiling was reached. A figure quoted from part of a window " +
			"without saying so is the one thing a number like this must not be.\n\n" +
			"Send-backs are counted for the deployment rather than per person: the record " +
			"holds that a claim was sent back and not by whom, and the reason travels as a " +
			"comment.\n\n" +
			"Narrowed to what you may read, like every count here — so two people asking get " +
			"different answers rather than one of them getting an error.\n\n" +
			"Asked for neither a period nor a window, this is the last 90 days.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Period
		Product string `query:"product" doc:"Limit to judgments made in one product, by name"`
		Team    string `query:"team" doc:"Limit to judgments this team's members proposed, and to what they themselves agreed to and withdrew, by team name"`
	}) (*struct{ Body MeasuresBody }, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		since, until, err := input.window(90, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		only, err := measuring(ctx, in, subject, input.Product, input.Team)
		if err != nil {
			return nil, err
		}
		got, err := store.Measure(ctx, subject, only, since, until)
		if err != nil {
			return nil, wentWrong(in.Logger, "how triage is going could not be read", err)
		}
		body := MeasuresBody{
			Since: got.Since.Format(time.DateOnly), Until: got.Until.Format(time.DateOnly),
			ToDecide: spreadBodies(got.ToDecide), ToAgree: spreadBodies(got.ToAgree),
			SentBack: got.SentBack, Sampled: got.Sampled, Capped: got.Capped,
			Worked: make([]WorkedBody, 0, len(got.Throughput)),
		}
		for _, one := range got.Throughput {
			body.Worked = append(body.Worked, WorkedBody{
				Person: one.Person, Proposed: one.Proposed,
				Approved: one.Approved, Withdrawn: one.Withdrawn,
			})
		}
		return &struct{ Body MeasuresBody }{Body: body}, nil
	})
}

// spreadBodies says each set of waits in days, rounded to a tenth.
//
// Days because that is the unit the deadlines are in, and a tenth because a
// figure with four decimal places invites a precision the sample does not have.
func spreadBodies(all []triage.Spread) []SpreadBody {
	out := make([]SpreadBody, 0, len(all))
	for _, one := range all {
		out = append(out, SpreadBody{
			Band: one.Band, Count: one.Count,
			Median: inDays(one.Median), P90: inDays(one.P90), Worst: inDays(one.Worst),
		})
	}
	return out
}

func inDays(d time.Duration) float64 {
	return float64(int64(d.Hours()/24*10)) / 10
}
