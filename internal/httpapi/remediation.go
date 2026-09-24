// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// BucketBody is how many issues have been open for a stretch of time.
type BucketBody struct {
	Label string `json:"label"`
	Days  int    `json:"days" doc:"The start of the stretch, so these can be ordered without reading the label"`
	Open  int    `json:"open"`
	// BySeverity and Undecided are the two cuts worth having. One number says
	// a hundred things are over three months old and not whether any of them
	// matters, nor whether anybody has looked: a bucket of lows that were all
	// argued and dismissed is a tidy record, and a bucket with four criticals
	// nobody has read is a backlog.
	BySeverity map[string]int `json:"by_severity,omitempty" doc:"The same count by how the issues were rated. 'unrated' is what nobody scored"`
	Undecided  int            `json:"undecided" doc:"The number nobody has said anything about. A claim waiting for a second person is not an answer"`
}

// RemediationOutput is how fast things are being fixed.
type RemediationOutput struct {
	Body struct {
		// Fixed and Opened are in the same unit deliberately, so the two can be
		// read against each other.
		Fixed  int `json:"fixed" doc:"Distinct issues that actually went away in the window"`
		Opened int `json:"opened" doc:"Distinct issues that appeared in it"`
		// TimeToFix is by the severity a thing was rated, in hours. Absent for
		// a rating nothing closed at, because a zero would read as instant.
		TimeToFix map[string]float64 `json:"time_to_fix,omitempty" doc:"Average hours an issue closed in the window was open for, by severity. A severity nothing closed at is absent rather than zero"`
		Aging     []BucketBody       `json:"aging" doc:"Everything open now, by how long it has been. About now whatever period was asked for"`
		// The period these cover, said back, so a figure is never read apart
		// from the window it was worked out over.
		From string `json:"from,omitempty" doc:"The first day of the period. Absent where it runs from the beginning"`
		To   string `json:"to" doc:"The day it ends, which is not itself in it"`
	}
}

// RepeatBody is one place that keeps being put off.
type RepeatBody struct {
	Product string `json:"product" doc:"The product, by the name that addresses it"`

	ProductName   string `json:"product_name,omitempty" doc:"The product's display name, where it has one"`
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity,omitempty"`
	Place         string `json:"place" doc:"Names the place rather than describing it: what it is called depends on the build, and this is not about one build"`
	Times         int    `json:"times" doc:"The number of times it has been put off"`
	TotalDays     int    `json:"total_days" doc:"The total it has been put off for"`
	Standing      bool   `json:"standing,omitempty" doc:"A deferral is in force now. Something put off three times and since decided is history; the same thing still being put off is the pattern"`
	LastUntil     string `json:"last_until,omitempty" doc:"The furthest any of them reached"`
}

func registerRemediation(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-remediation", Method: http.MethodGet, Path: "/v1/remediation",
		Summary: "Report how fast findings are being fixed",
		Description: "Fix velocity, average time to remediate by severity, and what is aging, " +
			"over a period and narrowed by the scope picker.\n\n" +
			"A period or a rolling window. `from` and `to` name a stretch — a quarter, a " +
			"financial year — and `days` is the rolling window ending now. They are two ways " +
			"of saying when, so only one may be sent. What is aging is a statement about " +
			"now whatever period was asked for: how long something has been open is answered " +
			"by the clock.\n\n" +
			"A closure only counts as a fix if the issue actually went away. An upgrade that " +
			"carried the issue into the next version, and a finding a scanner silently stopped " +
			"reporting, are not fixes — counting them measures churn and reports it as " +
			"progress, so the figure moves in the right direction while nothing improves.\n\n" +
			"Counted in issues, not in places. One kernel flaw across sixty modules is one " +
			"thing that was fixed; an average weighted by how far a component fans out measures " +
			"the dependency graph rather than anybody's work.\n\n" +
			"Asked for neither a period nor a window, this is the last 30 days.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Period
	}) (*RemediationOutput, error) {
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
		since, until, err := input.window(30, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		got, err := finding.NewStore(in.DB.DB).Remediation(ctx, subject, scope, since, until)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot measure how fast things are fixed")
		}

		out := &RemediationOutput{}
		out.Body.From, out.Body.To = stating(since, until)
		out.Body.Aging = []BucketBody{}
		out.Body.TimeToFix = map[string]float64{}
		if got == nil {
			return out, nil
		}
		out.Body.Fixed, out.Body.Opened = got.Fixed, got.Opened
		for band, took := range got.TimeToFix {
			out.Body.TimeToFix[band] = took.Hours()
		}
		for _, bucket := range got.Aging {
			out.Body.Aging = append(out.Body.Aging, BucketBody{
				Label: bucket.Label, Days: bucket.Days, Open: bucket.Open,
				BySeverity: bucket.BySeverity, Undecided: bucket.Undecided,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-repeated-deferrals", Method: http.MethodGet, Path: "/v1/deferrals/repeated",
		Summary: "List repeated deferrals",
		Description: "Places deferred more than once, most-deferred first, with how long they " +
			"have been put off for in total.\n\n" +
			"The cumulative threshold already refuses a further deferral past a point, one item " +
			"at a time. What it cannot show is the shape across everything: one item deferred " +
			"three times is a judgment, and forty of them is a policy nobody wrote down.\n\n" +
			"Counted over the judgments rather than the findings they cover, so the order is not " +
			"decided by how far a component spreads through an image.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to one product, by name. Empty means every product you can see"`
		AtLeast int    `query:"at_least" default:"2" minimum:"2" maximum:"50" doc:"The number of deferrals that makes something worth listing. One is an ordinary judgment"`
		Limit   int    `query:"limit" default:"100" minimum:"1" maximum:"500"`
		Offset  int    `query:"offset" minimum:"0" doc:"The offset into the list"`
	}) (*listOutput[RepeatBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		var productID int64
		if input.Product != "" {
			// A name nobody declared and a name somebody holds
			// nothing on answer alike. Telling them apart is a way
			// to read the deployment's product list one guess at a
			// time.
			named, err := productNamedVisibly(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			productID = named.ID
		}
		rows, total, err := triage.NewStore(in.DB.DB).RepeatsPage(ctx, subject, productID,
			input.AtLeast, input.Limit, input.Offset)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read what keeps being put off")
		}
		out := &listOutput[RepeatBody]{}
		// The total, so a caller holding a full page can tell
		// a clipped page from the whole list.
		out.Body.Total = total
		out.Body.Items = repeatBodies(rows)
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-repeated-deferrals", Method: http.MethodGet,
		Path:    "/v1/deferrals/repeated.{format}",
		Summary: "Export repeated deferrals",
		Description: "The same list as a file: places deferred more than once, most-deferred " +
			"first, with how long they have been put off for in total.\n\n" +
			"What the screen shows is a shape rather than a page — one item deferred three " +
			"times is a judgment and forty of them is a policy nobody wrote down — and the " +
			"file is what that goes into a review as.",
		Tags: []string{"Reports"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format  string `path:"format" enum:"csv,json"`
		Product string `query:"product" doc:"Limit to one product, by name. Empty means every product you can see"`
		AtLeast int    `query:"at_least" default:"2" minimum:"2" maximum:"50" doc:"The number of deferrals that makes something worth listing. One is an ordinary judgment"`
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		var productID int64
		if input.Product != "" {
			named, err := productNamedVisibly(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			productID = named.ID
		}
		store := triage.NewStore(in.DB.DB)
		out := Exporting{
			What:  "repeated deferrals",
			About: []Stated{{"deferred at least", strconv.Itoa(input.AtLeast) + " times"}},
			Header: []string{
				"product", "product_name", "issue", "severity", "place", "times",
				"total_days", "standing", "last_until",
			},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				rows, _, err := store.RepeatsPage(ctx, subject, productID,
					input.AtLeast, limit, offset)
				if err != nil {
					return nil, err
				}
				written := make([][]string, 0, len(rows))
				for _, row := range repeatBodies(rows) {
					written = append(written, []string{
						row.Product, row.ProductName, row.Vulnerability, row.Severity, row.Place,
						strconv.Itoa(row.Times), strconv.Itoa(row.TotalDays),
						strconv.FormatBool(row.Standing), row.LastUntil,
					})
				}
				return written, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "repeated-deferrals", out)
		}}, nil
	})
}

// repeatBodies is the list as it is written, for the screen and for the file.
func repeatBodies(rows []triage.Repeated) []RepeatBody {
	out := make([]RepeatBody, 0, len(rows))
	for _, row := range rows {
		item := RepeatBody{
			Product: row.Product, ProductName: labelBeside(row.ProductName, row.Product),
			Vulnerability: row.Vulnerability, Severity: row.Severity,
			Place: row.PlaceIdentity, Times: row.Times,
			TotalDays: int(math.Round(row.TotalDays)),
			Standing:  row.Standing,
		}
		if !row.LastUntil.IsZero() {
			item.LastUntil = row.LastUntil.Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return out
}
