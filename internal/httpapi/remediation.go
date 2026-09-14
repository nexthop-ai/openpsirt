package httpapi

import (
	"context"
	"math"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// BucketBody is how many issues have been open for a stretch of time.
type BucketBody struct {
	Label string `json:"label"`
	Days  int    `json:"days" doc:"Where the stretch starts, so these can be ordered without reading the label"`
	Open  int    `json:"open"`
	// BySeverity and Undecided are the two cuts worth having. One number says
	// a hundred things are over three months old and not whether any of them
	// matters, nor whether anybody has looked: a bucket of lows that were all
	// argued and dismissed is a tidy record, and a bucket with four criticals
	// nobody has read is a backlog.
	BySeverity map[string]int `json:"by_severity,omitempty" doc:"The same count by how the issues were rated. 'unrated' is what nobody scored"`
	Undecided  int            `json:"undecided" doc:"How many of them nobody has said anything about. A claim waiting for a second person is not an answer"`
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
		Aging     []BucketBody       `json:"aging" doc:"What is open now, by how long it has been"`
		Days      int                `json:"days" doc:"The window these cover"`
	}
}

// RepeatBody is one place that keeps being put off.
type RepeatBody struct {
	Product       string `json:"product"`
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity,omitempty"`
	Place         string `json:"place" doc:"Names the place rather than describing it: what it is called depends on the build, and this is not about one build"`
	Times         int    `json:"times" doc:"How often it has been put off"`
	TotalDays     int    `json:"total_days" doc:"How long it has been put off for, added up"`
	Standing      bool   `json:"standing,omitempty" doc:"A deferral is in force now. Something put off three times and since decided is history; the same thing still being put off is the pattern"`
	LastUntil     string `json:"last_until,omitempty" doc:"The furthest any of them reached"`
}

func registerRemediation(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-remediation", Method: http.MethodGet, Path: "/v1/remediation",
		Summary: "Report how fast findings are being fixed",
		Description: "Fix velocity, average time to remediate by severity, and what is aging, " +
			"over a window and narrowed by the scope picker.\n\n" +
			"**A closure only counts as a fix if the issue actually went away.** A bump that " +
			"carried the issue into the next version, and a finding a scanner silently stopped " +
			"reporting, are not fixes — counting them measures churn and reports it as " +
			"progress, so the figure moves in the right direction while nothing improves.\n\n" +
			"**Counted in issues, not in places.** One kernel flaw across sixty modules is one " +
			"thing that was fixed; an average weighted by how far a component fans out measures " +
			"the dependency graph rather than anybody's work.",
		Tags: []string{"Reports"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Days int `query:"days" default:"30" minimum:"1" maximum:"366" doc:"How far back to measure"`
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
		window := time.Duration(input.Days) * 24 * time.Hour
		got, err := finding.NewStore(in.DB.DB).Remediation(ctx, subject, scope, window)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot measure how fast things are fixed")
		}

		out := &RemediationOutput{}
		out.Body.Days = input.Days
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
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to one product, by name. Empty means every product you can see"`
		AtLeast int    `query:"at_least" default:"2" minimum:"2" maximum:"50" doc:"How many deferrals make something worth listing. One is an ordinary judgment"`
		Limit   int    `query:"limit" default:"100" minimum:"1" maximum:"500"`
	}) (*struct {
		Body struct {
			Items []RepeatBody `json:"items"`
		}
	}, error) {
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
		rows, err := triage.NewStore(in.DB.DB).Repeats(ctx, subject, productID,
			input.AtLeast, input.Limit)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read what keeps being put off")
		}
		out := &struct {
			Body struct {
				Items []RepeatBody `json:"items"`
			}
		}{}
		out.Body.Items = make([]RepeatBody, 0, len(rows))
		for _, row := range rows {
			item := RepeatBody{
				Product: row.Product, Vulnerability: row.Vulnerability, Severity: row.Severity,
				Place: row.PlaceIdentity, Times: row.Times,
				TotalDays: int(math.Round(row.TotalDays)),
				Standing:  row.Standing,
			}
			if !row.LastUntil.IsZero() {
				item.LastUntil = row.LastUntil.Format(time.RFC3339)
			}
			out.Body.Items = append(out.Body.Items, item)
		}
		return out, nil
	})
}
