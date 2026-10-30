// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// CodeFindingChange is what a marker on a trend of code findings says moved.
type CodeFindingChange string

// Schema offers every change a marker says.
func (CodeFindingChange) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(analysis.Changes()))
	for _, each := range analysis.Changes() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// CodeFindingTrendAsked is the narrowing a trend of code findings takes, for
// the chart and for its file: the queue's own, but for the state and the
// holder, which a line of what is not fixed does not read.
type CodeFindingTrendAsked struct {
	Product string `path:"product"`
	CodeFindingNarrowing
	Weeks int `query:"weeks" default:"12" minimum:"1" maximum:"104" doc:"The number of weeks, ending at the coming midnight UTC"`
}

// scoped resolves what is asked for against what the reader may see. The
// reader is refused before any component name is resolved, so a name held and
// a name not held are refused alike.
func (a CodeFindingTrendAsked) scoped(ctx context.Context, in core.Deps) (access.Subject, analysis.Scope, error) {
	return figuresScoped(ctx, in, a.Product, a.CodeFindingNarrowing, "trend the code findings")
}

// trended works the trend out over the weeks asked. The weeks end at
// midnight UTC, the last at the coming one, so a week holds whole days and a
// marker, dated by its day, is in the week its runs moved the line.
func (a CodeFindingTrendAsked) trended(ctx context.Context, in core.Deps, subject access.Subject,
	scope analysis.Scope) (*analysis.Trended, error) {

	const week = 7 * 24 * time.Hour
	until := time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	since := until.Add(-time.Duration(a.Weeks) * week)
	return analysis.Trend(ctx, in.DB.DB, subject, scope, since, week, a.Weeks)
}

// lastDay is the day a week ending at a midnight ends on.
func lastDay(end time.Time) string {
	return end.Add(-time.Nanosecond).UTC().Format(time.DateOnly)
}

// CodeFindingTrendBody is code findings over time.
type CodeFindingTrendBody struct {
	Points           []CodeFindingPointBody  `json:"points" doc:"One per week, oldest first"`
	Markers          []CodeFindingMarkerBody `json:"markers" doc:"Runs applied in the weeks that changed what the trend compares, oldest first, one per day, series and change"`
	NoLongerDetected int                     `json:"no_longer_detected" doc:"Code findings a comparable run did not see, now: the code finding list's no-longer-detected count for the same narrowing. Absence closes nothing, so these are counted in not_fixed too"`
}

// CodeFindingPointBody is the code findings at the end of one week.
type CodeFindingPointBody struct {
	At       string         `json:"at" format:"date" doc:"The last day of the week, which ends at midnight UTC after it"`
	NotFixed int            `json:"not_fixed" doc:"Code findings opened and not closed as fixed by the end of the week, whatever was decided about them"`
	Opened   int            `json:"opened" doc:"Code findings not fixed at the end of the week that were not at the end of the one before. Zero on the first week"`
	Fixed    int            `json:"fixed" doc:"Code findings closed as fixed in the week. Zero on the first week"`
	ByTier   map[string]int `json:"by_tier" doc:"not_fixed by the tier of the rule's weaknesses as rated now: memory-safety, input, resource and other, each named"`
	BySeries map[string]int `json:"by_series" doc:"not_fixed by analyzer series, naming every series with a code finding counted in any week"`
	ByMethod map[string]int `json:"by_method" doc:"not_fixed by testing method, each named"`
}

// CodeFindingMarkerBody is runs of one series on one day that changed what
// the trend compares.
type CodeFindingMarkerBody struct {
	At     string            `json:"at" format:"date" doc:"The day the runs were applied"`
	Series string            `json:"series" doc:"The analyzer series whose runs made the change, by name"`
	Change CodeFindingChange `json:"change" doc:"What changed from the run applied before on the same build: the tool, its version or its rules; or not-comparable, a run whose absences are no evidence for another reason"`
	Reason core.RunReason    `json:"reason,omitempty" doc:"Why the runs were not comparable. Only on not-comparable"`
	From   string            `json:"from,omitempty" doc:"The tool, the version or the number of rules before. Left out on a tool, version or rules change where the run before stated none"`
	To     string            `json:"to,omitempty" doc:"The tool, the version or the number of rules after. Left out on a tool, version or rules change where the run stated none"`
	Builds int               `json:"builds" doc:"How many builds the change was made on that day"`
}

func registerCodeFindingTrend(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "trend-code-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-finding-trend",
		Summary: "Trend code findings",
		Description: "Returns, per week, the code findings of a product that are not fixed at the end of the " +
			"week, split by the tier of the rule's weaknesses, by analyzer series and by testing method, and " +
			"how many were opened and fixed in it. Weeks end at the coming midnight UTC and every seven days " +
			"before, each point dated by its last day; a code finding " +
			"is dated by when the run that opened it was applied, and counted once however many builds hold it.\n\n" +
			"A code finding stays counted until somebody closes it as fixed: a decision answers it without " +
			"closing it, and a run missing it closes nothing. `no_longer_detected` is how many a comparable run " +
			"did not see, now, and has no weekly history.\n\n" +
			"`markers` are the runs that changed what the trend compares: another tool, version or rule set " +
			"than the run before on the same build, and runs whose absences are no evidence.\n\n" +
			"Takes the code finding list's narrowings but the state and the holder. Refused, with no count, to " +
			"anybody who does not read security testing material in the product, before a component name is " +
			"looked up.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, "Requires security-testing-read on the product."), func(ctx context.Context, input *CodeFindingTrendAsked) (*struct{ Body CodeFindingTrendBody }, error) {
		subject, scope, err := input.scoped(ctx, in)
		if err != nil {
			return nil, err
		}
		trended, err := input.trended(ctx, in, subject, scope)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the code findings over time could not be worked out")
		}
		out := &struct{ Body CodeFindingTrendBody }{}
		out.Body.NoLongerDetected = trended.NoLongerDetected
		out.Body.Points = make([]CodeFindingPointBody, 0, len(trended.Points))
		for _, p := range trended.Points {
			out.Body.Points = append(out.Body.Points, CodeFindingPointBody{
				At: lastDay(p.At), NotFixed: p.NotFixed, Opened: p.Opened, Fixed: p.Fixed,
				ByTier: p.ByTier, BySeries: p.BySeries, ByMethod: p.ByMethod,
			})
		}
		out.Body.Markers = make([]CodeFindingMarkerBody, 0, len(trended.Markers))
		for _, m := range trended.Markers {
			out.Body.Markers = append(out.Body.Markers, CodeFindingMarkerBody{
				At: m.At.UTC().Format(time.DateOnly), Series: m.Series, Change: CodeFindingChange(m.Change),
				Reason: core.RunReason(m.Reason), From: m.From, To: m.To, Builds: m.Builds,
			})
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-code-finding-trend", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-finding-trend.{format}",
		Summary: "Export the code finding trend",
		Description: "The code finding trend as a file: per week, a row with what was not fixed, opened and " +
			"fixed and the markers of that week, then a row per tier, method and series with what of it was " +
			"not fixed. The columns are the same whatever the data holds. Takes what the trend takes, and is " +
			"refused as it is.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, "Requires security-testing-read on the product."), func(ctx context.Context, input *struct {
		CodeFindingTrendAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		// Refused before the first byte, so a refusal is a status rather
		// than a line in a file that answered 200.
		subject, scope, err := input.scoped(ctx, in)
		if err != nil {
			return nil, err
		}
		out := core.Exporting{
			What:   "code findings over time",
			About:  []core.Stated{{Label: "weeks", Value: strconv.Itoa(input.Weeks)}},
			Header: []string{"week ending", "split", "part", "not fixed", "opened", "fixed", "changes"},
			// Every week in one answer, because a trend is worked out over
			// the whole window: the second page is empty and the walk stops.
			Rows: func(ctx context.Context, _, offset int) ([][]string, error) {
				if offset > 0 {
					return nil, nil
				}
				trended, err := input.trended(ctx, in, subject, scope)
				if err != nil {
					return nil, err
				}
				return trendRows(trended), nil
			},
		}
		name := "code findings over time-" + strings.ToLower(input.Product)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, name, out)
		}}, nil
	})
}

// trendRows is a trend as the rows of its file.
func trendRows(trended *analysis.Trended) [][]string {
	var rows [][]string
	for i, p := range trended.Points {
		end := lastDay(p.At)
		// A marker is dated by day, so it is in the week whose last day is
		// its day or after it, and the week before ended before its day.
		var changes []string
		for _, m := range trended.Markers {
			day := m.At.UTC().Format(time.DateOnly)
			if day > end || (i > 0 && day <= lastDay(trended.Points[i-1].At)) {
				continue
			}
			changes = append(changes, markerWords(m))
		}
		rows = append(rows, []string{end, "total", "", strconv.Itoa(p.NotFixed),
			strconv.Itoa(p.Opened), strconv.Itoa(p.Fixed), strings.Join(changes, "; ")})
		for _, tier := range weakness.Tiers() {
			rows = append(rows, []string{end, "tier", tier.Name(), strconv.Itoa(p.ByTier[tier.Name()]), "", "", ""})
		}
		for _, method := range analysis.Methods() {
			rows = append(rows, []string{end, "method", method, strconv.Itoa(p.ByMethod[method]), "", "", ""})
		}
		named := make([]string, 0, len(p.BySeries))
		for name := range p.BySeries {
			named = append(named, name)
		}
		sort.Strings(named)
		for _, name := range named {
			rows = append(rows, []string{end, "series", name, strconv.Itoa(p.BySeries[name]), "", "", ""})
		}
	}
	return rows
}

// markerWords is a marker as the file states it.
func markerWords(m analysis.Marker) string {
	said := m.Series + " " + string(m.Change)
	if m.Change == analysis.NotComparable {
		said += " (" + string(m.Reason) + ")"
	}
	if m.Change != analysis.NotComparable && (m.From != "" || m.To != "") {
		said += " from " + stated(m.From) + " to " + stated(m.To)
	}
	builds := "builds"
	if m.Builds == 1 {
		builds = "build"
	}
	return said + fmt.Sprintf(" on %s, %d %s", m.At.UTC().Format(time.DateOnly), m.Builds, builds)
}

// stated is a tool, version or rule count a run may leave unstated, as words.
func stated(value string) string {
	if value == "" {
		return "not stated"
	}
	return value
}
