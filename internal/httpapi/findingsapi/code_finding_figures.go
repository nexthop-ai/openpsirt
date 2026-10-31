// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// The security testing figures past the trend: time to judge, time to fix,
// analyzer precision, analysis coverage and code findings by release. Each is
// the Security testing statistics consumer's, refused with no count to
// anybody who does not read security testing material in the product, before
// any name in its narrowing is resolved, and each has a file of the same read.

const securityTestingRead = "Requires security-testing-read on the product."

// figuresScoped resolves a product and the queue's narrowing against what the
// reader may see, refusing a reader who does not read security testing
// material in the product before any component name is resolved, so a name
// held and a name not held are refused alike.
func figuresScoped(ctx context.Context, in core.Deps, product string, n CodeFindingNarrowing,
	what string) (access.Subject, analysis.Scope, error) {
	subject, scope, err := n.selected(ctx, in, product)
	if err != nil {
		return subject, analysis.Scope{}, err
	}
	if err := analysis.MayCount(subject, *scope.ProductID, what); err != nil {
		return subject, analysis.Scope{}, core.Refused(in.Logger, err, "cannot "+what)
	}
	out, err := n.narrowed(ctx, in, scope)
	return subject, out, err
}

// weeksEnding is the window of whole weeks ending at the coming midnight UTC.
func weeksEnding(weeks int) (since, until time.Time) {
	until = time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	return until.Add(-time.Duration(weeks) * 7 * 24 * time.Hour), until
}

// weeksStated is the window a figure's file covers, as the trend's file
// states it.
func weeksStated(weeks int) []core.Stated {
	return []core.Stated{{Label: "weeks", Value: strconv.Itoa(weeks)}}
}

// CodeFindingWindowAsked is a figure over a window of weeks, narrowed as the
// queue narrows.
type CodeFindingWindowAsked struct {
	Product string `path:"product"`
	CodeFindingNarrowing
	Weeks int `query:"weeks" default:"13" minimum:"1" maximum:"104" doc:"The number of weeks, ending at the coming midnight UTC"`
}

// CodeFindingWaitBody is how long a set of code findings waited.
type CodeFindingWaitBody struct {
	Tier   string  `json:"tier,omitempty" doc:"The tier of the rule's weaknesses as rated now: memory-safety, input, resource or other. Left out on the whole set"`
	Count  int     `json:"count" doc:"The number of code findings behind it"`
	Median float64 `json:"median_days" doc:"The middle wait, in days, nearest-rank"`
	P90    float64 `json:"p90_days" doc:"The wait nine in ten came in under, in days, nearest-rank"`
	Worst  float64 `json:"worst_days" doc:"The longest wait, in days"`
}

// CodeFindingWaitsBody is a set of waits, whole and by tier.
type CodeFindingWaitsBody struct {
	All    CodeFindingWaitBody   `json:"all" doc:"Every code finding counted"`
	ByTier []CodeFindingWaitBody `json:"by_tier" doc:"One per tier, memory-safety first, every tier named"`
}

func waitBody(s triage.Spread) CodeFindingWaitBody {
	return CodeFindingWaitBody{Tier: s.Band, Count: s.Count,
		Median: core.InDays(s.Median), P90: core.InDays(s.P90), Worst: core.InDays(s.Worst)}
}

func waitsBody(w analysis.Waits) CodeFindingWaitsBody {
	out := CodeFindingWaitsBody{All: waitBody(w.All), ByTier: make([]CodeFindingWaitBody, 0, len(w.ByTier))}
	for _, tier := range weakness.Tiers() {
		out.ByTier = append(out.ByTier, waitBody(w.ByTier[tier.Name()]))
	}
	return out
}

// waitRows is a set of waits as the rows of a file.
func waitRows(part string, w analysis.Waits) [][]string {
	row := func(tier string, s triage.Spread) []string {
		return []string{part, tier, strconv.Itoa(s.Count), days(s.Median), days(s.P90), days(s.Worst)}
	}
	rows := [][]string{row("all", w.All)}
	for _, tier := range weakness.Tiers() {
		rows = append(rows, row(tier.Name(), w.ByTier[tier.Name()]))
	}
	return rows
}

func days(d time.Duration) string { return strconv.FormatFloat(core.InDays(d), 'f', 1, 64) }

// CodeFindingAgedBody is the code findings waiting for a person whose age
// falls in one stretch of days.
type CodeFindingAgedBody struct {
	Label   string         `json:"label" doc:"The stretch in words"`
	From    int            `json:"from_days" doc:"The age in days the stretch starts at"`
	Until   int            `json:"until_days,omitempty" doc:"The age in days the stretch ends before. Left out on the last, which has no end"`
	Waiting int            `json:"waiting" doc:"Code findings in the stretch"`
	ByTier  map[string]int `json:"by_tier" doc:"waiting by the tier of the rule's weaknesses as rated now, each named"`
}

// CodeFindingJudgingBody is how long code findings wait for a person.
type CodeFindingJudgingBody struct {
	Since            string                `json:"since" format:"date" doc:"The first day of the window"`
	Until            string                `json:"until" format:"date" doc:"The last day of the window"`
	Judged           CodeFindingWaitsBody  `json:"judged" doc:"From a code finding opening to the first decision proposed about it, whatever its outcome, for the first decisions proposed in the window"`
	Waiting          []CodeFindingAgedBody `json:"waiting" doc:"The code finding queue now, open code findings no decision waits on, by the age of their first opening"`
	Oldest           string                `json:"oldest,omitempty" format:"date" doc:"When the longest-waiting code finding in the queue opened. Left out where the queue is empty"`
	NoLongerDetected int                   `json:"no_longer_detected" doc:"Code findings no comparable run saw, now, which wait in no queue: the code finding list's no-longer-detected count for the same narrowing"`
}

// CodeFindingFixingBody is how long code findings take to be fixed.
type CodeFindingFixingBody struct {
	Since            string               `json:"since" format:"date" doc:"The first day of the window"`
	Until            string               `json:"until" format:"date" doc:"The last day of the window"`
	Fixed            CodeFindingWaitsBody `json:"fixed" doc:"From a code finding first opening to a person closing it as fixed on the last build in the scope holding it, for the closings in the window. Dismissals are left out"`
	Dismissed        int                  `json:"dismissed" doc:"Code findings closed as fixed in the window that a dismissal, a not-security decision or a suppression rule answers, left out of fixed"`
	NoLongerDetected CodeFindingWaitsBody `json:"no_longer_detected" doc:"Code findings no comparable run saw, now, from opening to the first run not seeing them. Absence is no fix, so these are apart from fixed and have no history"`
}

func registerCodeFindingTiming(api huma.API, in core.Deps) {
	judged := func(ctx context.Context, input *CodeFindingWindowAsked) (*analysis.Judging, time.Time, time.Time, error) {
		subject, scope, err := figuresScoped(ctx, in, input.Product, input.CodeFindingNarrowing,
			"time the judging of code findings")
		if err != nil {
			return nil, time.Time{}, time.Time{}, err
		}
		since, until := weeksEnding(input.Weeks)
		out, err := analysis.TimeToJudge(ctx, in.DB.DB, subject, scope, since, until, time.Now().UTC())
		if err != nil {
			return nil, since, until, core.Refused(in.Logger, err, "the time to judge could not be worked out")
		}
		return out, since, until, nil
	}
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "time-code-finding-judging", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-finding-time-to-judge",
		Summary: "Measure time to judge code findings",
		Description: "Returns how long code findings waited from opening to the first decision anybody " +
			"proposed about them, for the first decisions proposed in the weeks asked: the median, the " +
			"ninetieth percentile and the longest, for every code finding and per tier of the rule's " +
			"weaknesses as rated now. A dismissal is a judgment and counts; a code finding a suppression " +
			"rule covers has no wait. Also returns the queue now, by age, and how many code findings are " +
			"no longer detected, which wait in no queue.\n\n" +
			"Takes the code finding list's narrowings but the state and the holder. Refused, with no " +
			"count, to anybody who does not read security testing material in the product, before a " +
			"component name is looked up.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, securityTestingRead), func(ctx context.Context, input *CodeFindingWindowAsked) (*struct{ Body CodeFindingJudgingBody }, error) {
		got, since, until, err := judged(ctx, input)
		if err != nil {
			return nil, err
		}
		return &struct{ Body CodeFindingJudgingBody }{Body: judgingBody(got, since, until)}, nil
	})
	judgedFile := figureFile{
		id: "export-code-finding-time-to-judge", path: "/v1/products/{product}/code-finding-time-to-judge",
		summary: "Export the time to judge code findings",
		description: "The time to judge as a file: a row per wait and tier, then a row per stretch of the " +
			"queue's ages and tier, then the count no longer detected. Takes what the figure takes, and " +
			"is refused as it is.",
		what:   "time to judge code findings",
		header: []string{"part", "split", "count", "median days", "p90 days", "worst days"},
	}
	huma.Register(api, judgedFile.operation(), func(ctx context.Context, input *struct {
		CodeFindingWindowAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, _, _, err := judged(ctx, &input.CodeFindingWindowAsked)
		if err != nil {
			return nil, err
		}
		return judgedFile.stream(input.Format, input.Product, weeksStated(input.Weeks), judgingRows(got)), nil
	})

	fixed := func(ctx context.Context, input *CodeFindingWindowAsked) (*analysis.Fixing, time.Time, time.Time, error) {
		subject, scope, err := figuresScoped(ctx, in, input.Product, input.CodeFindingNarrowing,
			"time the fixing of code findings")
		if err != nil {
			return nil, time.Time{}, time.Time{}, err
		}
		since, until := weeksEnding(input.Weeks)
		out, err := analysis.TimeToFix(ctx, in.DB.DB, subject, scope, since, until)
		if err != nil {
			return nil, since, until, core.Refused(in.Logger, err, "the time to fix could not be worked out")
		}
		return out, since, until, nil
	}
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "time-code-finding-fixing", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-finding-time-to-fix",
		Summary: "Measure time to fix code findings",
		Description: "Returns how long code findings took from first opening to a person closing them as " +
			"fixed on every build in the scope holding them, for the closings in the weeks asked: the " +
			"median, the ninetieth percentile and the longest, for every code finding and per tier of the " +
			"rule's weaknesses as rated now. A code finding a dismissal, a not-security decision or a " +
			"suppression rule answers is left out and counted in `dismissed`.\n\n" +
			"A run missing a code finding closes nothing, so `no_longer_detected` times the code findings " +
			"no comparable run saw, now, from opening to the first run not seeing them, apart from the " +
			"fixes and with no history.\n\n" +
			"Takes the code finding list's narrowings but the state and the holder. Refused, with no " +
			"count, to anybody who does not read security testing material in the product, before a " +
			"component name is looked up.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, securityTestingRead), func(ctx context.Context, input *CodeFindingWindowAsked) (*struct{ Body CodeFindingFixingBody }, error) {
		got, since, until, err := fixed(ctx, input)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body CodeFindingFixingBody }{}
		out.Body = CodeFindingFixingBody{
			Since: since.UTC().Format(time.DateOnly), Until: lastDay(until), Fixed: waitsBody(got.Fixed),
			Dismissed: got.Dismissed, NoLongerDetected: waitsBody(got.NoLongerDetected),
		}
		return out, nil
	})
	fixedFile := figureFile{
		id: "export-code-finding-time-to-fix", path: "/v1/products/{product}/code-finding-time-to-fix",
		summary: "Export the time to fix code findings",
		description: "The time to fix as a file: a row per tier for the fixes, then a row per tier for the " +
			"code findings no longer detected, then the count of fixes left out as dismissed. Takes what " +
			"the figure takes, and is refused as it is.",
		what:   "time to fix code findings",
		header: []string{"part", "split", "count", "median days", "p90 days", "worst days"},
	}
	huma.Register(api, fixedFile.operation(), func(ctx context.Context, input *struct {
		CodeFindingWindowAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, _, _, err := fixed(ctx, &input.CodeFindingWindowAsked)
		if err != nil {
			return nil, err
		}
		rows := append(waitRows("fixed", got.Fixed), waitRows("no longer detected", got.NoLongerDetected)...)
		rows = append(rows, []string{"dismissed, left out", "all", strconv.Itoa(got.Dismissed), "", "", ""})
		return fixedFile.stream(input.Format, input.Product, weeksStated(input.Weeks), rows), nil
	})
}

// judgingBody is the time to judge as its figure reads it.
func judgingBody(got *analysis.Judging, since, until time.Time) CodeFindingJudgingBody {
	out := CodeFindingJudgingBody{
		Since: since.UTC().Format(time.DateOnly), Until: lastDay(until), Judged: waitsBody(got.Judged),
		NoLongerDetected: got.NoLongerDetected, Waiting: make([]CodeFindingAgedBody, 0, len(got.Waiting)),
	}
	if got.Oldest != nil {
		out.Oldest = got.Oldest.UTC().Format(time.DateOnly)
	}
	for _, aged := range got.Waiting {
		out.Waiting = append(out.Waiting, CodeFindingAgedBody{Label: aged.Stretch.Label,
			From: aged.Stretch.From, Until: aged.Stretch.To, Waiting: aged.Waiting, ByTier: aged.ByTier})
	}
	return out
}

// judgingRows is the time to judge as the rows of its file.
func judgingRows(got *analysis.Judging) [][]string {
	rows := waitRows("judged", got.Judged)
	for _, aged := range got.Waiting {
		rows = append(rows, []string{"waiting " + aged.Stretch.Label, "all", strconv.Itoa(aged.Waiting), "", "", ""})
		for _, tier := range weakness.Tiers() {
			rows = append(rows, []string{"waiting " + aged.Stretch.Label, tier.Name(),
				strconv.Itoa(aged.ByTier[tier.Name()]), "", "", ""})
		}
	}
	return append(rows, []string{"no longer detected", "all", strconv.Itoa(got.NoLongerDetected), "", "", ""})
}

// figureFile is the file of one figure: what the operation is called and
// says, and what its rows are headed.
type figureFile struct {
	id, path, summary, description, what string
	header                               []string
}

// operation is the operation serving a figure's file, at the figure's
// path with the format as its extension.
func (f figureFile) operation() huma.Operation {
	return core.Requiring(huma.Operation{
		OperationID: f.id, Method: http.MethodGet, Path: f.path + ".{format}",
		Summary: f.summary, Description: f.description, Tags: []string{"Analytics"},
	}, core.AnyPerson, securityTestingRead)
}

// stream writes a figure's rows as its file, saying what it covers where a
// default the query leaves out decides it, such as the weeks of a window. The
// figure is worked out before this is called, so a refusal is a status rather
// than a line in a file that answered 200.
func (f figureFile) stream(format, product string, about []core.Stated, rows [][]string) *huma.StreamResponse {
	out := core.Exporting{
		What:   f.what,
		About:  about,
		Header: f.header,
		// Every row in one answer: a figure is worked out whole, so the
		// second page is empty and the walk stops.
		Rows: func(_ context.Context, _, offset int) ([][]string, error) {
			if offset > 0 {
				return nil, nil
			}
			return rows, nil
		},
	}
	// A figure across products is named for no product.
	name := f.what
	if product != "" {
		name += "-" + strings.ToLower(product)
	}
	return &huma.StreamResponse{Body: func(writer huma.Context) {
		core.WriteExport(writer, format, name, out)
	}}
}
