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

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// CodeFindingAnsweredBody is what people said of the code findings of one
// series, or of one analyzer rule in it, each code finding in one count.
type CodeFindingAnsweredBody struct {
	Series      string   `json:"series" doc:"The analyzer series, by name"`
	Rule        string   `json:"rule,omitempty" doc:"The analyzer rule, as <tool>/<rule>. Left out on a series' own row"`
	Judged      int      `json:"judged" doc:"Code findings a person or a suppression rule answered: the sum of dismissed, not_security, ruled, confirmed and fixed"`
	Dismissed   int      `json:"dismissed" doc:"Code findings whose standing decision dismisses them"`
	NotSecurity int      `json:"not_security" doc:"Code findings whose standing decision says they are not a security issue"`
	Ruled       int      `json:"ruled" doc:"Code findings a suppression rule dismisses with no decision standing"`
	Confirmed   int      `json:"confirmed" doc:"Code findings whose standing decision confirms them, or recorded as a flaw"`
	Fixed       int      `json:"fixed" doc:"Code findings a person closed as fixed with no decision standing"`
	Unjudged    int      `json:"unjudged" doc:"Code findings nothing answers yet, a decision waiting for a second person included"`
	NoiseShare  *float64 `json:"noise_share,omitempty" doc:"The share of judged answered as noise, dismissed, not_security and ruled together, from 0 to 1. Left out where none is judged"`
}

func answeredBody(a analysis.Answered) CodeFindingAnsweredBody {
	out := CodeFindingAnsweredBody{
		Series: a.Series, Rule: a.Rule, Judged: a.Judged(), Dismissed: a.Dismissed, NotSecurity: a.NotSecurity,
		Ruled: a.Ruled, Confirmed: a.Confirmed, Fixed: a.Fixed, Unjudged: a.Unjudged,
	}
	if judged := a.Judged(); judged > 0 {
		share := float64(a.Noise()) / float64(judged)
		out.NoiseShare = &share
	}
	return out
}

// CodeFindingSuppressionBody is a suppression rule and what it covers.
type CodeFindingSuppressionBody struct {
	ID         int64                  `json:"id" doc:"The rule's identifier in the product"`
	Rule       string                 `json:"rule,omitempty" doc:"The analyzer rule it names, where it names one"`
	Prefix     string                 `json:"path,omitempty" doc:"The path it names, from the top of the checkout, where it names one"`
	Reason     core.CodeFindingReason `json:"reason" doc:"Why what it covers is dismissed"`
	State      string                 `json:"state" doc:"Where the rule stands: proposed, in-force, outgrown, needs-path or retired"`
	ProposedAt string                 `json:"proposed_at" doc:"When it was proposed"`
	ApprovedAt string                 `json:"approved_at,omitempty" doc:"When it was last approved, where it was"`
	Approved   *int                   `json:"approved_covering,omitempty" doc:"The code findings it covered when it was approved"`
	RetiredAt  string                 `json:"retired_at,omitempty" doc:"When it was taken out of use, where it was"`
	Covering   int                    `json:"covering" doc:"The open code findings it names now that the reader may read, whether or not it is in force"`
}

// CodeFindingPrecisionBody is which analyzers and rules are noise.
type CodeFindingPrecisionBody struct {
	BySeries []CodeFindingAnsweredBody    `json:"by_series" doc:"One per series with a code finding in the scope, by name"`
	ByRule   []CodeFindingAnsweredBody    `json:"by_rule" doc:"One per analyzer rule with a code finding judged, the highest noise share first, then the most judged"`
	Rules    []CodeFindingSuppressionBody `json:"suppression_rules" doc:"The product's suppression rules, retired ones included, oldest first. Every branch and variant, whatever the narrowing"`
}

// CodeFindingStandingAsked is a figure of how code findings stand now,
// narrowed as the queue narrows.
type CodeFindingStandingAsked struct {
	Product string `path:"product"`
	CodeFindingNarrowing
}

// AnalysisCoverageAsked is the narrowing analysis coverage takes.
type AnalysisCoverageAsked struct {
	Product     string            `path:"product"`
	BranchOrTag string            `query:"branch_or_tag" doc:"Limit to one branch or tag. Left out, every one under the product"`
	Variant     string            `query:"variant" doc:"Limit to one variant. Left out, every one under the product"`
	Series      string            `query:"series" maxLength:"200" doc:"Limit to one analyzer series, by name, without regard to capitals"`
	Method      CodeFindingMethod `query:"method" doc:"Limit to the series of one testing method. sast is static analysis"`
	Weeks       int               `query:"weeks" default:"13" minimum:"1" maximum:"104" doc:"The number of weeks the run counts cover, ending at the coming midnight UTC"`
}

// AnalyzedBody is one series on one build in use.
type AnalyzedBody struct {
	BranchOrTag       string         `json:"branch_or_tag" doc:"The branch or tag, by the name that addresses it"`
	BranchOrTagName   string         `json:"branch_or_tag_name" doc:"The branch or tag as shown"`
	Variant           string         `json:"variant" doc:"The variant, by the name that addresses it"`
	VariantName       string         `json:"variant_name" doc:"The variant as shown"`
	Series            string         `json:"series" doc:"The analyzer series, by name"`
	Method            string         `json:"method" doc:"The testing method the series reports. sast is static analysis"`
	Quiet             bool           `json:"quiet" doc:"Whether the series has gone quiet on the build: no comparable run arrived for three of its own usual gaps, never under a day. Never on a release past its end of life"`
	PastEndOfLife     bool           `json:"past_end_of_life,omitempty" doc:"Whether the release is past its end of life, analyzed by nobody on purpose"`
	Arrived           string         `json:"last_arrived,omitempty" doc:"When the newest applied run arrived. Left out where none was applied"`
	Applied           string         `json:"last_applied,omitempty" doc:"When the newest applied run was applied"`
	NotComparable     core.RunReason `json:"not_comparable,omitempty" doc:"Why the newest applied run's absences are no evidence. Left out where they are"`
	UnitsExpected     *int           `json:"units_expected,omitempty" doc:"What the newest applied run said it was meant to analyze. Left out where it said nothing"`
	UnitsAnalyzed     *int           `json:"units_analyzed,omitempty" doc:"What the newest applied run said it analyzed. Left out where it said nothing"`
	Comparable        string         `json:"last_comparable,omitempty" doc:"When the newest comparable run arrived. Left out where none did"`
	AppliedRuns       int            `json:"applied_runs" doc:"Runs that arrived in the weeks asked and were applied"`
	NotComparableRuns int            `json:"not_comparable_runs" doc:"Of those applied, the runs whose absences are no evidence"`
	FailedRuns        int            `json:"failed_runs" doc:"Runs that arrived in the weeks asked and could not be read"`
	Expected          *float64       `json:"expected_days,omitempty" doc:"The series' own expected interval on the build: the median of its newest gaps between runs, in days. Left out until three runs were applied"`
	Allowed           *float64       `json:"allowed_days,omitempty" doc:"The silence the expected interval allows before the series is quiet: three intervals, never under a day"`
	Silent            *float64       `json:"silent_days,omitempty" doc:"Days since the newest comparable run arrived, or since the oldest run read where none was comparable. Left out where none was applied"`
}

// AnalysisCoverageBody is what is analyzed, and what has gone quiet.
type AnalysisCoverageBody struct {
	Since string         `json:"since" format:"date" doc:"The first day the run counts cover"`
	Until string         `json:"until" format:"date" doc:"The last day the run counts cover"`
	Quiet int            `json:"quiet" doc:"Series gone quiet on a build"`
	Items []AnalyzedBody `json:"items" doc:"One per series and build in use, quiet first, then the longest silent"`
}

// CodeFindingsByReleaseAsked is the narrowing code findings by release takes.
type CodeFindingsByReleaseAsked struct {
	Product          string            `path:"product"`
	Variant          string            `query:"variant" doc:"Limit to one variant. Left out, every one"`
	Series           string            `query:"series" maxLength:"200" doc:"Limit to one analyzer series, by name, without regard to capitals"`
	Method           CodeFindingMethod `query:"method" doc:"Limit to one testing method. sast is static analysis"`
	Component        string            `query:"component" maxLength:"200" doc:"Limit to the code findings placed on one source package, as the code finding list reads it"`
	ComponentVersion string            `query:"component_version" maxLength:"200" doc:"Limit component to the source package at this version. Ignored without component"`
	Releases         int               `query:"releases" default:"12" minimum:"1" maximum:"50" doc:"The number of releases, the newest"`
}

// CodeFindingReleaseBody is the code findings one tagged release holds now.
type CodeFindingReleaseBody struct {
	BranchOrTag      string         `json:"branch_or_tag" doc:"The tag, by the name that addresses it"`
	BranchOrTagName  string         `json:"branch_or_tag_name" doc:"The tag as shown"`
	Cut              string         `json:"cut" format:"date" doc:"When the release went out, where somebody said, and when it was declared otherwise. It orders the releases"`
	NotFixed         int            `json:"not_fixed" doc:"Code findings on the release's builds nobody closed as fixed, whatever was decided about them"`
	ByTier           map[string]int `json:"by_tier" doc:"not_fixed by the tier of the rule's weaknesses as rated now, each named"`
	Open             int            `json:"open" doc:"Of not_fixed, those open on a build of the release: nothing answers them"`
	Dismissed        int            `json:"dismissed" doc:"Of not_fixed, those dismissed on a build of the release, by a decision or a suppression rule"`
	NotSecurity      int            `json:"not_security" doc:"Of not_fixed, those decided not a security issue on a build of the release"`
	NoLongerDetected int            `json:"no_longer_detected" doc:"Of not_fixed, those no comparable run saw on a build of the release"`
}

func registerSecurityTestingFigures(api huma.API, in core.Deps) {
	precise := func(ctx context.Context, input *CodeFindingStandingAsked) (*analysis.Precision, error) {
		subject, scope, err := figuresScoped(ctx, in, input.Product, input.CodeFindingNarrowing,
			"measure the precision of the analyzers")
		if err != nil {
			return nil, err
		}
		out, err := analysis.PrecisionOf(ctx, in.DB.DB, subject, scope)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the precision of the analyzers could not be worked out")
		}
		return out, nil
	}
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "measure-analyzer-precision", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-finding-precision",
		Summary: "Measure analyzer precision",
		Description: "Returns what was said of the code findings of each analyzer series and of each " +
			"analyzer rule, now: dismissed, not a security issue, dismissed by a suppression rule, " +
			"confirmed, fixed, or nothing yet, each code finding counted once at the first that holds, " +
			"and the share of those judged that was answered as noise. Also returns the product's " +
			"suppression rules with what each covers now.\n\n" +
			"Takes the code finding list's narrowings but the state and the holder. Refused, " +
			"with no count, to anybody who does not read security testing material in the product, " +
			"before a component name is looked up.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, securityTestingRead), func(ctx context.Context, input *CodeFindingStandingAsked) (*struct{ Body CodeFindingPrecisionBody }, error) {
		got, err := precise(ctx, input)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body CodeFindingPrecisionBody }{}
		out.Body.BySeries = make([]CodeFindingAnsweredBody, 0, len(got.BySeries))
		for _, each := range got.BySeries {
			out.Body.BySeries = append(out.Body.BySeries, answeredBody(each))
		}
		out.Body.ByRule = make([]CodeFindingAnsweredBody, 0, len(got.ByRule))
		for _, each := range got.ByRule {
			out.Body.ByRule = append(out.Body.ByRule, answeredBody(each))
		}
		out.Body.Rules = make([]CodeFindingSuppressionBody, 0, len(got.Rules))
		for _, r := range got.Rules {
			out.Body.Rules = append(out.Body.Rules, CodeFindingSuppressionBody{
				ID: r.ID, Rule: r.Rule, Prefix: r.Prefix, Reason: core.CodeFindingReason(r.Reason),
				State: string(r.State), ProposedAt: core.Stamp(r.ProposedAt), ApprovedAt: core.StampAt(r.ApprovedAt),
				Approved: r.ApprovedCovering, RetiredAt: core.StampAt(r.RetiredAt), Covering: r.Covering,
			})
		}
		return out, nil
	})
	preciseFile := figureFile{
		id: "export-analyzer-precision", path: "/v1/products/{product}/code-finding-precision",
		summary: "Export analyzer precision",
		description: "Analyzer precision as a file: a row per series, then a row per analyzer rule with a " +
			"code finding judged, then a row per suppression rule with what it covers. Takes what the " +
			"figure takes, and is refused as it is.",
		what: "analyzer precision",
		header: []string{"part", "series", "rule", "judged", "dismissed", "not security", "ruled",
			"confirmed", "fixed", "unjudged", "noise share", "state", "covering"},
	}
	huma.Register(api, preciseFile.operation(), func(ctx context.Context, input *struct {
		CodeFindingStandingAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, err := precise(ctx, &input.CodeFindingStandingAsked)
		if err != nil {
			return nil, err
		}
		var rows [][]string
		answered := func(part string, a analysis.Answered) []string {
			share := ""
			if judged := a.Judged(); judged > 0 {
				share = strconv.FormatFloat(float64(a.Noise())/float64(judged), 'f', 3, 64)
			}
			return []string{part, a.Series, a.Rule, strconv.Itoa(a.Judged()), strconv.Itoa(a.Dismissed),
				strconv.Itoa(a.NotSecurity), strconv.Itoa(a.Ruled), strconv.Itoa(a.Confirmed),
				strconv.Itoa(a.Fixed), strconv.Itoa(a.Unjudged), share, "", ""}
		}
		for _, each := range got.BySeries {
			rows = append(rows, answered("series", each))
		}
		for _, each := range got.ByRule {
			rows = append(rows, answered("rule", each))
		}
		for _, r := range got.Rules {
			named := r.Rule
			if r.Prefix != "" {
				named = strings.TrimSpace(named + " under " + r.Prefix)
			}
			rows = append(rows, []string{"suppression rule", "", named, "", "", "", "", "", "", "", "",
				string(r.State), strconv.Itoa(r.Covering)})
		}
		return preciseFile.stream(input.Format, input.Product, nil, rows), nil
	})

	covered := func(ctx context.Context, input *AnalysisCoverageAsked) ([]analysis.Analyzed, time.Time, time.Time, error) {
		subject, scope, err := (CodeFindingNarrowing{BranchOrTag: input.BranchOrTag, Variant: input.Variant}).
			selected(ctx, in, input.Product)
		if err != nil {
			return nil, time.Time{}, time.Time{}, err
		}
		if err := analysis.MayCount(subject, *scope.ProductID, "read the analysis coverage"); err != nil {
			return nil, time.Time{}, time.Time{}, core.Refused(in.Logger, err, "cannot read the analysis coverage")
		}
		since, until := weeksEnding(input.Weeks)
		out, err := analysis.CoverageOf(ctx, in.DB.DB, subject, analysis.Scope{
			ProductID: *scope.ProductID, BranchOrTagID: scope.BranchOrTagID, VariantID: scope.VariantID,
			Series: strings.TrimSpace(input.Series), Method: analysis.Method(input.Method),
		}, since, until, time.Now().UTC())
		if err != nil {
			return nil, since, until, core.Refused(in.Logger, err, "the analysis coverage could not be read")
		}
		return out, since, until, nil
	}
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "read-analysis-coverage", Method: http.MethodGet,
		Path:    "/v1/products/{product}/analysis-coverage",
		Summary: "Read analysis coverage",
		Description: "Returns every analyzer series on every build in use of the product: its newest applied " +
			"run, what that run analyzed against what it was meant to, its newest comparable run, the runs " +
			"in the weeks asked that were applied, not comparable or failed, and its own expected interval " +
			"between runs on that build.\n\n" +
			"A series is quiet when no comparable run arrived for three of its own usual gaps between applied " +
			"runs, never under a day, once three runs were applied. Each series is judged " +
			"on its own interval, so a quarterly series is not quiet after a week. A retired build is left " +
			"out; a release past its end of life is listed and never quiet. Quiet first, then the longest " +
			"silent.\n\n" +
			"Refused to anybody who does not read security testing material in the product.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, securityTestingRead), func(ctx context.Context, input *AnalysisCoverageAsked) (*struct{ Body AnalysisCoverageBody }, error) {
		got, since, until, err := covered(ctx, input)
		if err != nil {
			return nil, err
		}
		out := &struct{ Body AnalysisCoverageBody }{}
		out.Body = AnalysisCoverageBody{Since: since.UTC().Format(time.DateOnly), Until: lastDay(until),
			Items: make([]AnalyzedBody, 0, len(got))}
		for _, a := range got {
			if a.Quiet() {
				out.Body.Quiet++
			}
			out.Body.Items = append(out.Body.Items, analyzedBody(a))
		}
		return out, nil
	})
	coveredFile := figureFile{
		id: "export-analysis-coverage", path: "/v1/products/{product}/analysis-coverage",
		summary: "Export analysis coverage",
		description: "Analysis coverage as a file, a row per series and build in the order the coverage " +
			"lists them. Takes what the coverage takes, and is refused as it is.",
		what: "analysis coverage",
		header: []string{"branch or tag", "variant", "series", "method", "quiet", "past end of life",
			"last arrived", "last applied", "not comparable", "units expected", "units analyzed",
			"last comparable", "applied runs", "not comparable runs", "failed runs", "expected days",
			"allowed days", "silent days"},
	}
	huma.Register(api, coveredFile.operation(), func(ctx context.Context, input *struct {
		AnalysisCoverageAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, _, _, err := covered(ctx, &input.AnalysisCoverageAsked)
		if err != nil {
			return nil, err
		}
		rows := make([][]string, 0, len(got))
		for _, a := range got {
			b := analyzedBody(a)
			rows = append(rows, []string{b.BranchOrTagName, b.VariantName, b.Series, b.Method,
				strconv.FormatBool(b.Quiet), strconv.FormatBool(b.PastEndOfLife), b.Arrived, b.Applied,
				string(b.NotComparable), optionalInt(b.UnitsExpected), optionalInt(b.UnitsAnalyzed), b.Comparable,
				strconv.Itoa(b.AppliedRuns), strconv.Itoa(b.NotComparableRuns), strconv.Itoa(b.FailedRuns),
				optionalDays(b.Expected), optionalDays(b.Allowed), optionalDays(b.Silent)})
		}
		return coveredFile.stream(input.Format, input.Product, weeksStated(input.Weeks), rows), nil
	})

	released := func(ctx context.Context, input *CodeFindingsByReleaseAsked) ([]analysis.Release, error) {
		subject, scope, err := figuresScoped(ctx, in, input.Product, CodeFindingNarrowing{
			Variant: input.Variant, Series: input.Series, Method: input.Method,
			Component: input.Component, ComponentVersion: input.ComponentVersion,
		}, "count the code findings of each release")
		if err != nil {
			return nil, err
		}
		out, err := analysis.ByRelease(ctx, in.DB.DB, subject, scope, input.Releases)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the code findings by release could not be counted")
		}
		return out, nil
	}
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "count-code-findings-by-release", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-findings-by-release",
		Summary: "Count code findings by release",
		Description: "Returns, for each tagged release of the product an analyzer run was applied to, " +
			"oldest first, the code findings on its builds nobody closed as fixed, split by the tier of " +
			"the rule's weaknesses as rated now, with how many of them are open, dismissed, not a " +
			"security issue and no longer detected. A release is one frozen point, answered today; a " +
			"release analyzed and holding nothing is a point at zero, and a release never analyzed is " +
			"absent.\n\n" +
			"Refused, with no count, to anybody who does not read security testing material in the " +
			"product, before a component name is looked up.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, securityTestingRead), func(ctx context.Context, input *CodeFindingsByReleaseAsked) (*struct {
		Body struct {
			Releases []CodeFindingReleaseBody `json:"releases" doc:"One per release, oldest first"`
		}
	}, error) {
		got, err := released(ctx, input)
		if err != nil {
			return nil, err
		}
		out := &struct {
			Body struct {
				Releases []CodeFindingReleaseBody `json:"releases" doc:"One per release, oldest first"`
			}
		}{}
		out.Body.Releases = make([]CodeFindingReleaseBody, 0, len(got))
		for _, r := range got {
			out.Body.Releases = append(out.Body.Releases, releaseBody(r))
		}
		return out, nil
	})
	releasedFile := figureFile{
		id: "export-code-findings-by-release", path: "/v1/products/{product}/code-findings-by-release",
		summary: "Export code findings by release",
		description: "Code findings by release as a file: a row per release with what is not fixed, open, " +
			"dismissed, not a security issue and no longer detected, then a row per tier. Takes what the " +
			"figure takes, and is refused as it is.",
		what: "code findings by release",
		header: []string{"release", "cut", "split", "not fixed", "open", "dismissed", "not security",
			"no longer detected"},
	}
	huma.Register(api, releasedFile.operation(), func(ctx context.Context, input *struct {
		CodeFindingsByReleaseAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, err := released(ctx, &input.CodeFindingsByReleaseAsked)
		if err != nil {
			return nil, err
		}
		var rows [][]string
		for _, r := range got {
			b := releaseBody(r)
			rows = append(rows, []string{b.BranchOrTagName, b.Cut, "all", strconv.Itoa(b.NotFixed),
				strconv.Itoa(b.Open), strconv.Itoa(b.Dismissed), strconv.Itoa(b.NotSecurity),
				strconv.Itoa(b.NoLongerDetected)})
			for _, tier := range weakness.Tiers() {
				rows = append(rows, []string{b.BranchOrTagName, b.Cut, tier.Name(),
					strconv.Itoa(b.ByTier[tier.Name()]), "", "", "", ""})
			}
		}
		return releasedFile.stream(input.Format, input.Product,
			[]core.Stated{{Label: "releases", Value: strconv.Itoa(input.Releases)}}, rows), nil
	})
}

func analyzedBody(a analysis.Analyzed) AnalyzedBody {
	out := AnalyzedBody{
		BranchOrTag: a.BranchOrTag, BranchOrTagName: a.BranchOrTagShown, Variant: a.Variant,
		VariantName: a.VariantShown, Series: a.Series, Method: string(a.Method), Quiet: a.Quiet(),
		PastEndOfLife: a.PastEndOfLife, Arrived: core.StampAt(a.Arrived), Applied: core.StampAt(a.Applied),
		NotComparable: core.RunReason(a.NotComparable), UnitsExpected: a.UnitsExpected,
		UnitsAnalyzed: a.UnitsAnalyzed, Comparable: core.StampAt(a.Comparable),
		AppliedRuns: a.AppliedRuns, NotComparableRuns: a.NotComparableRuns, FailedRuns: a.FailedRuns,
	}
	inDays := func(d time.Duration) *float64 {
		out := core.InDays(d)
		return &out
	}
	if a.Arrived != nil {
		out.Silent = inDays(a.Rhythm.Silent)
	}
	if a.Rhythm.Known {
		out.Expected, out.Allowed = inDays(a.Rhythm.Usual), inDays(a.Rhythm.Allowed)
	}
	return out
}

func releaseBody(r analysis.Release) CodeFindingReleaseBody {
	return CodeFindingReleaseBody{
		BranchOrTag: r.BranchOrTag, BranchOrTagName: r.Shown, Cut: r.Cut.UTC().Format(time.DateOnly),
		NotFixed: r.NotFixed, ByTier: r.ByTier, Open: r.Open, Dismissed: r.Dismissed,
		NotSecurity: r.NotSecurity, NoLongerDetected: r.NoLongerDetected,
	}
}

func optionalInt(n *int) string {
	if n == nil {
		return ""
	}
	return strconv.Itoa(*n)
}

func optionalDays(d *float64) string {
	if d == nil {
		return ""
	}
	return strconv.FormatFloat(*d, 'f', 1, 64)
}
