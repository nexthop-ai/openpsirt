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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// The security testing figures home draws with no product picked, each one
// read across products: the queue's counts, the trend, the time to judge and
// analysis coverage. Each counts the products in use where the reader reads
// security testing material, the products the session lists them as reading
// it in, so every figure covers the products the screen says it counts.

const acrossRead = "Answers only the products in use where you read security testing material."

// acrossProducts is how each figure across products says which products it
// counts, in its description.
const acrossProducts = "Counts every product in use where you read security testing material, each " +
	"at the visibilities you read in it: a retired product, a product you read at another visibility " +
	"and a product you cannot see contribute nothing, and a reader of security testing material in no " +
	"product is answered with nothing counted. Refused to a pipeline key."

// CodeFindingAcrossAsked is the narrowing every security testing figure across
// products takes: the ones a product's figure takes that name no part of one
// product.
type CodeFindingAcrossAsked struct {
	Series string            `query:"series" maxLength:"200" doc:"Limit to the analyzer series of this name in each product, without regard to capitals. A name no product holds a series under counts nothing"`
	Method CodeFindingMethod `query:"method" doc:"Limit to the code findings one testing method reported. Left out, every method. sast is static analysis"`
}

// CodeFindingAcrossWindowAsked is a figure across products over a window of
// weeks.
type CodeFindingAcrossWindowAsked struct {
	CodeFindingAcrossAsked
	Weeks int `query:"weeks" default:"13" minimum:"1" maximum:"104" doc:"The number of weeks, ending at the coming midnight UTC"`
}

// CodeFindingAcrossTrendAsked is the trend across products, over twelve weeks
// unless named, as one product's is.
type CodeFindingAcrossTrendAsked struct {
	CodeFindingAcrossAsked
	Weeks int `query:"weeks" default:"12" minimum:"1" maximum:"104" doc:"The number of weeks, ending at the coming midnight UTC"`
}

// scoped is the reader and the products the figure counts: every product in
// use the reader reads security testing material in. A pipeline key is
// refused as no person. No name in the narrowing resolves to anything that
// could be refused, so nothing is looked up before the reader is known.
func (a CodeFindingAcrossAsked) scoped(ctx context.Context, in core.Deps, what string) (access.Subject, analysis.Scope, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return subject, analysis.Scope{}, err
	}
	// The products in use, as the session lists them, so a retired product
	// the session does not list is counted by no figure here.
	products, err := catalog.NewStore(in.DB.DB).Products(ctx, subject)
	if err != nil {
		return subject, analysis.Scope{}, core.WentWrong(in.Logger, "the products could not be read", err)
	}
	across := []int64{}
	for _, product := range products {
		if analysis.MayCount(subject, product.ID, what) == nil {
			across = append(across, product.ID)
		}
	}
	return subject, analysis.Scope{
		Across: across, Series: strings.TrimSpace(a.Series), Method: analysis.Method(a.Method),
	}, nil
}

// CodeFindingCountsBody is the code finding queue's counts.
type CodeFindingCountsBody struct {
	Total   int            `json:"total" doc:"The code findings the queue holds: open, with no decision waiting for a second person, and seen in a release still in support"`
	States  map[string]int `json:"states" doc:"The code findings by where they stand. A code finding on two builds in two states counts in both, and a fixed code finding counts until it opens anew on its build"`
	Waiting int            `json:"waiting" doc:"Open code findings left out of the queue because a decision about them waits for a second person"`
	Ruled   int            `json:"ruled" doc:"Dismissed code findings an approved suppression rule covers, counted among the dismissed in states"`
	Ended   int            `json:"past_end_of_life" doc:"Open code findings left out of the queue because every release they are open in is past its end of life"`
}

func registerSecurityTestingAcross(api huma.API, in core.Deps) {
	registerCountsAcross(api, in)
	registerTrendAcross(api, in)
	registerJudgingAcross(api, in)
	registerCoverageAcross(api, in)
}

// acrossOperation is a figure across products' own operation.
func acrossOperation(id, path, summary, description string) huma.Operation {
	return core.Requiring(huma.Operation{
		OperationID: id, Method: http.MethodGet, Path: path,
		Summary: summary, Description: description, Tags: []string{"Analytics"},
	}, core.AnyPerson, acrossRead)
}

// fileAcross is a figure file's operation across products, which differs
// from a product's in what it requires.
func fileAcross(f figureFile) huma.Operation {
	return acrossOperation(f.id, f.path+".{format}", f.summary, f.description)
}

func registerCountsAcross(api huma.API, in core.Deps) {
	const what = "count the code findings"
	counted := func(ctx context.Context, input *CodeFindingAcrossAsked) (*analysis.Queue, error) {
		subject, scope, err := input.scoped(ctx, in, what)
		if err != nil {
			return nil, err
		}
		got, err := analysis.CodeFindingCountsOf(ctx, in.DB.DB, subject, scope)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the code findings could not be counted")
		}
		return got, nil
	}
	huma.Register(api, acrossOperation("count-code-findings-across-products", "/v1/code-finding-counts",
		"Count code findings across products",
		"Returns the code finding queue's counts summed over products, with no rows: how many code "+
			"findings the queue holds, how many stand in each state, how many wait for a second person, "+
			"how many a suppression rule dismisses, and how many are open only in releases past their end "+
			"of life. Each product's counts are its own queue's.\n\n"+acrossProducts),
		func(ctx context.Context, input *CodeFindingAcrossAsked) (*struct{ Body CodeFindingCountsBody }, error) {
			got, err := counted(ctx, input)
			if err != nil {
				return nil, err
			}
			return &struct{ Body CodeFindingCountsBody }{Body: countsBody(got)}, nil
		})
	file := figureFile{id: "export-code-finding-counts-across-products", path: "/v1/code-finding-counts",
		summary: "Export code finding counts across products",
		description: "The code finding counts across products as a file: a row for the queue, a row per state, then " +
			"the rows waiting, ruled and past end of life. Takes what the counts take, and is refused as " +
			"they are.",
		what: "code finding counts", header: []string{"part", "code findings"}}
	huma.Register(api, fileAcross(file), func(ctx context.Context, input *struct {
		CodeFindingAcrossAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, err := counted(ctx, &input.CodeFindingAcrossAsked)
		if err != nil {
			return nil, err
		}
		body := countsBody(got)
		rows := [][]string{{"queue", strconv.Itoa(body.Total)}}
		for _, state := range analysis.States() {
			rows = append(rows, []string{string(state), strconv.Itoa(body.States[string(state)])})
		}
		rows = append(rows, []string{"waiting", strconv.Itoa(body.Waiting)}, []string{"ruled", strconv.Itoa(body.Ruled)},
			[]string{"past end of life", strconv.Itoa(body.Ended)})
		return file.stream(input.Format, "", nil, rows), nil
	})
}

// countsBody is the queue's counts as the figure states them, every state
// named.
func countsBody(got *analysis.Queue) CodeFindingCountsBody {
	out := CodeFindingCountsBody{Total: got.Total, Waiting: got.Waiting, Ruled: got.Ruled, Ended: got.Ended,
		States: map[string]int{}}
	for _, state := range analysis.States() {
		out.States[string(state)] = got.ByState[state]
	}
	return out
}

func registerTrendAcross(api huma.API, in core.Deps) {
	const what = "trend the code findings"
	trended := func(ctx context.Context, input *CodeFindingAcrossTrendAsked) (*analysis.Trended, error) {
		subject, scope, err := input.scoped(ctx, in, what)
		if err != nil {
			return nil, err
		}
		since, _ := weeksEnding(input.Weeks)
		got, err := analysis.Trend(ctx, in.DB.DB, subject, scope, since, 7*24*time.Hour, input.Weeks)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the code findings over time could not be worked out")
		}
		return got, nil
	}
	huma.Register(api, acrossOperation("trend-code-findings-across-products", "/v1/code-finding-trend",
		"Trend code findings across products",
		"Returns, per week, the code findings not fixed at the end of the week summed over products, split "+
			"by the tier of the rule's weaknesses, by analyzer series and by testing method, and how many "+
			"were opened and fixed in it, as one product's trend counts them. A series of the same name in "+
			"two products is one split. Each marker names its product.\n\n"+acrossProducts),
		func(ctx context.Context, input *CodeFindingAcrossTrendAsked) (*struct{ Body CodeFindingTrendBody }, error) {
			got, err := trended(ctx, input)
			if err != nil {
				return nil, err
			}
			return &struct{ Body CodeFindingTrendBody }{Body: trendBody(got)}, nil
		})
	file := figureFile{id: "export-code-finding-trend-across-products", path: "/v1/code-finding-trend",
		summary: "Export the code finding trend across products",
		description: "The code finding trend across products as a file, in the columns of one product's, each marker " +
			"naming its product. Takes what the trend takes, and is refused as it is.",
		what:   "code findings over time",
		header: []string{"week ending", "split", "part", "not fixed", "opened", "fixed", "changes"}}
	huma.Register(api, fileAcross(file), func(ctx context.Context, input *struct {
		CodeFindingAcrossTrendAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, err := trended(ctx, &input.CodeFindingAcrossTrendAsked)
		if err != nil {
			return nil, err
		}
		return file.stream(input.Format, "", weeksStated(input.Weeks), trendRows(got, true)), nil
	})
}

func registerJudgingAcross(api huma.API, in core.Deps) {
	const what = "time the judging of code findings"
	judged := func(ctx context.Context, input *CodeFindingAcrossWindowAsked) (*analysis.Judging, time.Time, time.Time, error) {
		subject, scope, err := input.scoped(ctx, in, what)
		if err != nil {
			return nil, time.Time{}, time.Time{}, err
		}
		since, until := weeksEnding(input.Weeks)
		got, err := analysis.TimeToJudge(ctx, in.DB.DB, subject, scope, since, until, time.Now().UTC())
		if err != nil {
			return nil, since, until, core.Refused(in.Logger, err, "the time to judge could not be worked out")
		}
		return got, since, until, nil
	}
	huma.Register(api, acrossOperation("time-code-finding-judging-across-products",
		"/v1/code-finding-time-to-judge", "Measure time to judge code findings across products",
		"Returns how long code findings waited from opening to the first decision proposed about them in "+
			"their product, for the first decisions proposed in the weeks asked, over every product's code "+
			"findings together; the queue now by age, summed over products; when the oldest code finding in "+
			"any product's queue opened; and how many are no longer detected. Each product's code findings "+
			"are judged against its own decisions.\n\n"+acrossProducts),
		func(ctx context.Context, input *CodeFindingAcrossWindowAsked) (*struct{ Body CodeFindingJudgingBody }, error) {
			got, since, until, err := judged(ctx, input)
			if err != nil {
				return nil, err
			}
			return &struct{ Body CodeFindingJudgingBody }{Body: judgingBody(got, since, until)}, nil
		})
	file := figureFile{id: "export-code-finding-time-to-judge-across-products", path: "/v1/code-finding-time-to-judge",
		summary: "Export the time to judge code findings across products",
		description: "The time to judge across products as a file, in the rows of one product's. Takes what the figure " +
			"takes, and is refused as it is.",
		what:   "time to judge code findings",
		header: []string{"part", "split", "count", "median days", "p90 days", "worst days"}}
	huma.Register(api, fileAcross(file), func(ctx context.Context, input *struct {
		CodeFindingAcrossWindowAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, _, _, err := judged(ctx, &input.CodeFindingAcrossWindowAsked)
		if err != nil {
			return nil, err
		}
		return file.stream(input.Format, "", weeksStated(input.Weeks), judgingRows(got)), nil
	})
}

func registerCoverageAcross(api huma.API, in core.Deps) {
	const what = "read the analysis coverage"
	covered := func(ctx context.Context, input *CodeFindingAcrossWindowAsked) ([]analysis.Analyzed, time.Time, time.Time, error) {
		subject, scope, err := input.scoped(ctx, in, what)
		if err != nil {
			return nil, time.Time{}, time.Time{}, err
		}
		since, until := weeksEnding(input.Weeks)
		got, err := analysis.CoverageOf(ctx, in.DB.DB, subject, scope, since, until, time.Now().UTC())
		if err != nil {
			return nil, since, until, core.Refused(in.Logger, err, "the analysis coverage could not be read")
		}
		return got, since, until, nil
	}
	huma.Register(api, acrossOperation("read-analysis-coverage-across-products", "/v1/analysis-coverage",
		"Read analysis coverage across products",
		"Returns every analyzer series on every build in use of every product counted, each row naming "+
			"its product, as one product's coverage lists them: quiet first, then the longest silent.\n\n"+
			acrossProducts),
		func(ctx context.Context, input *CodeFindingAcrossWindowAsked) (*struct{ Body AnalysisCoverageBody }, error) {
			got, since, until, err := covered(ctx, input)
			if err != nil {
				return nil, err
			}
			return &struct{ Body AnalysisCoverageBody }{Body: coverageBody(got, since, until)}, nil
		})
	file := figureFile{id: "export-analysis-coverage-across-products", path: "/v1/analysis-coverage",
		summary: "Export analysis coverage across products",
		description: "Analysis coverage across products as a file, a row per series and build in the order the coverage " +
			"lists them, in the columns of one product's with its product last. Takes what the coverage " +
			"takes, and is refused as it is.",
		what: "analysis coverage", header: append(coverageColumns(), "product")}
	huma.Register(api, fileAcross(file), func(ctx context.Context, input *struct {
		CodeFindingAcrossWindowAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		got, _, _, err := covered(ctx, &input.CodeFindingAcrossWindowAsked)
		if err != nil {
			return nil, err
		}
		return file.stream(input.Format, "", weeksStated(input.Weeks), coverageRows(got, true)), nil
	})
}
