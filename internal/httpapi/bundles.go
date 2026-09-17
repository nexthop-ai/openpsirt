package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// bundleSort is the query parameter for which order the fix-bundle list pages
// in, built from the store's own list the way the findings list's is.
type bundleSort string

// Schema answers with the orders the store knows, in its order.
func (bundleSort) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(finding.BundleSortKeys()))
	for _, key := range finding.BundleSortKeys() {
		offered = append(offered, string(key))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// BundleBody is one upstream bump and everything it would close.
type BundleBody struct {
	Upstream string `json:"upstream" doc:"What the upgrade is of: the source package where one is recorded, and the component's own name otherwise"`
	From     string `json:"from" doc:"The version in hand"`
	To       string `json:"to" doc:"The version that fixes it, as whoever packages the component wrote it. Never compared against what ships, only grouped"`
	// Components are the names this bundle moves, which is what makes a
	// bundle keyed on a source package readable.
	Components []string `json:"components" doc:"The packages this one upgrade moves. More than one where a source package builds several"`
	Issues     int      `json:"issues" doc:"Distinct vulnerabilities the upgrade closes"`
	Places     int      `json:"places" doc:"How many findings those sit at"`
	Builds     int      `json:"builds,omitempty" doc:"How many builds of the selection hold any of it. Absent where the selection is one build"`
	Severity   string   `json:"severity,omitempty" doc:"The worst of what it closes"`
	Exploited  bool     `json:"exploited,omitempty" doc:"Some of what it closes is being exploited"`
	// In names the builds that hold it, which is what a declaration is
	// offered against: a bump is declared for releases, and the ones worth
	// offering are the ones that have it.
	In []BuildName `json:"in" doc:"The builds that hold this upgrade"`
}

// BundleQuery is what narrows the fix-bundle list.
//
// One struct for the screen and the file, because they are one question. An
// export declaring its own parameters drifts from the list it came from, and
// nothing rejects an undeclared parameter — so the filters a caller sent
// arrive and are dropped before the handler runs, with no error and no clue.
type BundleQuery struct {
	Stream    string     `query:"stream" doc:"Limit to one branch or tag"`
	Variant   string     `query:"variant" doc:"Limit to one variant"`
	Severity  string     `query:"severity" enum:"low,medium,high,critical" doc:"Keep only issues rated this badly or worse"`
	Exploited bool       `query:"exploited" doc:"Keep only upgrades closing something known to be exploited"`
	Component string     `query:"component" doc:"Keep only upgrades moving a component of this name"`
	Search    string     `query:"q" maxLength:"200" doc:"Keep only rows whose component or issue name contains this"`
	Ecosystem string     `query:"ecosystem" doc:"Keep only components of one package kind"`
	State     string     `query:"state" enum:"undecided,waiting,agreed,lapsed" doc:"Keep only groups this far decided"`
	Sort      bundleSort `query:"sort" doc:"Which order to page in. Worst first by default. A bundle with no deadline sorts last whichever direction is asked for"`
	Ascending bool       `query:"asc" doc:"Order the other way — fewest, least urgent, nearest deadline first"`
}

// narrow is what the store reads by, from what was asked for.
func (q BundleQuery) narrow(floor finding.Floor) finding.Filter {
	return finding.Filter{
		MinSeverity: q.Severity, Exploited: q.Exploited,
		Components: []string{q.Component}, Search: q.Search,
		Ecosystems: []string{q.Ecosystem}, States: []string{q.State},
		BundleSort: finding.BundleSortKey(q.Sort), Ascending: q.Ascending,
		Floor: floor,
	}
}

func registerBundles(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-fix-bundles", Method: http.MethodGet,
		Path:    "/v1/products/{product}/fix-bundles",
		Summary: "List findings by upgrade",
		Description: "One row per upstream upgrade, with the issues it closes.\n\n" +

			"Keyed on the **source package** where one is recorded and on the component's " +
			"own name otherwise, so packages built from one source are one row — curl, " +
			"libcurl4t64 and libcurl3t64 are upgraded once.\n\n" +
			"Only what has a fix: a bundle is a version to move to, so a finding upstream has " +
			"released nothing for is not in one.\n\n" +
			"Grouping is presentation: one act still writes one decision per component and " +
			"per place.\n\n" +
			"Takes the same selection as the findings list, and six of its filters: " +
			"severity, exploited, component, search, ecosystem and state. Not the rest: a " +
			"filter that answers about a place or a deadline has no row here to narrow.\n\n" +
			"Ordered worst first, and `sort` takes any of: what the upgrade would close " +
			"(`issues`, `places`), how far it reaches (`builds`), how bad the worst of it is " +
			"(`urgency`, `severity`) and the soonest deadline it would meet (`deadline`). " +
			"`asc` orders the other way. The default answers what should worry you; " +
			"`sort=issues` answers what to do this afternoon.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		BundleQuery
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []BundleBody `json:"items"`
			Total int          `json:"total"`
		}
	}, error) {
		subject, scope, floor, err := scopedFloor(ctx, in, ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, "the triage line could not be read")
		if err != nil {
			return nil, err
		}
		bundles, total, err := finding.NewStore(in.DB.DB).Bundles(ctx, subject, scope,
			input.Limit, input.Offset, input.narrow(floor))
		if err != nil {
			return nil, refusedFinding(in, err)
		}

		out := &struct {
			Body struct {
				Items []BundleBody `json:"items"`
				Total int          `json:"total"`
			}
		}{}
		out.Body.Total = total
		oneBuild := scope.StreamID != nil && scope.VariantID != nil
		out.Body.Items = bundleBodies(bundles, oneBuild)
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-fix-bundles", Method: http.MethodGet,
		Path:    "/v1/products/{product}/fix-bundles.{format}",
		Summary: "Export findings by upgrade",
		Description: "The same list as a file: one row per upstream upgrade, with what it closes " +
			"and the builds that hold it.\n\n" +
			"Takes the same selection and the same filters as the screen, from the same " +
			"struct. The builds an upgrade is held in are one cell, separated by spaces, because " +
			"a spreadsheet has no second dimension.",
		Tags: []string{"Findings"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Format  string `path:"format" enum:"csv,json"`
		BundleQuery
	}) (*huma.StreamResponse, error) {
		subject, scope, floor, err := scopedFloor(ctx, in, ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, "the triage line could not be read")
		if err != nil {
			return nil, err
		}
		store := finding.NewStore(in.DB.DB)
		narrowed := input.narrow(floor)
		oneBuild := scope.StreamID != nil && scope.VariantID != nil
		line := "everything"
		if floor.Hides() {
			line = floor.Word
		}
		out := Exporting{
			What:  "findings by upgrade",
			About: []Stated{{"triaged at or above", line}},
			Header: []string{
				"upstream", "from", "to", "components", "issues", "places",
				"builds", "severity", "exploited", "in",
			},
			// Paged through the store the screen reads, so the file is the
			// list rather than a second query that will come to disagree
			// with it.
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				bundles, _, err := store.Bundles(ctx, subject, scope, limit, offset, narrowed)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(bundles))
				for _, body := range bundleBodies(bundles, oneBuild) {
					builds := make([]string, 0, len(body.In))
					for _, at := range body.In {
						builds = append(builds, at.Stream+"/"+at.Variant)
					}
					rows = append(rows, []string{
						body.Upstream, body.From, body.To,
						strings.Join(body.Components, " "),
						strconv.Itoa(body.Issues), strconv.Itoa(body.Places),
						strconv.Itoa(body.Builds), body.Severity,
						strconv.FormatBool(body.Exploited),
						strings.Join(builds, " "),
					})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "fix-bundles-"+downloadName(input.Product), out)
		}}, nil
	})
}

// bundleBodies is the list as it is written, for the screen and for the file.
func bundleBodies(bundles []finding.Bundle, oneBuild bool) []BundleBody {
	out := make([]BundleBody, 0, len(bundles))
	for _, bundle := range bundles {
		body := BundleBody{
			Upstream: bundle.Upstream, From: bundle.From, To: bundle.To,
			Components: bundle.Components,
			Issues:     bundle.Issues, Places: bundle.Places,
			Severity: bundle.Severity, Exploited: bundle.Exploited,
			In: make([]BuildName, 0, len(bundle.In)),
		}
		for _, at := range bundle.In {
			body.In = append(body.In, BuildName{Stream: at.Stream, Variant: at.Variant})
		}
		// Absent where the selection is one build, because then it is the
		// same number on every row.
		if !oneBuild {
			body.Builds = bundle.Builds
		}
		out = append(out, body)
	}
	return out
}

// BuildName is a release and variant, as the catalog names them.
type BuildName struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
}

// PlannedBody is one bump a release is waiting on.
type PlannedBody struct {
	Fold       string   `json:"fold" doc:"The upgrade's own key: the source package at the version it was built at, in the ecosystem and distribution it came from"`
	Upstream   string   `json:"upstream" doc:"What to call it: the source package"`
	From       string   `json:"from"`
	To         string   `json:"to" doc:"The version it moves to, as the commitment recorded it"`
	Components []string `json:"components"`
	Issues     int      `json:"issues" doc:"Distinct issues still open under this upgrade here, which is what it would close. Nothing is declared done by hand: a build is clear when it stops holding them"`
	Places     int      `json:"places" doc:"How many findings those issues sit at"`
	DeclaredAt string   `json:"declared_at" doc:"When the commitment was made, which is what this release has been waiting since"`
	// By, HeldBy and State are the promise, who is carrying it, and where
	// it stands. The state is derived on every read from the scans and the
	// date, and set by nobody.
	By     string `json:"by,omitempty" doc:"The date the promise named, as a date. Absent where the commitment is intent rather than a promise"`
	HeldBy string `json:"held_by,omitempty" doc:"The party carrying it, where one party holds all of what is still open under it. An upgrade split between two is nobody's"`
	State  string `json:"state" enum:"planned,landed,lapsed" doc:"Where it stands. 'landed' is nothing left open under it here, which the scans say; 'lapsed' is the date past with work outstanding. Nobody sets this"`
	// ClaimID is the claim that argued for it, which is the way through to
	// the reasoning, the approval and the conversation about the upgrade.
	ClaimID int64 `json:"claim_id,omitempty" doc:"The claim that argued for it, where one did: its reasoning, its approval and its comments"`
}

func registerPendingUpgrades(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-pending-upgrades", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/pending-upgrades",
		Summary: "List the upgrades one build is waiting on",
		Description: "Everything committed for this build, one row per upgrade — a source package " +
			"at the version it was built at, moving to another version — with what it would " +
			"still close here.\n\n" +
			"**What it covers is a match, not a list.** A finding is covered when its " +
			"component folds to the same key in this build, so changing the version a release " +
			"is moving to is one row, and an issue published tonight against the same package " +
			"is covered by this morning's commitment with nobody acting.\n\n" +
			"**The fix-bundle query read from the other end.** A triager reads an upgrade and the " +
			"issues it closes; a coordinator reads a build and the upgrades it is waiting on. One " +
			"query rather than two reports that will eventually disagree.\n\n" +
			"**Nothing here is declared done.** A piece of work has landed when the build " +
			"stops holding it, which the scans already say — a declared fix that is still " +
			"open after a scan has run is a missed target, and the scan is independent " +
			"evidence against the claim.\n\n" +
			"**Each row says where it stands** — planned, landed, or lapsed — derived on every " +
			"read from the scans and the date the promise named, and set by nobody. A lapsed " +
			"upgrade returns as one item to whoever holds it: the findings it covers stay " +
			"covered, because deciding them again one at a time is the thing the promise was " +
			"made instead of. They return on their own only when the component moved and they " +
			"did not close, which needs nothing extra — a decision is keyed on the version it " +
			"was made against and stops applying the moment that version changes.\n\n" +
			"There is no separate 'replanned': re-promising writes a new date and the standing " +
			"promise is the one read, so a replanned upgrade is a planned one with a later " +
			"date.",
		Tags: []string{"Remediation"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
	}) (*listOutput[PlannedBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		located, err := locatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := targetRow(ctx, in, located.StreamID, located.VariantID)
		if err != nil {
			return nil, err
		}
		planned, err := finding.NewStore(in.DB.DB).PendingUpgrades(ctx, subject, target.ID)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &listOutput[PlannedBody]{}
		out.Body.Items = plannedBodies(planned)
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-pending-upgrades", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/pending-upgrades.{format}",
		Summary: "Export the upgrades one build is waiting on",
		Description: "The same list as a file: one row per upgrade this build is waiting on, " +
			"where it stands, and what it would still close here.\n\n" +
			"The packages one upgrade moves are a single cell, separated by spaces, because a " +
			"spreadsheet has no second dimension.",
		Tags: []string{"Remediation"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Format  string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		located, err := locatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := targetRow(ctx, in, located.StreamID, located.VariantID)
		if err != nil {
			return nil, err
		}
		// Read whole before a byte is written, like the screen reads it: this
		// is one build's plan rather than a paged list, and a refusal has to
		// land before the status is gone.
		planned, err := finding.NewStore(in.DB.DB).PendingUpgrades(ctx, subject, target.ID)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		rows := plannedBodies(planned)
		out := Exporting{
			What: "upgrades this build is waiting on",
			About: []Stated{
				{"build", input.Product + " " + input.Stream + " (" + input.Variant + ")"},
			},
			Header: []string{
				"upstream", "from", "to", "components", "issues", "places",
				"declared_at", "by", "held_by", "state", "claim",
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
					claim := ""
					if row.ClaimID != 0 {
						claim = strconv.FormatInt(row.ClaimID, 10)
					}
					written = append(written, []string{
						row.Upstream, row.From, row.To,
						strings.Join(row.Components, " "),
						strconv.Itoa(row.Issues), strconv.Itoa(row.Places),
						row.DeclaredAt, row.By, row.HeldBy, row.State, claim,
					})
				}
				return written, nil
			},
		}
		name := "pending-upgrades-" + downloadName(input.Product+"-"+input.Stream+"-"+input.Variant)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, name, out)
		}}, nil
	})
}

// plannedBodies is the plan as it is written, for the screen and for the file.
func plannedBodies(planned []finding.Planned) []PlannedBody {
	out := make([]PlannedBody, 0, len(planned))
	for _, one := range planned {
		row := PlannedBody{
			Fold: one.Fold, Upstream: one.Upstream, From: one.From, To: one.To,
			Components: one.Components,
			Issues:     one.Issues, Places: one.Places,
			DeclaredAt: one.DeclaredAt.Format(time.DateOnly),
			HeldBy:     one.HeldBy, State: string(one.State),
			ClaimID: one.ClaimID,
		}
		if row.Components == nil {
			row.Components = []string{}
		}
		if one.By != nil {
			row.By = one.By.Format(time.DateOnly)
		}
		out = append(out, row)
	}
	return out
}
