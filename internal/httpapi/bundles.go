package httpapi

import (
	"context"
	"net/http"
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
	Upstream string `json:"upstream" doc:"What the bump is of: the source package where one is recorded, and the component's own name otherwise"`
	From     string `json:"from" doc:"The version in hand"`
	To       string `json:"to" doc:"The version that fixes it, as whoever packages the component wrote it. Never compared against what ships, only grouped"`
	// Components are the names this bundle moves, which is what makes a
	// bundle keyed on a source package readable.
	Components []string `json:"components" doc:"The packages this one bump moves. More than one where a source package builds several"`
	Issues     int      `json:"issues" doc:"Distinct vulnerabilities the bump closes"`
	Places     int      `json:"places" doc:"How many findings those sit at"`
	Builds     int      `json:"builds,omitempty" doc:"How many builds of the selection hold any of it. Absent where the selection is one build"`
	Severity   string   `json:"severity,omitempty" doc:"The worst of what it closes"`
	Exploited  bool     `json:"exploited,omitempty" doc:"Some of what it closes is being exploited"`
	// In names the builds that hold it, which is what a declaration is
	// offered against: a bump is declared for releases, and the ones worth
	// offering are the ones that have it.
	In []BuildName `json:"in" doc:"The builds that hold this bump"`
}

func registerBundles(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-fix-bundles", Method: http.MethodGet,
		Path:    "/v1/products/{product}/fix-bundles",
		Summary: "List findings by upgrade",
		Description: "One row per upstream bump, with the issues it closes.\n\n" +

			"Keyed on the **source package** where one is recorded and on the component's " +
			"own name otherwise, so packages built from one source are one row — curl, " +
			"libcurl4t64 and libcurl3t64 bump once.\n\n" +
			"Only what has a fix: a bundle is a version to move to, so a finding upstream has " +
			"released nothing for is not in one.\n\n" +
			"Grouping is presentation: one act still writes one decision per component and " +
			"per place.\n\n" +
			"Takes the same selection as the findings list, and six of its filters: " +
			"severity, exploited, component, search, ecosystem and state. Not the rest: a " +
			"filter that answers about a place or a deadline has no row here to narrow.\n\n" +
			"Ordered worst first, and `sort` takes any of: what the bump would close " +
			"(`issues`, `places`), how far it reaches (`builds`), how bad the worst of it is " +
			"(`urgency`, `severity`) and the soonest deadline it would meet (`deadline`). " +
			"`asc` orders the other way. The default answers what should worry you; " +
			"`sort=issues` answers what to do this afternoon.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product   string     `path:"product"`
		Stream    string     `query:"stream" doc:"Limit to one branch or tag"`
		Variant   string     `query:"variant" doc:"Limit to one variant"`
		Severity  string     `query:"severity" enum:"low,medium,high,critical" doc:"Keep only issues rated this badly or worse"`
		Exploited bool       `query:"exploited" doc:"Keep only bumps closing something known to be exploited"`
		Component string     `query:"component" doc:"Keep only bumps moving a component of this name"`
		Search    string     `query:"q" maxLength:"200" doc:"Keep only rows whose component or issue name contains this"`
		Ecosystem string     `query:"ecosystem" doc:"Keep only components of one package kind"`
		State     string     `query:"state" enum:"undecided,waiting,agreed,lapsed" doc:"Keep only groups this far decided"`
		Sort      bundleSort `query:"sort" doc:"Which order to page in. Worst first by default. A bundle with no deadline sorts last whichever direction is asked for"`
		Ascending bool       `query:"asc" doc:"Order the other way — fewest, least urgent, nearest deadline first"`
		Limit     int        `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset    int        `query:"offset" minimum:"0"`
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
			input.Limit, input.Offset, finding.Filter{
				MinSeverity: input.Severity, Exploited: input.Exploited,
				Components: []string{input.Component}, Search: input.Search,
				Ecosystems: []string{input.Ecosystem}, States: []string{input.State},
				BundleSort: finding.BundleSortKey(input.Sort), Ascending: input.Ascending,
				Floor: floor,
			})
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
		out.Body.Items = make([]BundleBody, 0, len(bundles))
		oneBuild := scope.StreamID != nil && scope.VariantID != nil
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
			if !oneBuild {
				body.Builds = bundle.Builds
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}

// BuildName is a release and variant, as the catalog names them.
type BuildName struct {
	Stream  string `json:"stream"`
	Variant string `json:"variant"`
}

// PlannedBody is one bump a release is waiting on.
type PlannedBody struct {
	Fold       string   `json:"fold" doc:"The bump's own key: the source package at the version it was built at, in the ecosystem and distribution it came from"`
	Upstream   string   `json:"upstream" doc:"What to call it: the source package"`
	From       string   `json:"from"`
	To         string   `json:"to" doc:"The version it moves to, as the commitment recorded it"`
	Components []string `json:"components"`
	Issues     int      `json:"issues" doc:"Distinct issues still open under this bump here, which is what it would close. Nothing is declared done by hand: a build is clear when it stops holding them"`
	Places     int      `json:"places" doc:"How many findings those issues sit at"`
	DeclaredAt string   `json:"declared_at" doc:"When the commitment was made, which is what this release has been waiting since"`
	// By, HeldBy and State are the promise, who is carrying it, and where
	// it stands. The state is derived on every read from the scans and the
	// date, and set by nobody.
	By     string `json:"by,omitempty" doc:"The date the promise named, as a date. Absent where the commitment is intent rather than a promise"`
	HeldBy string `json:"held_by,omitempty" doc:"The party carrying it, where one party holds all of what is still open under it. A bump split between two is nobody's"`
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
		Description: "Everything committed for this build, one row per bump — a source package " +
			"at the version it was built at, moving to another version — with what it would " +
			"still close here.\n\n" +
			"**What it covers is a match, not a list.** A finding is covered when its " +
			"component folds to the same key in this build, so changing the version a release " +
			"is moving to is one row, and an issue published tonight against the same package " +
			"is covered by this morning's commitment with nobody acting.\n\n" +
			"**The fix-bundle query read from the other end.** A triager reads a bump and the " +
			"issues it closes; a coordinator reads a build and the bumps it is waiting on. One " +
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
		out.Body.Items = make([]PlannedBody, 0, len(planned))
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
			out.Body.Items = append(out.Body.Items, row)
		}
		return out, nil
	})
}
