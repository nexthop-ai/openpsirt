// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// FindingBody is one issue in one component, with the places it occupies.
type FindingBody struct {
	// Product is present only where the list spans products. Inside one
	// product every row would repeat it, and a column every row agrees
	// about is width the parts that differ need.
	Product     string `json:"product,omitempty" doc:"The product this is open in. Present only on the list that spans products"`
	ProductName string `json:"product_name,omitempty" doc:"That product's display name, or its name where it has none"`

	Vulnerability string `json:"vulnerability" doc:"The issue, under the name it is most widely known by"`
	// Summary is the one line of the issue's own words the row shows. Without
	// it a list of fifty reads "CVE-2026-74280 · linux-image" fifty times, and
	// telling two rows apart costs a click each.
	Summary string `json:"summary,omitempty" doc:"The first line of what the issue says about itself, cut to fit a row. The whole of it is on the finding"`
	// The rating in force rather than the published one, which is what the
	// row is ranked, filtered and clocked by — so a word saying "as the
	// scanner rated it" means the published rating on the evidence and the
	// in-force one here, which is the disagreement this list exists not to
	// have.
	Severity  string `json:"severity,omitempty" doc:"The rating in force: what we rate it where we have said something, and what was published otherwise. A word, not a score"`
	Component string `json:"component" doc:"The component that carries it"`
	Version   string `json:"version" doc:"The version that ships"`
	Upstream  string `json:"upstream,omitempty" doc:"The upstream a fork was made from, where it is one"`
	Source    string `json:"source,omitempty" doc:"The package this binary was built from, where the two differ. The same issue at two binaries of one source is two rows here and one piece of work everywhere else: decided once, upgraded once, routed by one rule"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The kind of package, as its identifier spells it — deb, apk, rpm, golang, cargo, pypi, npm, gem, generic, oci, github, maven and whatever else a producer emits. Read out of the identifier rather than chosen from a list, so the set is open. With the component and version it tells one row from another, which those two alone do not: one build can hold one name at one version as two components, a source repository and the package built from it"`
	Namespace string `json:"namespace,omitempty" doc:"The namespace the package identifier names, where it names one. With the ecosystem it tells apart two components one build holds at one name and one version"`
	FixState  string `json:"fix_state,omitempty" enum:"fixed,none,wont-fix,unknown,mixed" doc:"Upstream's answer about it"`
	FixedIn   string `json:"fixed_in,omitempty" doc:"The version that resolves it, where one exists"`
	// Matched is the route the scanner reached this by, the thing to ask about
	// a distribution's packages. "advisory" is the people who package it
	// saying so, and what they say about a fix is about the version actually
	// installed. "identifier" is a published identifier compared against an
	// upstream version range, which cannot see a backported patch: a
	// distribution that has already fixed this looks the same as one that has
	// not. Empty where the scanner said nothing.
	Matched string `json:"matched,omitempty" enum:"advisory,identifier" doc:"The scanner's route to this"`
	// Places counts the consumers that pull this component in here, and
	// Answered how many of those the build has already argued about. Both
	// ends of the way down, with the middle collapsed. Those two are what
	// differ between sibling rows; the steps between them rarely
	// distinguish anything, so they are counted rather than named.
	Owner  string `json:"owner,omitempty" doc:"The part of the product this belongs to. Absent where the inventory placed the component nowhere"`
	Parent string `json:"parent,omitempty" doc:"The component that directly pulls it in, which is what a decision is about"`
	Middle int    `json:"middle,omitempty" doc:"The number of steps between those two"`
	Chains int    `json:"chains,omitempty" doc:"The number of distinct ways down. More than one means the pair above is one of them"`
	// Builds is where the selection is more than one build, the four above
	// are absent — a chain belongs to one build's graph — and these three
	// take their place.
	Builds      int    `json:"builds,omitempty" doc:"The number of builds in the selection holding this. Absent where the selection is one build"`
	Stream      string `json:"stream,omitempty" doc:"A branch or tag holding this, for linking to. One of them, not the only one: builds says how many there are. Absent where the selection is one build"`
	StreamName  string `json:"stream_name,omitempty" doc:"The branch or tag as it was spelled, or its name where no spelling was recorded"`
	Variant     string `json:"variant,omitempty" doc:"The variant of that build"`
	VariantName string `json:"variant_name,omitempty" doc:"The variant as it was spelled, or its name where no spelling was recorded"`

	// Tags are the words people put on this, as they were typed. On the
	// row because the point of marking work is finding it again in a list,
	// and a mark only the detail screen shows is one nobody sees.
	Tags []string `json:"tags,omitempty" doc:"Words somebody put on this. Free text, no fixed vocabulary"`

	// Fold is the row's subject: the source package at the version it was
	// built at. Two binaries of one source are one row, because deciding about
	// them is one judgment, upgrading them is one act and routing them is one
	// rule.
	Fold string `json:"fold" doc:"The row's subject: the source package at the version it was built at, in the ecosystem and distribution it came from"`
	// Packages and Consumers are the numbers a reader is shown, counted in
	// the units they act in. Places is the unit the bulk cap is measured in
	// and the unit the disposition register expands to.
	Packages  int `json:"packages" doc:"The number of binaries of the source package here. More than one means deciding on this row decides about all of them"`
	Consumers int `json:"consumers" doc:"The number of things pulling those in here. The build itself counts as one where anything is pulled in directly"`
	Places    int `json:"places" doc:"The number of findings under this row. The bulk cap counts these, and the disposition register expands to them, so it is not a number to reconcile with the two above"`
	Answered  int `json:"answered,omitempty" doc:"The number of those the build has already argued do not apply"`
	// State is how far we have decided this group, by the definition the
	// state filter uses, so a row and the filter that found it agree.
	State    core.Standing `json:"state,omitempty" doc:"The decision state: undecided when no place has a decision of any kind, waiting when a claim stands proposed and nobody has agreed, agreed when every place is answered by a standing decision, lapsed when a decision here stopped applying and nothing replaced it. Absent where some places are approved and the rest never decided"`
	SentBack bool          `json:"sent_back,omitempty" doc:"A live claim at one of these places is currently with its author, sent back for more"`

	// Opened, Due and NoDeadline are the clock on the row. The age is this
	// finding's own rather than the year in the identifier, which the
	// identifier already carries: an issue assigned in 2019 that first
	// appeared here last week has been somebody's problem for a week.
	Opened   string `json:"opened,omitempty" doc:"The earliest of these places opening here, as a date. The age a deadline relates to"`
	Due      string `json:"due,omitempty" doc:"The date it is due. Absent where there is none, and then no_deadline gives the reason"`
	DaysLeft *int   `json:"days_left,omitempty" doc:"Negative once it is overdue. Absent where there is no deadline"`
	// Undisclosed says nothing here has been announced, and DiscloseAt
	// when the embargo ends. On the row because a person deciding what may
	// be said about something has to be told before they say it, and the
	// finding screen's notice is the primary signal rather than this.
	Undisclosed bool   `json:"undisclosed,omitempty" doc:"Nothing here has been announced. Anything said about it outside this deployment discloses it"`
	DiscloseAt  string `json:"disclose_at,omitempty" doc:"The date the embargo ends. Reaching it discloses nothing by itself"`

	NoDeadline string `json:"no_deadline,omitempty" enum:"not-rated,below-the-line,nothing-to-take,out-of-support" doc:"The reason there is no deadline: not-rated when a flaw recorded here has no severity yet, below-the-line when this product does not consider it worth triaging, nothing-to-take when upstream has released no fix, or has declined to on an issue nobody is exploiting, out-of-support when its release is past end of life or was built once. Where more than one holds, the narrowest is the one reported"`
	// Exploited is the reason a row sits at the top. A position nobody
	// can explain is one people stop trusting, and then they sort by something
	// else and lose the point of the order entirely.
	Exploited bool `json:"exploited,omitempty" doc:"Somebody is known to be exploiting this"`
	// ExploitedHere is the other reason a row sits at the top, and the one
	// that outranks everything: a person here recorded this product being
	// attacked through the issue. Carried apart from the flag above because
	// the two are different facts, and a row showing one where the other
	// holds is the confusion the pair exists to prevent.
	ExploitedHere bool `json:"exploited_here,omitempty" doc:"This product is recorded as having been exploited through this issue"`
	// Likelihood separates one medium from another, and from a high. It ranks
	// between reachability and severity, so a list ordering by it and not
	// showing it reads as unsorted.
	Likelihood float64 `json:"likelihood,omitempty" doc:"Published estimate that this will be exploited, 0 to 1"`
	// Score is the number the ordering compares. The word beside it comes from
	// whichever scoring generation rated it — 10.0 reads "high" under CVSS v2
	// and "critical" under v3 — so two rows can tie on the number while their
	// words disagree, and without the number that looks mis-sorted.
	Score float64 `json:"score,omitempty" doc:"The severity as a number, which is what the order compares"`
	// ScoreVersion is the scheme that number is on. Two schemes are scorable
	// here and their numbers are not comparable, so a row carrying the number
	// without the scheme invites the comparison it cannot support.
	ScoreVersion string `json:"score_version,omitempty" doc:"The scoring system the number is on"`
}

// FindingsOutput is a page of what is open.
type FindingsOutput struct {
	Body struct {
		Items []FindingBody `json:"items"`
		// Total counts the things to decide about, which is not the number of
		// findings: one issue in one component can occupy sixty
		// places and is one decision.
		Total int `json:"total"`
		// Hidden counts the rows the triage line keeps out, and Floor
		// is the line itself. Stated rather than silently subtracted: a list
		// showing a smaller number with nothing explaining it is how
		// two people quote different figures for one question.
		Hidden int    `json:"hidden,omitempty" doc:"Findings this product does not consider worth triaging, kept out of the list. Still recorded and still counted"`
		Floor  string `json:"floor,omitempty" doc:"The line they are below"`
	}
}

// ComponentFindingBody is one component at one version, with what is open
// against it counted.
type ComponentFindingBody struct {
	Component     string `json:"component"`
	Version       string `json:"version"`
	Upstream      string `json:"upstream,omitempty" doc:"The upstream a fork was cut from, where one is known"`
	Source        string `json:"source_package,omitempty" doc:"The source package this was built from, where one is recorded. What a routing rule matches on: several binary packages of one source move together, so a rule names the source rather than each binary"`
	Ecosystem     string `json:"ecosystem,omitempty" doc:"The kind of package, as its identifier spells it. With the component and version it tells one row from another, which those two alone do not"`
	Namespace     string `json:"namespace,omitempty" doc:"The namespace the package identifier names, where it names one. With the ecosystem it tells apart two components of one name at one version"`
	Issues        int    `json:"issues" doc:"Distinct vulnerabilities open against it, which is how many rows it contributes to the findings list"`
	Places        int    `json:"places" doc:"The number of times those sit somewhere in the build"`
	Exploited     bool   `json:"exploited" doc:"Whether any of them is known-exploited"`
	ExploitedHere bool   `json:"exploited_here,omitempty" doc:"Whether this product is recorded as having been exploited through any of them"`
	// BySeverity and Worst are the parts of the weight. Ranking by count
	// alone answers this view's own question with the opposite of what
	// somebody needs: a package with forty-four issues outranks one with three
	// criticals, and the count says nothing about which.
	BySeverity map[string]int `json:"by_severity,omitempty" doc:"Those issues by how they were rated. 'unrated' is what nobody scored"`
	Worst      core.Band      `json:"worst,omitempty" doc:"The highest band among them. Absent where nothing here was rated"`
	// Upgrades is the versions this can move to, the decision somebody reading
	// a package is making.
	Upgrades []core.UpgradeBody `json:"upgrades,omitempty" doc:"Versions upstream released that would close some of what is open here, furthest along first where the ecosystem defines an ordering and unranked where it does not"`
}

// ComponentFindingsOutput is a page of what is open, by component.
type ComponentFindingsOutput struct {
	Body struct {
		Items []ComponentFindingBody `json:"items"`
		Total int                    `json:"total"`
	}
}

func registerFindings(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/findings",
		Summary: "List vulnerability findings",
		Description: "Returns one row per vulnerability-and-component pair, not one row per " +
			"place the component appears. Each row gives the number of places it occupies and " +
			"how many of those the build's VEX documents already answer.\n\n" +
			"Ordered by urgency — known-exploited first, then whether the build ships to " +
			"customers, then severity, then likelihood. Supports limit and offset.\n\n" +
			"Every filter is applied here, and `total` counts what it admits rather than " +
			"what the page holds.\n\n" +
			"`under` keeps what one container holds directly; `beneath` keeps what sits at a " +
			"component or anywhere under it, which is what the dependency tree's cumulative " +
			"count counts. The tree counts distinct issues and this list is one row per issue " +
			"and component, so a subtree holding one issue at two components is two rows here " +
			"and one there.\n\n" +
			"`stream` and `variant` are optional and independent. With both named the list is " +
			"one build. With either left out it answers for every build under the product " +
			"that matches the rest: a row is still one issue in one component, its place " +
			"count is across every build it is in, and `builds` says how many those are. " +
			"Across more than one build a row carries `stream` and `variant` naming one of " +
			"them to link to, and carries no `owner`, `parent`, `middle` or `chains` — a " +
			"chain belongs to one build's graph. `beneath` is a walk over one build's edges " +
			"and is refused unless both are named.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant string `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
		core.AtOneBuild
		core.Narrowing
		core.Paging
	}) (*FindingsOutput, error) {
		at, err := core.ListNarrowed(ctx, in, core.ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "cannot tell what is worth triaging here")
		if err != nil {
			return nil, err
		}
		subject, scope, floor, narrowed, store := at.Subject, at.Scope, at.Floor, at.Filter, at.Store
		groups, total, err := store.Groups(ctx, subject, scope,
			input.Limit, input.Offset, narrowed)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read what is open")
		}
		hidden, err := store.Hidden(ctx, subject, scope, narrowed)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read what is open")
		}

		out := &FindingsOutput{}
		out.Body.Total = total
		out.Body.Hidden = hidden
		if hidden > 0 {
			out.Body.Floor = floor.Word
		}
		out.Body.Items = make([]FindingBody, 0, len(groups))
		now := time.Now().UTC()
		for _, group := range groups {
			row := findingBody(group, now)
			out.Body.Items = append(out.Body.Items, row)
		}
		return out, nil
	})
}

// findingBody is one row of a findings list, however the list was narrowed.
//
// One spelling for both, because a row means the same thing on the list that
// spans products as on the one that does not — and two spellings is how a
// column comes to say something slightly different on one screen.
func findingBody(group finding.Group, now time.Time) FindingBody {
	row := FindingBody{
		Product: group.Product, ProductName: group.ProductName,
		Vulnerability: group.Vulnerability, Summary: group.Summary,
		Severity:  group.Severity,
		Component: group.Component, Version: group.Version, Upstream: group.Upstream,
		Source:    group.Source,
		Ecosystem: group.Ecosystem, Namespace: group.Namespace,
		FixState: string(group.FixState), FixedIn: group.FixedIn,
		Matched: string(group.Matched),
		Owner:   group.Owner, Parent: group.Parent,
		Middle: group.Middle, Chains: group.Chains,
		Builds: group.Builds, Stream: group.Stream, Variant: group.Variant,
		StreamName:  group.StreamName,
		VariantName: group.VariantName,
		Tags:        group.Tags,
		Fold:        group.Fold, Packages: group.Packages, Consumers: group.Consumers,
		Places: group.Places, Answered: group.Answered,
		State: core.Standing(group.State), SentBack: group.SentBack,
		Exploited: group.Exploited, ExploitedHere: group.ExploitedHere,
		Likelihood:   float64(group.LikelihoodPPM) / 1_000_000,
		Score:        float64(group.ScoreCenti) / 100,
		ScoreVersion: group.ScoreVersion,
		NoDeadline:   string(group.NoDeadline),
		Undisclosed:  group.Undisclosed,
	}
	if group.DiscloseAt != nil {
		row.DiscloseAt = group.DiscloseAt.Format(time.DateOnly)
	}
	if !group.OpenedAt.IsZero() {
		row.Opened = group.OpenedAt.Format(time.DateOnly)
	}
	if group.DueAt != nil {
		row.Due = group.DueAt.Format(time.DateOnly)
		// Rounded down, not toward zero, the way the running-out list
		// rounds it: truncation reports something twelve hours overdue
		// as having zero days left, which reads as due today.
		left := int(math.Floor(group.DueAt.Sub(now).Hours() / 24))
		row.DaysLeft = &left
	}
	return row
}

func registerComponentFindings(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-finding-components", Method: http.MethodGet,
		Path:    "/v1/products/{product}/findings/components",
		Summary: "List findings by component",
		Description: "One row per component and version, with how many distinct issues are " +
			"open against it and how many places those sit at. The level above the findings " +
			"list: it answers where the weight is rather than what is wrong, which is the " +
			"question somebody asks before deciding what to read and what to put aside.\n\n" +
			"It is also how a person finds the one package worth hiding. On a switch " +
			"operating-system image the kernel carried 4,943 of 6,822 findings rows and the " +
			"next largest contributor carried 58 — a fact no list of issues makes visible, " +
			"because ordered by urgency it just looks like a long list.\n\n" +
			"Takes the same filters as the findings list, so the two agree about what is " +
			"being counted. Ordered by how many issues, not by urgency: making urgency the " +
			"default would reproduce the findings list at worse resolution. Each row says " +
			"what its weight is made of — the issues by severity, and the worst among them — " +
			"because ranking by count alone answers this view's own question backwards: a " +
			"package with forty-four issues outranks one with three criticals. `sort` takes " +
			"every key the findings list takes, read of the package rather than of one " +
			"finding — the worst of what is open against it (`severity`, `urgency`, `epss`), " +
			"the oldest thing in it (`age`), the soonest deadline in it (`deadline`) and how " +
			"far it reaches (`places`) — and `asc` orders the other way.\n\n" +
			"`stream` and `variant` are optional and independent, as they are on the findings " +
			"list: with either left out this counts across every build under the product that " +
			"matches the rest. `beneath` is a walk over one build's edges and is refused " +
			"unless both are named.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant string `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
		core.AtOneBuild
		core.Narrowing
		core.Paging
	}) (*ComponentFindingsOutput, error) {
		at, err := core.ListNarrowed(ctx, in, core.ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "cannot tell what is worth triaging here")
		if err != nil {
			return nil, err
		}
		subject, scope, narrowed := at.Subject, at.Scope, at.Filter
		groups, total, err := finding.NewStore(in.DB.DB).ComponentGroups(ctx, subject, scope,
			input.Limit, input.Offset, narrowed)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read what is open")
		}

		out := &ComponentFindingsOutput{}
		out.Body.Total = total
		out.Body.Items = make([]ComponentFindingBody, 0, len(groups))
		for _, group := range groups {
			upgrades := make([]core.UpgradeBody, 0, len(group.Upgrades))
			for _, each := range group.Upgrades {
				upgrades = append(upgrades, core.UpgradeBody{To: each.To, FixedHere: each.FixedHere,
					Reached: each.Reached, Ordered: each.Ordered})
			}
			out.Body.Items = append(out.Body.Items, ComponentFindingBody{
				Component: group.Component, Version: group.Version, Upstream: group.Upstream,
				Source:     group.UpstreamName,
				Ecosystem:  group.Ecosystem,
				Namespace:  group.Namespace,
				BySeverity: group.BySeverity, Worst: core.Band(group.Worst),
				Issues: group.Issues, Places: group.Places, Exploited: group.Exploited,
				ExploitedHere: group.ExploitedHere,
				Upgrades:      upgrades,
			})
		}
		return out, nil
	})
}

// ReferenceBody is somewhere an issue is written up, or fixed.
type ReferenceBody struct {
	URL  string `json:"url"`
	Kind string `json:"kind" enum:"patch,advisory,report,other" doc:"The kind of reference. A patch is the change itself"`
	// Branches is filled from a copy of the repository a patch link names,
	// where this deployment keeps one (REQ-78). A fix is backported as a
	// separate commit to each maintained branch, and this says which link is
	// which.
	Branches    []string `json:"branches,omitempty" doc:"The branches of its repository that contain the commit this patch link names, in version order. At most 100 are listed"`
	BranchCount int      `json:"branch_count,omitempty" doc:"How many branches contain the commit, which may be more than are listed"`
	Lookup      string   `json:"lookup,omitempty" enum:"found,absent" doc:"'found' is a commit the copy of its repository holds, 'absent' one it does not. Omitted where no copy has been asked, or where the link names no commit"`
}

// LinkBody is somewhere to read about this issue or this package, worked out
// from the identifiers held here.
type LinkBody struct {
	URL  string `json:"url"`
	Name string `json:"name" doc:"The destination — the issue's record, a distribution's answer about it, or the package's own page"`
}

// StepBody is one component on the way down to another.
type StepBody struct {
	Component string `json:"component"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The kind of package the step is, as its identifier spells it"`
	Namespace string `json:"namespace,omitempty" doc:"The namespace its package identifier names, where it names one"`
}

// SittingBody is one place a component occupies in this build.
type SittingBody struct {
	Place string `json:"place" doc:"Name this when recording a decision about it"`
	// Component is the package of the fold this place holds. A finding covers
	// every binary one source package was built at one version, so a place
	// named only by its consumer leaves a reader unable to tell one from
	// another.
	Component string `json:"component" doc:"The package of the source package this place is"`
	Consumer  string `json:"consumer,omitempty" doc:"The consumer that pulls the component in. Absent where the build holds it directly"`
	// DeclaredAs is the producer's own word and nothing here reads it. It is
	// not a rank input, not a prefilled outcome, and nothing is hidden by it:
	// reading "build" as "does not ship" is wrong for every compiled language.
	DeclaredAs string `json:"declared_as,omitempty" doc:"The producer's own word for this dependency, where it said anything: a CycloneDX component scope, or an SPDX lifecycle scope. Evidence, and nothing acts on it"`
	Suppressed bool   `json:"suppressed,omitempty" doc:"The build has already argued this place away"`
	Decision   int64  `json:"decision,omitempty" doc:"The claim already standing here, where one does. Not the same as suppressed, which is the build's own argument"`
	Claim      int64  `json:"claim,omitempty" doc:"The action that decision was one row of, so a claim shown on this finding can name the places it covers rather than only count them"`
	// DeferredDays is what a deferral asked for here is added to before it is
	// measured against the threshold, so the form can say which side of it a
	// date falls on before it is sent. Fractional, because the threshold is
	// compared with exact durations and a whole number of days moves the line.
	DeferredDays float64 `json:"deferred_days,omitempty" doc:"The total this place has been put off for, in days and parts of a day, across every deferral recorded about it, taken back ones included for the span they stood"`
	// Chain is display rather than identity. A decision is keyed on the direct
	// consumer and nothing else, which is what keeps one judgment from
	// multiplying by every route through the graph.
	Chain []StepBody `json:"chain,omitempty" doc:"The way down to here, the build first and this component last. Empty where the inventory left the component unplaced"`
}

// RatingBody is one published rating of an issue.
type RatingBody struct {
	Version string  `json:"version" doc:"The scoring system's version, as the report states it"`
	Score   float64 `json:"score" doc:"The score the publisher states for the vector"`
	Vector  string  `json:"vector" doc:"The vector the score is worked out from"`
	Source  string  `json:"source,omitempty" doc:"The publisher, where the report names them"`
	Kind    string  `json:"kind,omitempty" doc:"The rating's rank: primary or secondary"`
}

// ratingBodies is the ratings an issue holds, in the order they were read.
func ratingBodies(ratings []finding.CVSS) []RatingBody {
	if len(ratings) == 0 {
		return nil
	}
	out := make([]RatingBody, 0, len(ratings))
	for _, rating := range ratings {
		version := rating.Version
		if version == "" {
			version = strconv.Itoa(rating.Generation)
		}
		out = append(out, RatingBody{
			Version: version, Score: float64(rating.ScoreCenti) / 100,
			Vector: rating.Vector, Source: rating.Source, Kind: rating.Kind,
		})
	}
	return out
}

// EvidenceBody is everything held about one issue in one component.
type EvidenceBody struct {
	Vulnerability string   `json:"vulnerability"`
	Aliases       []string `json:"aliases,omitempty" doc:"Other names the same issue is known by"`
	AliasesByHand []string `json:"aliases_by_hand,omitempty" doc:"Every name somebody recorded by hand, the one it is filed under included, which are the ones that may be removed"`
	Severity      string   `json:"severity,omitempty" doc:"As the data rates it. A word"`
	// Assessed is our own rating, where somebody has recorded one.
	// Both are carried and both are shown: a rating of ours put where the
	// world's goes reads as the world's, and the first person to check
	// against the public record finds a discrepancy nobody declared.
	Assessed string  `json:"assessed,omitempty" doc:"This deployment's own rating, where somebody has said something. This is what ranks; severity is the published word"`
	Score    float64 `json:"score,omitempty" doc:"The same judgment as a number, where one is published"`
	Vector   string  `json:"vector,omitempty" doc:"The score's assumptions — reachability, privilege, interaction"`
	// ScoreVersion is where the number came from. Everything else a scan
	// says carries its provenance; the one number a deadline is set from
	// carries none.
	ScoreVersion string       `json:"score_version,omitempty" doc:"The scoring system the number is on, as the report states it"`
	ScoreSource  string       `json:"score_source,omitempty" doc:"The publisher, where the report names them"`
	ScoreKind    string       `json:"score_kind,omitempty" doc:"The rating's rank: primary or secondary"`
	Ratings      []RatingBody `json:"ratings,omitempty" doc:"Every published rating of the issue, one per generation of the scoring system, newest first"`
	Exploited    bool         `json:"exploited,omitempty" doc:"Somebody is known to be exploiting this"`
	Likelihood   float64      `json:"likelihood,omitempty" doc:"Published probability of exploitation, 0 to 1"`
	// ExploitedHere is what has been recorded in this product about being
	// exploited through the issue, newest first. Not the flag above: that is a
	// feed's word about the world, and this is somebody here saying this
	// product was the thing attacked.
	//
	// Cleared records are among them rather than hidden. What was said and
	// then taken back is part of the answer to what was known and when.
	ExploitedHere []core.ExploitedHereBody `json:"exploited_here,omitempty" doc:"What has been recorded about this product being exploited through this issue, newest first. At most one of them stands; the rest were cleared"`
	// LikelihoodPercentile ranks the estimate against every other published
	// one, and the day beside it dates the forecast. The probability alone is
	// unreadable — nobody acts on 0.00042 — and it is a thirty-day forecast
	// recomputed daily, so the day it covers is part of it.
	LikelihoodPercentile float64  `json:"likelihood_percentile,omitempty" doc:"The estimate's standing among all published ones, 0 to 1"`
	LikelihoodOn         string   `json:"likelihood_on,omitempty" doc:"The day the estimate was computed for, as a date"`
	Weaknesses           []string `json:"weaknesses,omitempty" doc:"The kind of flaw, as CWE identifiers"`
	Description          string   `json:"description,omitempty"`
	Advisory             string   `json:"advisory,omitempty" doc:"The issue's write-up"`
	// References carries patches first, because for somebody deciding whether
	// to backport rather than upgrade, the change itself is the answer.
	References []ReferenceBody `json:"references,omitempty"`
	// Links are derived here rather than relayed. A scanner points at whatever
	// its data carried, which for a package matched by identifier is often
	// another distribution's write-up and need not include the issue's own
	// record at all.
	Links []LinkBody `json:"links,omitempty"`

	Component string `json:"component"`
	Version   string `json:"version"`
	Upstream  string `json:"upstream,omitempty" doc:"The upstream a fork was made from, where it is one"`
	FixState  string `json:"fix_state,omitempty" enum:"fixed,none,wont-fix,unknown,mixed"`
	FixedIn   string `json:"fixed_in,omitempty" doc:"The version that resolves it"`
	// Matched is the route this place was reached by and MatchedFrom the data
	// that supplied it. The source sits here rather than on the issue because
	// one issue reached through two ecosystems has two answers and the issue
	// holds one, which is how a package from one distribution links to
	// another's tracker.
	Matched     string `json:"matched,omitempty" enum:"advisory,identifier"`
	MatchedFrom string `json:"matched_from,omitempty" doc:"The source of this match"`
	// The evidence for the judgment `matched` asks for, rather than a second
	// way of making it. Recorded as the scanner wrote them and never parsed:
	// deciding whether a version falls inside a range needs an ordering per
	// ecosystem, which this does not have and does not attempt.
	MatchedIn    string `json:"matched_in,omitempty" doc:"The body of vulnerability data that answered, as the scanner names it — an ecosystem's own advisories against the national database's identifiers"`
	MatchedRange string `json:"matched_range,omitempty" doc:"The version range this match fired on. For a distribution's package reached by identifier it is an upstream range, which names no packaging revision and so cannot see a backported fix"`
	FixedAt      string `json:"fixed_at,omitempty" doc:"The date that version became available"`
	// ArrivedFrom says somebody moved this version and the issue came with it.
	// A different sentence aimed at a different person: whoever did the bump,
	// rather than whoever triages.
	ArrivedFrom string `json:"arrived_from,omitempty" doc:"The version this was upgraded from, where the upgrade did not resolve it"`

	// Tags are the words people put on this, as they were typed.
	Tags []string `json:"tags,omitempty" doc:"Words somebody put on this. Free text, no fixed vocabulary"`

	// Opened and FoundBy are when this first appeared here and what
	// produced it. The run that answered is not the run that answers now,
	// so this cannot be worked out again later — and without it the scanner
	// and vulnerability database behind a finding dismissed on 3 March have no
	// record at all.
	Opened string `json:"opened,omitempty" doc:"The earliest of these places first appearing here, as a date"`
	// Due and NoDeadline are the same pair the list carries. The screen
	// somebody decides on needs both.
	Due      string `json:"due,omitempty" doc:"The date it runs out. The earliest among its places, which is the one that makes the whole finding late"`
	DaysLeft *int   `json:"days_left,omitempty" doc:"Negative once it is overdue"`
	// The same words the list body declares, and the words the store emits.
	// A consumer validating against the published document rejects a body
	// carrying a word the enum omits, and a TypeScript one cannot narrow on it.
	NoDeadline string             `json:"no_deadline,omitempty" enum:"not-rated,below-the-line,nothing-to-take,out-of-support" doc:"The reason there is no deadline: not-rated when a flaw recorded here has no severity yet, below-the-line when this product does not consider it worth triaging, nothing-to-take when upstream has released no fix, or has declined to on an issue nobody is exploiting, out-of-support when its release is past end of life or was built once. Where more than one holds, the narrowest is the one reported"`
	FoundBy    *core.MeasuredBody `json:"found_by,omitempty" doc:"The provenance: the scanner, its version, and the vulnerability database it read at the time. Absent on something a person recorded, which no run found"`

	// Recorded says a person entered this rather than a scanner reporting it,
	// which is the one thing that decides whether it can be closed by hand.
	Recorded bool `json:"recorded,omitempty" doc:"Somebody recorded this here rather than a scanner reporting it. Only such a finding can be closed as fixed by hand"`

	// Undisclosed says this has not been announced and DiscloseAt when the
	// embargo ends. The screen's standing notice is what somebody has to
	// be unable to miss before they say anything about it.
	Undisclosed bool   `json:"undisclosed,omitempty" doc:"This has not been announced. Anything said about it outside this deployment discloses it"`
	DiscloseAt  string `json:"disclose_at,omitempty" doc:"The date the embargo ends. Reaching it discloses nothing by itself"`

	// LatestVersion is what upstream has released. Absent unless this
	// deployment has turned asking on, which is off by default because it
	// sends a component's name to a public index.
	LatestVersion    string `json:"latest_version,omitempty" doc:"The newest version the ecosystem's own index knows of"`
	LatestReleasedAt string `json:"latest_released_at,omitempty" doc:"The date that version shipped"`
	NothingSince     bool   `json:"nothing_since,omitempty" doc:"Upstream has released nothing since the year this issue was named, and there is no fix. Two dates compared — it says why there is no fix, not that the project is abandoned"`

	Places []SittingBody `json:"places"`

	// AssignedTo is who is dealing with this, by sign-in identity. Empty means
	// nobody — and it is the same field the assignment route writes, so the
	// screen somebody reads a finding on is the screen they can hand it over
	// from. Being able to record a judgment about something and not to say who
	// is dealing with it is a strange half of the same job.
	//
	// One name for the whole finding, because assignment is set for the whole
	// group at once. Where the places somehow disagree it is left empty rather
	// than naming one of them, which is the same rule the deadline list uses.
	AssignedTo string `json:"assigned_to,omitempty" doc:"The party dealing with this, by sign-in identity. Empty means nobody, or not everywhere the same person"`
	// RoutedBy names the standing rule that placed this, where a rule did
	// rather than a person. A placement nobody can explain is one nobody
	// can correct.
	RoutedBy string `json:"routed_by,omitempty" doc:"The standing rule that placed this, where one did. Empty means a person did, or nobody has"`

	// Standing is the decisions in force here, so the finding is the
	// working screen after a decision as well as before it: the live
	// claims covering any of its places, the decisions that stopped
	// applying with their reasoning offered back, and approved claims
	// about other issues at the same places that may reach this one.
	Standing []core.StandingClaimBody `json:"standing" doc:"Live claims covering any of this finding's places, newest first. A proposed one needing approval is waiting for a second person, and one needing nobody is in force"`
	Previous []core.EarlierBody       `json:"previous" doc:"Decisions made at these places that lapsed or were withdrawn, newest first, with their reasoning"`
	Similar  []core.SimilarBody       `json:"similar" doc:"Approved not-applicable claims about other issues at the same component and consumer, which extends can carry to this one. At most five"`
	// Elsewhere is another product's decision about this same issue at this
	// same place. Evidence and a prefill, never an outcome: the software
	// shipped around a component differs between products, which is the whole
	// reason a place is a component at a position.
	Elsewhere []core.ElsewhereBody `json:"elsewhere" doc:"Approved claims about this same issue at this same place in another product. Evidence to read and quote, and never a decision about this product. At most five"`

	// Vex is the third layer beside the build's own claims and our decisions:
	// the claims a distribution or an upstream security team has published
	// about this component in a VEX document. Evidence and a
	// prefill; never applied to anything by itself, because a third
	// party's claim standing as ours would put somebody else's judgment
	// inside a number we quote.
	Said []core.SaidBody `json:"said" doc:"What publishers have said about this, from VEX documents and supplier advisories uploaded here. Evidence, never applied"`
}

func registerFindingDetail(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-finding", Method: http.MethodGet,
		Path: "/v1/products/{product}/streams/{stream}/variants/{variant}" +
			"/findings/{vulnerability}/components/{component}",
		Summary: "Get everything known about one finding",
		Description: "Returns the full record for one issue in one component of a build: the " +
			"description, the advisory, every reference the data carries with patches listed " +
			"first, the score and what it assumes, whether it is known to be exploited and how " +
			"likely exploitation is, the weakness classification, what upstream has done about " +
			"it, and every place the component sits at here.\n\n" +
			"This is what a triage decision is made from, so it is gathered into one request. " +
			"Each entry in `places` carries the `place` identity to name when recording a " +
			"decision about it.\n\n" +
			"A component name is not unique within a build. `version` says which where it ships " +
			"at several, `ecosystem` where two share a version, and `namespace` where two share " +
			"an ecosystem. A name that still matches more than one is refused with 409, naming " +
			"the choices; where the issue is open at only one of them, that one is answered.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Component     string `path:"component" doc:"The component's name, as the findings list gives it"`
		core.ComponentQuery
	}) (*struct{ Body EvidenceBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := core.LocatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := core.TargetRow(ctx, in, named.StreamID, named.VariantID)
		if err != nil {
			return nil, err
		}

		issue, err := core.IssueHere(ctx, in, subject, named.ProductID, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		// Name and version together, because a name alone is not unique: a
		// real image ships three vendored versions of one library, and
		// resolving the name on its own answers about whichever was interned
		// first — for two of the three rows, an issue it does not carry.
		component, err := core.ComponentCarrying(ctx, in, subject, target.ID, issue,
			input.Component, input.Choice(), func(err error) error { return core.AmbiguousOrMissing(in.Logger, err) })
		if err != nil {
			return nil, err
		}

		evidence, err := finding.NewStore(in.DB.DB).Detail(ctx, subject, target.ID, issue, component)
		if err != nil {
			return nil, core.Absent(in.Logger, err, "that finding could not be read", core.NoSuchFinding)
		}
		body := evidenceBody(*evidence)
		if err := labelPatches(ctx, in.DB.DB, body.References); err != nil {
			return nil, core.WentWrong(in.Logger, "which branches carry the patches could not be read", err)
		}
		if err := putOff(ctx, in, subject, named.ProductID, issue, body.Places); err != nil {
			return nil, core.WentWrong(in.Logger, "how long these places were put off could not be read", err)
		}
		// The record kept in this product, where one stands. Read here rather
		// than in the detail because it is the triage record's, and what it
		// carries — the moment something became known, the grounds, who wrote
		// them — is what a reader of the finding is asking about when the row
		// is at the top of the list and nothing on the page says why.
		if body.ExploitedHere, err = exploitedHereAt(ctx, in, subject,
			named.ProductID, issue, input.Vulnerability); err != nil {
			return nil, core.WentWrong(in.Logger,
				"what this product was exploited through could not be read", err)
		}

		// The build's own places, with the versions it ships at each: what
		// stands is matched by key, and a key carries versions a place name
		// alone does not.
		keyed, err := finding.NewStore(in.DB.DB).PlacesFor(ctx, subject, target.ID, issue, component)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "where this sits could not be read", err)
		}
		body.Standing, body.Previous, body.Similar, body.Elsewhere, err = decidedAbout(ctx, in,
			subject, named.ProductID, issue, keyed)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what was decided here could not be read", err)
		}

		// What publishers have said, matched on every name the issue is known
		// by: the identifier a publisher chose is a preference of whichever
		// database they consulted rather than a property of the issue.
		said, err := finding.NewStore(in.DB.DB).SaidAbout(ctx, subject, named.ProductID,
			issue, append([]string{body.Vulnerability}, body.Aliases...),
			body.Component, evidence.Purl)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what publishers say could not be read", err)
		}
		for _, one := range said {
			// Offered for the version this place ships, because a statement
			// naming a version is about that version: a publisher saying
			// something is fixed in one is saying nothing about another.
			// The component's own identifier where it has one, and its stated
			// version otherwise. The two spellings differ — a Go module is
			// `go1.26.3` and its identifier says `1.26.3` — and the matching
			// path already asks it this way, so asking differently here makes
			// a claim about exactly the version shipped offer nothing.
			at := graph.PartsOfPurl(evidence.Purl).Version
			if at == "" {
				at = evidence.Version
			}
			offers, _ := one.PrefillsFor(at)
			body.Said = append(body.Said, core.SaidBody{
				ID: one.ID, Publisher: one.Publisher,
				Source: core.EvidenceSource(one.Source), Identifier: one.Identifier,
				Status: one.Status, About: one.About,
				Justification: one.Justification, Statement: one.Statement,
				Document: one.Document, At: one.UploadedAt.Format(time.DateOnly),
				Offers: core.OutcomeOffered(offers),
			})
		}
		return &struct{ Body EvidenceBody }{Body: body}, nil
	})
}

func evidenceBody(e finding.Evidence) EvidenceBody {
	body := EvidenceBody{
		Vulnerability: e.Vulnerability, Aliases: e.Aliases, AliasesByHand: e.AliasesByHand,
		Severity: e.Severity,
		Assessed: e.Assessed,
		Score:    float64(e.ScoreCenti) / 100, Vector: e.Vector,
		ScoreVersion: e.ScoreVersion, ScoreSource: e.ScoreSource, ScoreKind: e.ScoreKind,
		Ratings:   ratingBodies(e.Ratings),
		Exploited: e.Exploited, Likelihood: float64(e.LikelihoodPPM) / 1_000_000,
		LikelihoodPercentile: float64(e.LikelihoodPercentilePPM) / 1_000_000,
		// The day rather than an instant: the estimate is computed per day,
		// and a timestamp would state a precision the feed does not have.
		LikelihoodOn: core.DayOf(e.LikelihoodOn),
		Weaknesses:   e.Weaknesses, Description: e.Description, Advisory: e.Advisory,
		Component: e.Component, Version: e.Version, Upstream: e.Upstream,
		FixState: string(e.FixState), FixedIn: e.FixedIn, ArrivedFrom: e.ArrivedFrom,
		Matched: string(e.Matched), MatchedFrom: e.MatchedFrom,
		MatchedIn: e.MatchedIn, MatchedRange: e.MatchedRange, Recorded: e.Recorded,
		LatestVersion: e.LatestVersion, NothingSince: e.NothingSince,
		AssignedTo: e.AssignedTo, Undisclosed: e.Undisclosed, RoutedBy: e.RoutedBy,
		Tags:     e.Tags,
		Places:   make([]SittingBody, 0, len(e.Places)),
		Standing: []core.StandingClaimBody{}, Previous: []core.EarlierBody{}, Similar: []core.SimilarBody{},
		Elsewhere: []core.ElsewhereBody{},
		Said:      []core.SaidBody{},
	}
	if !e.OpenedAt.IsZero() {
		body.Opened = e.OpenedAt.Format(time.DateOnly)
	}
	if e.DueAt != nil {
		body.Due = e.DueAt.Format(time.DateOnly)
		// Rounded down, not toward zero, the way every other screen rounds it:
		// truncation reports something twelve hours overdue as having zero
		// days left, which reads as due today rather than as late.
		left := int(math.Floor(time.Until(*e.DueAt).Hours() / 24))
		body.DaysLeft = &left
	} else {
		body.NoDeadline = string(e.NoDeadline)
	}
	if e.FoundBy != nil {
		body.FoundBy = &core.MeasuredBody{
			Scanner: e.FoundBy.Scanner, ScannerVersion: e.FoundBy.ScannerVersion,
			DatabaseVersion: e.FoundBy.DatabaseVersion, RanHere: e.FoundBy.RanHere,
		}
		if e.FoundBy.RanAt != nil {
			body.FoundBy.RanAt = core.Stamp(*e.FoundBy.RanAt)
		}
	}
	if e.LatestReleasedAt != nil {
		body.LatestReleasedAt = e.LatestReleasedAt.Format(time.DateOnly)
	}
	if e.FixedAt != nil {
		body.FixedAt = e.FixedAt.Format(time.DateOnly)
	}
	if e.DiscloseAt != nil {
		body.DiscloseAt = e.DiscloseAt.Format(time.DateOnly)
	}
	for _, reference := range e.References {
		body.References = append(body.References, ReferenceBody{
			URL: reference.URL, Kind: string(reference.Kind),
		})
	}
	for _, link := range e.Links {
		body.Links = append(body.Links, LinkBody{URL: link.URL, Name: link.Name})
	}
	for _, place := range e.Places {
		sitting := SittingBody{
			Place: place.PlaceIdentity, Component: place.Component,
			Consumer: place.Consumer, Suppressed: place.Suppressed,
			DeclaredAs: place.DeclaredAs,
		}
		if place.Decision != nil {
			sitting.Decision = *place.Decision
		}
		if place.Claim != nil {
			sitting.Claim = *place.Claim
		}
		for _, step := range place.Chain {
			sitting.Chain = append(sitting.Chain, StepBody{
				Component: step.Name, Version: step.Version,
				Ecosystem: graph.EcosystemOf(step.Purl), Namespace: graph.NamespaceOf(step.Purl),
			})
		}
		body.Places = append(body.Places, sitting)
	}
	return body
}

// putOff fills in how long each place has been put off for, in one read.
func putOff(ctx context.Context, in core.Deps, subject access.Subject, productID,
	vulnerabilityID int64, places []SittingBody) error {
	if len(places) == 0 {
		return nil
	}
	names := make([]string, 0, len(places))
	for _, place := range places {
		names = append(names, place.Place)
	}
	totals, err := triage.NewStore(in.DB.DB).DeferredAt(ctx, subject, productID, vulnerabilityID, names)
	if err != nil {
		return err
	}
	for i := range places {
		places[i].DeferredDays = totals[places[i].Place].Hours() / 24
	}
	return nil
}

// labelPatches fills in the branches each patch link's commit is on, where a
// copy of its repository has been asked.
func labelPatches(ctx context.Context, db bun.IDB, references []ReferenceBody) error {
	var links []string
	for _, reference := range references {
		if reference.Kind == string(finding.Patch) {
			links = append(links, reference.URL)
		}
	}
	if len(links) == 0 {
		return nil
	}
	labels, err := patchbranch.Labels(ctx, db, links)
	if err != nil {
		return err
	}
	for i, reference := range references {
		label, ok := labels[reference.URL]
		if !ok || reference.Kind != string(finding.Patch) {
			continue
		}
		references[i].Branches = label.Branches
		references[i].BranchCount = label.Count
		references[i].Lookup = "absent"
		if label.Found {
			references[i].Lookup = "found"
		}
	}
	return nil
}
