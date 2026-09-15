package httpapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// sortOrder is the query parameter for which order to page in, and it takes
// the orders it offers from the store rather than naming them again.
//
// The list a caller sees was a literal in a struct tag, and `finding.SortKeys`
// — which says it is the one list "so the two cannot disagree" — was reached
// from nothing but a test asserting the two matched. That is a second copy
// kept in step by a check rather than by construction, and the check is the
// thing that goes missing. The framework asks a type for its own schema, so
// the enum is built from the same slice the store looks the ordering up in.
type sortOrder string

// Schema answers with the orders the store knows, in its order.
func (sortOrder) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(finding.SortKeys()))
	for _, key := range finding.SortKeys() {
		offered = append(offered, string(key))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// daysBack is the moment a finding must have opened before to have been open
// this long, or none where no age was asked for.
func daysBack(days int) *time.Time {
	if days <= 0 {
		return nil
	}
	at := time.Now().UTC().AddDate(0, 0, -days)
	return &at
}

// daysAhead is the moment a deadline must fall before, or none where nothing
// was asked. Overdue answers itself and needs no window: it is "before now",
// which the store spells so that the two cannot drift.
func daysAhead(days int, overdue bool) *time.Time {
	if overdue || days <= 0 {
		return nil
	}
	at := time.Now().UTC().AddDate(0, 0, days)
	return &at
}

// FindingBody is one issue in one component, with the places it occupies.
type FindingBody struct {
	// Product is present only where the list spans products. Inside one
	// product every row would repeat it, and a column every row agrees
	// about is width the parts that differ need.
	Product     string `json:"product,omitempty" doc:"Which product this is open in. Present only on the list that spans products"`
	ProductName string `json:"product_name,omitempty" doc:"What that product is called, where it has a display name"`

	Vulnerability string `json:"vulnerability" doc:"The issue, under the name it is most widely known by"`
	// Summary is the one line of the issue's own words the row shows. Without
	// it a list of fifty reads "CVE-2026-74280 · linux-image" fifty times, and
	// telling two rows apart costs a click each.
	Summary string `json:"summary,omitempty" doc:"The first line of what the issue says about itself, cut to fit a row. The whole of it is on the finding"`
	// The rating in force rather than the published one, which is what the
	// row is ranked, filtered and clocked by — so a word that said "as the
	// scanner rated it" meant the published rating on the evidence and the
	// in-force one here, which is the disagreement this list exists not to
	// have.
	Severity  string `json:"severity,omitempty" doc:"The rating in force: what we rate it where we have said something, and what was published otherwise. A word, not a score"`
	Component string `json:"component" doc:"What carries it"`
	Version   string `json:"version" doc:"The version that ships"`
	Upstream  string `json:"upstream,omitempty" doc:"What a fork was made from, where it is one"`
	Source    string `json:"source,omitempty" doc:"The package this binary was built from, where the two differ. The same issue at two binaries of one source is two rows here and one piece of work everywhere else: decided once, upgraded once, routed by one rule"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The kind of package, as its identifier spells it — deb, apk, rpm, golang, cargo, pypi, npm, gem, generic, oci, github, maven and whatever else a producer emits. Read out of the identifier rather than chosen from a list, so the set is open. With the component and version it tells one row from another, which those two alone do not: one build can hold one name at one version as two components, a source repository and the package built from it"`
	FixState  string `json:"fix_state,omitempty" enum:"fixed,none,wont-fix,unknown,mixed" doc:"What upstream has done about it"`
	FixedIn   string `json:"fixed_in,omitempty" doc:"The version that resolves it, where one exists"`
	// Matched says how the scanner reached this, and it is the question to ask
	// about a distribution's packages. "advisory" is the people who package it
	// saying so, and what they say about a fix is about the version actually
	// installed. "identifier" is a published identifier compared against an
	// upstream version range, which cannot see a backported patch: a
	// distribution that has already fixed this looks the same as one that has
	// not. Empty where the scanner said nothing.
	Matched string `json:"matched,omitempty" enum:"advisory,identifier" doc:"How the scanner reached this"`
	// Places is how many consumers pull this component in here, and
	// Answered how many of those the build has already argued about. Both
	// ends of the way down, with the middle collapsed. Those two are what
	// differ between sibling rows; the steps between them rarely
	// distinguish anything, so they are counted rather than named.
	Owner  string `json:"owner,omitempty" doc:"The part of the product this belongs to. Absent where the inventory placed the component nowhere"`
	Parent string `json:"parent,omitempty" doc:"What directly pulls it in, which is what a decision is about"`
	Middle int    `json:"middle,omitempty" doc:"How many steps sit between those two"`
	Chains int    `json:"chains,omitempty" doc:"How many distinct ways down there are. More than one means the pair above is one of them"`
	// Where the selection is more than one build, the four above are absent —
	// a chain belongs to one build's graph — and these three take their place.
	Builds  int    `json:"builds,omitempty" doc:"How many builds in the selection hold this. Absent where the selection is one build"`
	Stream  string `json:"stream,omitempty" doc:"A branch or tag holding this, for linking to. One of them, not the only one: builds says how many there are. Absent where the selection is one build"`
	Variant string `json:"variant,omitempty" doc:"The variant of that build"`

	// Tags are the words people put on this, as they were typed. On the
	// row because the point of marking work is finding it again in a list,
	// and a mark only the detail screen shows is one nobody sees.
	Tags []string `json:"tags,omitempty" doc:"Words somebody put on this. Free text, no fixed vocabulary"`

	// Fold is what the row is about: the source package at the version it was
	// built at. Two binaries of one source are one row, because deciding about
	// them is one judgment, upgrading them is one act and routing them is one
	// rule.
	Fold string `json:"fold" doc:"What this row is about: the source package at the version it was built at, in the ecosystem and distribution it came from"`
	// Packages and Consumers are the numbers a reader is shown, counted in
	// the units they act in. Places is what the bulk cap is measured against
	// and what the disposition register expands to.
	Packages  int `json:"packages" doc:"How many binaries of the source package sit here. More than one means deciding on this row decides about all of them"`
	Consumers int `json:"consumers" doc:"How many things pull those in here. The build itself counts as one where anything is pulled in directly"`
	Places    int `json:"places" doc:"How many findings sit under this row. What the bulk cap counts and what the disposition register expands to, rather than a number to reconcile with the two above"`
	Answered  int `json:"answered,omitempty" doc:"How many of those the build has already argued do not apply"`
	// State is how far we have decided this group, by the definition the
	// state filter uses, so a row and the filter that found it agree.
	State    string `json:"state,omitempty" enum:"undecided,waiting,agreed,lapsed" doc:"How far this has been decided: undecided when no place has a decision of any kind, waiting when a claim stands proposed and nobody has agreed, agreed when every place is answered by a standing decision, lapsed when a decision here stopped applying and nothing replaced it. Absent where some places are approved and the rest never decided"`
	SentBack bool   `json:"sent_back,omitempty" doc:"A live claim at one of these places is currently with its author, sent back for more"`

	// Opened, Due and NoDeadline are the clock on the row. The age is this
	// finding's own rather than the year in the identifier, which the
	// identifier already carries: an issue assigned in 2019 that first
	// appeared here last week has been somebody's problem for a week.
	Opened   string `json:"opened,omitempty" doc:"When the earliest of these places opened here, as a date. The age a deadline relates to"`
	Due      string `json:"due,omitempty" doc:"When it is due, as a date. Absent where there is none, and then no_deadline says why"`
	DaysLeft *int   `json:"days_left,omitempty" doc:"Negative once it is overdue. Absent where there is no deadline"`
	// Undisclosed says nothing here has been announced, and DiscloseAt
	// when the embargo ends. On the row because a person deciding what may
	// be said about something has to be told before they say it, and the
	// finding screen's notice is the primary signal rather than this.
	Undisclosed bool   `json:"undisclosed,omitempty" doc:"Nothing here has been announced. Anything said about it outside this deployment discloses it"`
	DiscloseAt  string `json:"disclose_at,omitempty" doc:"When the embargo ends, as a date. Reaching it discloses nothing by itself"`

	NoDeadline string `json:"no_deadline,omitempty" enum:"below-the-line,out-of-support" doc:"Why there is no deadline: below-the-line when this product does not consider it worth triaging, out-of-support when its release is past end of life. Those are the only two, and both are deliberate"`
	// Exploited is why something is at the top when it is. A position nobody
	// can explain is one people stop trusting, and then they sort by something
	// else and lose the point of the order entirely.
	Exploited bool `json:"exploited,omitempty" doc:"Somebody is known to be exploiting this"`
	// Likelihood is why one medium sits above another, and above a high. It
	// ranks between whether something reaches customers and how severe it is,
	// so a list that orders by it and does not show it reads as unsorted.
	Likelihood float64 `json:"likelihood,omitempty" doc:"Published estimate that this will be exploited, 0 to 1"`
	// Score is what the ordering compares. The word beside it comes from
	// whichever scoring generation rated it — 10.0 reads "high" under CVSS v2
	// and "critical" under v3 — so two rows can tie on the number while their
	// words disagree, and without the number that looks mis-sorted.
	Score float64 `json:"score,omitempty" doc:"The severity as a number, which is what the order compares"`
}

// FindingsOutput is a page of what is open.
type FindingsOutput struct {
	Body struct {
		Items []FindingBody `json:"items"`
		// Total is how many things there are to decide about, which is not the
		// number of findings: one issue in one component can occupy sixty
		// places and is one decision.
		Total int `json:"total"`
		// Hidden is what the triage line kept out, and Floor is the
		// line itself. Said rather than silently subtracted: a list
		// showing a smaller number with nothing explaining it is how
		// two people quote different figures for one question.
		Hidden int    `json:"hidden,omitempty" doc:"Findings this product does not consider worth triaging, kept out of the list. Still recorded and still counted"`
		Floor  string `json:"floor,omitempty" doc:"The line they are below"`
	}
}

// UpgradeBody is a version a component could move to, and what that would fix.
type UpgradeBody struct {
	To string `json:"to" doc:"The version, as whoever packages the component wrote it"`
	// Two counts, because they answer different questions and confusing them
	// reads backwards: a quiet release late on a maintained line fixes two of
	// its own while carrying every fix before it.
	FixedHere int  `json:"fixed_here" doc:"How many of what is open here name this exact version as their fix — that release's own security content"`
	Reached   int  `json:"reached" doc:"How many moving here would close altogether, counting everything fixed at or before it. Equal to fixed_here where the versions could not be ordered"`
	Ordered   bool `json:"ordered" doc:"Whether these versions could be ordered at all. False means the list is not ranked and reached says no more than fixed_here"`
}

// ComponentFindingBody is one component at one version, with what is open
// against it counted.
type ComponentFindingBody struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Upstream  string `json:"upstream,omitempty" doc:"What a fork was cut from, where one is known"`
	Source    string `json:"source_package,omitempty" doc:"The source package this was built from, where one is recorded. What a routing rule matches on: several binary packages of one source move together, so a rule names the source rather than each binary"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The kind of package, as its identifier spells it. With the component and version it tells one row from another, which those two alone do not"`
	Issues    int    `json:"issues" doc:"Distinct vulnerabilities open against it, which is how many rows it contributes to the findings list"`
	Places    int    `json:"places" doc:"How many times those sit somewhere in the build"`
	Exploited bool   `json:"exploited" doc:"Whether any of them is known-exploited"`
	// BySeverity and Worst are what the weight is made of. Ranking by count
	// alone answers this view's own question with the opposite of what
	// somebody needs: a package with forty-four issues outranks one with three
	// criticals, and the count says nothing about which.
	BySeverity map[string]int `json:"by_severity,omitempty" doc:"Those issues by how they were rated. 'unrated' is what nobody scored"`
	Worst      string         `json:"worst,omitempty" enum:"critical,high,medium,low" doc:"The highest band among them. Absent where nothing here was rated"`
	// Where this could go, which is what somebody reading a package is
	// deciding about.
	Upgrades []UpgradeBody `json:"upgrades,omitempty" doc:"Versions upstream released that would close some of what is open here, furthest along first where the ecosystem defines an ordering and unranked where it does not"`
}

// ComponentFindingsOutput is a page of what is open, by component.
type ComponentFindingsOutput struct {
	Body struct {
		Items []ComponentFindingBody `json:"items"`
		Total int                    `json:"total"`
	}
}

// planned is what a promised upgrade should do to the list. "either" is a word
// in the request and the absence of a filter in the store, because a screen
// that narrows by default needs a way to say "stop" that is distinguishable
// from having said nothing — the address is what a reader sends somebody else,
// and a filter it cannot spell is one that cannot be turned off in a link.
func planned(word string) finding.PlannedFilter {
	if word == "either" {
		return finding.PlannedEither
	}
	return finding.PlannedFilter(word)
}

// fixStates is the fix statuses as the store takes them, which is a named
// type rather than the words the request carries.
func fixStates(words []string) []finding.FixState {
	out := make([]finding.FixState, 0, len(words))
	for _, word := range words {
		out = append(out, finding.FixState(word))
	}
	return out
}

// filter turns what was asked for into what the store narrows by.
//
// One mapping for both lists, for the same reason the parameters are one
// struct: two of these would drift, and the drift would be a filter that
// answers on one list and is quietly ignored on the other.
func (n Narrowing) filter(floor finding.Floor) (finding.Filter, error) {
	narrowed := finding.Filter{
		MinSeverity:   n.Severity,
		Exploited:     n.Exploited,
		HasFix:        n.Fixable,
		Components:    n.Component,
		Tags:          n.Tag,
		Search:        n.Search,
		Ecosystems:    n.Ecosystem,
		Under:         n.Under,
		UnderTheBuild: n.UnderBuild,
		States:        n.State,
		Outcomes:      n.Outcome,
		Assigned:      n.Assigned,
		Reassessed:    n.Reassessed,
		Recorded:      n.Recorded,
		Planned:       planned(n.Planned),
		Unconfirmed:   n.Unconfirmed,
		Exclude:       n.Exclude,
		Floor:         floor,
		BelowFloor:    n.BelowFloor,
		Workable:      finding.Working(n.On, n.Support),
		// Straight through: what reaches the statement is the
		// allowlist's own expression, chosen by this key, never the
		// key itself . A word that is not one of them is not a sort
		// and the list comes back in its own order.
		SortBy:    finding.SortKey(n.Sort),
		Ascending: n.Ascending,

		LikelihoodAtLeast: int(n.Likelihood * 1_000_000),
		OpenedBefore:      daysBack(n.OpenFor),
		DueBefore:         daysAhead(n.DueWithin, n.Overdue),
		Overdue:           n.Overdue,
		FixStates:         fixStates(n.FixState),
		Weaknesses:        n.Weakness,
		SentBack:          n.SentBack,
		Publishers:        n.Publisher,
		VexStatus:         n.Said,
	}
	for _, each := range []struct {
		text string
		at   **time.Time
	}{
		{n.OpenedAfter, &narrowed.OpenedAfter},
		{n.ClosedAfter, &narrowed.ClosedAfter},
		{n.DecidedAfter, &narrowed.ProposedAfter},
	} {
		when, err := finding.Since(each.text)
		if err != nil {
			// No store was reached, so there is nothing an engine could have
			// broken: this is a date nothing can read, which is the caller's.
			return narrowed, huma.Error422UnprocessableEntity(err.Error())
		}
		*each.at = when
	}
	return narrowed, nil
}

// Narrowing is the filters both findings lists take: the per-product one and
// the one that spans products.
//
// Named once and embedded in both, because two lists that narrowed by slightly
// different sets of words would be two answers to the same question side by
// side — and the drift would arrive one forgotten parameter at a time. What is
// *not* here is what belongs to one build: a subtree is a walk over one
// build's edges, and "differs between builds" is a statement about a
// selection.
// Every array here carries a bound and every free-text field a length, for the
// reason the ones that already did carry theirs: each element becomes a member
// of an IN clause on the findings, the counts and every export, and four of
// the seven were bounded by nothing at all — which is an inconsistency before
// it is a limit, and the inconsistency is what says nobody decided.
type Narrowing struct {
	Severity   string   `query:"severity" enum:"low,medium,high,critical" doc:"Keep only issues rated this badly or worse. 'low' excludes nothing, including issues carrying no rating"`
	Exploited  bool     `query:"exploited" doc:"Keep only issues somebody is known to be exploiting"`
	Fixable    bool     `query:"fixable" doc:"Keep only issues where an upstream fixed version is known"`
	BelowFloor bool     `query:"below_floor" doc:"Include what this product does not consider worth triaging. Those are always recorded and counted; this asks to see them in the list"`
	Component  []string `query:"component,explode" maxItems:"200" maxLength:"191" doc:"Keep only what is open against components of these names, whatever version. Any of them, not all: a component is one name and asking for two means either"`
	Tag        []string `query:"tag,explode" maxItems:"200" maxLength:"191" doc:"Keep only what somebody marked with one of these words, matched without regard to capitals. Any of them, not all. Free text: what is in use here is listed at /v1/products/{product}/tags"`
	Search     string   `query:"q" maxLength:"200" doc:"Keep only rows whose component name or issue name contains this, ignoring capitals. Issue names include every alias, so searching the name a reporter used reaches the row filed under the name a scanner used. A way to find a package, or an advisory, in a list of thousands — where component is the exact package name"`
	Ecosystem  []string `query:"ecosystem,explode" maxItems:"200" maxLength:"64" doc:"Keep only components of these package kinds, as the package identifier spells them — deb, apk, rpm, golang, cargo, pypi, npm, gem, generic, oci, github, maven, or anything else a producer emits. The kind is read out of the identifier rather than chosen from a list, so any string is accepted and one nothing carries matches nothing. Not the language's name — Rust is cargo and Python is pypi"`
	// The two questions about the release itself, kept apart because a tag
	// can be in support and a branch can be past end-of-life. Both default to
	// the working population, and both say so on the screen: a default that
	// narrows silently makes the count something other than the whole count
	// with nothing saying so.
	On           []string  `query:"on,explode" enum:"branch,tag" doc:"Keep only what sits in releases of these kinds. Defaults to branches: no work lands in a tag, whatever anybody decides about it. Ask for both to see everything"`
	Support      []string  `query:"support,explode" enum:"in-support,past-eol" doc:"Keep only what sits in releases in this state of support, its own end-of-life date or the product's. Defaults to what is still in support. Ask for both to see everything"`
	Under        string    `query:"under" maxLength:"191" doc:"Keep only what sits inside the container of this name"`
	UnderBuild   bool      `query:"under_build" doc:"Keep only what the build holds directly, which is what has no container above it"`
	State        []string  `query:"state,explode" enum:"undecided,waiting,agreed,lapsed" doc:"Keep only groups this far decided. A group covers every place an issue sits at in one component, so this is a statement about all of them: undecided means nothing stands, waits or has lapsed at any place, agreed means every place is answered"`
	Outcome      []string  `query:"outcome,explode" enum:"affected,not-applicable,deferred,wont-fix,already-fixed,upgrade-needed,patch-needed" doc:"Keep only groups a standing judgment of this kind covers — how to ask what has been dismissed, which state cannot answer: agreed says a judgment stands, not which one. Every place must be answered the same way, and only the claim standing now counts"`
	Assigned     []string  `query:"assigned,explode" enum:"me,somebody,nobody" doc:"Keep only groups by who is dealing with them. 'me' means mine or a team I am on. A group whose places are held by different parties is none of these. Several answers hold together: mine and whatever nobody has picked up is one question"`
	Likelihood   float64   `query:"epss_at_least" minimum:"0" maximum:"1" doc:"Keep only issues the published estimate rates at least this likely to be exploited, 0 to 1"`
	OpenFor      int       `query:"open_for" minimum:"1" doc:"Keep only what has been open here for at least this many days. The finding's own age, not the year in its identifier"`
	DueWithin    int       `query:"due_within" minimum:"1" doc:"Keep only what runs out within this many days. What is already past its deadline is asked for with overdue instead"`
	Overdue      bool      `query:"overdue" doc:"Keep only what is already past its deadline"`
	FixState     []string  `query:"fix_state,explode" enum:"fixed,none,wont-fix,unknown,mixed" doc:"Keep only what upstream has done one of these about. 'none' and 'wont-fix' are the rows that need a judgment rather than a bump, and the fixable flag cannot ask for either. 'unknown' is the scanner declining to say, which is not the same as upstream having released nothing. 'mixed' is a group whose places disagree — fixed in one build and not another — which has no single answer and is the population a half-landed bump shows up in"`
	Weakness     []string  `query:"weakness,explode" maxItems:"200" maxLength:"32" doc:"Keep only issues of these kinds of flaw, by CWE identifier — CWE-79. Any of them, not all: a class of flaw is usually several identifiers"`
	SentBack     bool      `query:"sent_back" doc:"Keep only groups where a claim is with its author, sent back for more"`
	Publisher    []string  `query:"vex_publisher,explode" maxItems:"200" maxLength:"191" doc:"Keep only what one of these VEX publishers has a standing statement about"`
	OpenedAfter  string    `query:"opened_after" doc:"Keep only what was first seen here after this date, as 2026-03-31"`
	ClosedAfter  string    `query:"closed_after" doc:"Keep only what stopped being present after this date. Closed rows are outside this list's own population, so asking changes what it is about rather than narrowing it"`
	DecidedAfter string    `query:"proposed_after" doc:"Keep only what somebody claimed something about after this date"`
	Said         []string  `query:"vex_status,explode" enum:"not_affected,affected,fixed,under_investigation" doc:"Keep only what a VEX statement says one of these about, in the format's own vocabulary. With a publisher, both must hold"`
	Reassessed   bool      `query:"reassessed" doc:"Keep only groups whose issue we rated differently from the world — what has been re-prioritized here"`
	Recorded     bool      `query:"recorded" doc:"Keep only what a person recorded here rather than what a scanner reported. Those are the only ones a person may close by hand, and the screen that records one is where somebody asks what has been recorded before"`
	Planned      string    `query:"planned" enum:"planned,unplanned,either" doc:"Keep only what a promised upgrade covers, or only what none covers. Derived from the decisions rather than stored, so withdrawing a promise puts what it covered back with nothing to clean up. 'unplanned' is the working list once planned work is out of view, and is what the by-issue list asks unless told otherwise; 'either' is how a reader asks for it back, and is what leaving this out means"`
	Unconfirmed  bool      `query:"unconfirmed" doc:"Keep only groups a scanner reached by comparing a published identifier against an upstream version range, never against an advisory for the package in its own ecosystem. A distribution backports fixes without moving the upstream version, so these are neither confirmed nor refuted — somebody has to look, and finding them one at a time is not a thing anybody does"`
	Exclude      []string  `query:"exclude,explode" maxItems:"200" maxLength:"191" doc:"Drop components of these names. One package can drown the list: on a switch image the kernel carried 4,943 of 6,822 rows"`
	Sort         sortOrder `query:"sort" doc:"Which order to page in. Urgency by default, which is what the list is designed around: what somebody with an hour should look at first. A finding with no deadline sorts last whichever direction is asked for"`
	Ascending    bool      `query:"asc" doc:"Order the other way — oldest, nearest deadline, fewest places, lowest first"`
}

// Paging is how much of a list to return, kept apart from the filters so that
// something answering the whole of a narrowing — an export — can take every
// filter without also offering a page size it does not honor. A parameter that
// changes nothing is worse than one that is missing.
type Paging struct {
	Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"How many to return"`
	Offset int `query:"offset" minimum:"0" doc:"How many to skip"`
}

// AtOneBuild is what narrows a list within a single product's builds, and has
// no meaning across products: a subtree is a walk over one build's edges, and
// "differs between builds" is a statement about a selection.
type AtOneBuild struct {
	Beneath string `query:"beneath" doc:"Keep only what sits at this component or anywhere under it — what the dependency tree's cumulative count counts. The name must be in the build; a name that is not, or that the build holds at more than one version, is refused"`
	Differs bool   `query:"differs" doc:"Keep only groups open in some builds of this selection and not others. Meaningless where the selection is one build, and ignored there"`
}

func registerFindings(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/findings",
		Summary: "List vulnerability findings",
		Description: "Returns one row per vulnerability-and-component pair, not one row per " +
			"place the component appears. Each row gives the number of places it occupies and " +
			"how many of those the build's VEX documents already answer.\n\n" +
			"Ordered by urgency — known-exploited first, then whether the build ships to " +
			"customers, then severity, then likelihood. Supports limit and offset.\n\n" +
			"**Every filter is applied here, and `total` counts what it admits** rather than " +
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
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant string `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
		AtOneBuild
		Narrowing
		Paging
	}) (*FindingsOutput, error) {
		at, err := narrowing(ctx, in, ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "cannot tell what is worth triaging here")
		if err != nil {
			return nil, err
		}
		subject, scope, floor, narrowed, store := at.Subject, at.Scope, at.Floor, at.Filter, at.Store
		groups, total, err := store.Groups(ctx, subject, scope,
			input.Limit, input.Offset, narrowed)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read what is open")
		}
		hidden, err := store.Hidden(ctx, subject, scope, narrowed)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read what is open")
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
	{
		{
			row := FindingBody{
				Product: group.Product, ProductName: group.ProductName,
				Vulnerability: group.Vulnerability, Summary: group.Summary,
				Severity:  group.Severity,
				Component: group.Component, Version: group.Version, Upstream: group.Upstream,
				Source:    group.Source,
				Ecosystem: group.Ecosystem,
				FixState:  string(group.FixState), FixedIn: group.FixedIn,
				Matched: string(group.Matched),
				Owner:   group.Owner, Parent: group.Parent,
				Middle: group.Middle, Chains: group.Chains,
				Builds: group.Builds, Stream: group.Stream, Variant: group.Variant,
				Tags: group.Tags,
				Fold: group.Fold, Packages: group.Packages, Consumers: group.Consumers,
				Places: group.Places, Answered: group.Answered,
				State: group.State, SentBack: group.SentBack,
				Exploited:   group.Exploited,
				Likelihood:  float64(group.LikelihoodPPM) / 1_000_000,
				Score:       float64(group.ScoreCenti) / 100,
				NoDeadline:  string(group.NoDeadline),
				Undisclosed: group.Undisclosed,
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
	}
}

func registerComponentFindings(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
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
			"package with forty-four issues outranks one with three criticals. Ask for " +
			"`sort=severity` (or `urgency`) to order by the worst instead, which is the other " +
			"question somebody reads this to answer.\n\n" +
			"`stream` and `variant` are optional and independent, as they are on the findings " +
			"list: with either left out this counts across every build under the product that " +
			"matches the rest. `beneath` is a walk over one build's edges and is refused " +
			"unless both are named.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant string `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
		AtOneBuild
		Narrowing
		Paging
	}) (*ComponentFindingsOutput, error) {
		at, err := narrowing(ctx, in, ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "cannot tell what is worth triaging here")
		if err != nil {
			return nil, err
		}
		subject, scope, narrowed := at.Subject, at.Scope, at.Filter
		groups, total, err := finding.NewStore(in.DB.DB).ComponentGroups(ctx, subject, scope,
			input.Limit, input.Offset, narrowed)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read what is open")
		}

		out := &ComponentFindingsOutput{}
		out.Body.Total = total
		out.Body.Items = make([]ComponentFindingBody, 0, len(groups))
		for _, group := range groups {
			upgrades := make([]UpgradeBody, 0, len(group.Upgrades))
			for _, each := range group.Upgrades {
				upgrades = append(upgrades, UpgradeBody{To: each.To, FixedHere: each.FixedHere,
					Reached: each.Reached, Ordered: each.Ordered})
			}
			out.Body.Items = append(out.Body.Items, ComponentFindingBody{
				Component: group.Component, Version: group.Version, Upstream: group.Upstream,
				Source:     group.UpstreamName,
				Ecosystem:  group.Ecosystem,
				BySeverity: group.BySeverity, Worst: group.Worst,
				Issues: group.Issues, Places: group.Places, Exploited: group.Exploited,
				Upgrades: upgrades,
			})
		}
		return out, nil
	})
}

// beneathIn resolves the component a list is narrowed beneath. Nil where
// nothing was asked. The walk under it is the store's, in the statement that
// lists.
//
// A name the build does not hold is refused rather than answered with an
// empty list: an empty list is also what a subtree with nothing open looks
// like, and the two mean different things to whoever typed the name.
//
// The subtree is a walk over one build's edges, so a selection holding several
// is refused here as well as in the store. Which builds a selection holds is
// asked of the store rather than inferred from which levels were named — one
// rule, in one place, so the endpoint cannot come to disagree with the
// statement it is narrowing.
func beneathIn(ctx context.Context, in Ingest, scope finding.Scope, name string) (*int64, error) {
	if name == "" {
		return nil, nil
	}
	targets, err := finding.NewStore(in.DB.DB).Builds(ctx, scope)
	if err != nil {
		return nil, wentWrong(in.Logger, "cannot tell which builds are in scope", err)
	}
	if len(targets) != 1 {
		return nil, huma.Error422UnprocessableEntity(
			"a subtree is a walk over one build's edges, so narrowing beneath a component" +
				" needs a branch and a variant that name exactly one build")
	}
	componentID, err := graph.NewStore(in.DB.DB).ComponentAt(ctx, targets[0], name)
	if err != nil {
		if errors.Is(err, graph.ErrAmbiguous) {
			return nil, huma.Error422UnprocessableEntity(
				"this build holds " + name + " at more than one version, so it cannot be narrowed beneath by name alone")
		}
		return nil, huma.Error422UnprocessableEntity("this build does not hold a component called " + name)
	}
	return &componentID, nil
}

// ReferenceBody is somewhere an issue is written up, or fixed.
type ReferenceBody struct {
	URL  string `json:"url"`
	Kind string `json:"kind" enum:"patch,advisory,report,other" doc:"What it appears to be. A patch is the change itself"`
}

// LinkBody is somewhere to read about this issue or this package, worked out
// from the identifiers held here.
type LinkBody struct {
	URL  string `json:"url"`
	Name string `json:"name" doc:"What is at the other end — the issue's record, a distribution's answer about it, or the package's own page"`
}

// StepBody is one component on the way down to another.
type StepBody struct {
	Component string `json:"component"`
	Version   string `json:"version,omitempty"`
}

// SittingBody is one place a component occupies in this build.
type SittingBody struct {
	Place string `json:"place" doc:"Name this when recording a decision about it"`
	// Component is which package of the fold this place is. A finding covers
	// every binary one source package was built at one version, so a place
	// named only by its consumer leaves a reader unable to tell one from
	// another.
	Component  string `json:"component" doc:"Which package of the source package this place is"`
	Consumer   string `json:"consumer,omitempty" doc:"What pulls the component in here. Absent under the product itself"`
	Suppressed bool   `json:"suppressed,omitempty" doc:"The build has already argued this place away"`
	Decision   int64  `json:"decision,omitempty" doc:"The claim already standing here, where one does. Not the same as suppressed, which is the build's own argument"`
	Claim      int64  `json:"claim,omitempty" doc:"The action that decision was one row of, so a claim shown on this finding can name the places it covers rather than only count them"`
	// Chain is display rather than identity. A decision is keyed on the direct
	// consumer and nothing else, which is what keeps one judgment from
	// multiplying by every route through the graph.
	Chain []StepBody `json:"chain,omitempty" doc:"The way down to here, the build first and this component last. Empty where the inventory left the component unplaced"`
}

// EvidenceBody is everything held about one issue in one component.
type EvidenceBody struct {
	Vulnerability string   `json:"vulnerability"`
	Aliases       []string `json:"aliases,omitempty" doc:"Other names the same issue is known by"`
	Severity      string   `json:"severity,omitempty" doc:"As the data rates it. A word"`
	// Assessed is what we say instead, where somebody has said something.
	// Both are carried and both are shown: a rating of ours put where the
	// world's goes reads as the world's, and the first person to check
	// against the public record finds a discrepancy nobody declared.
	Assessed    string   `json:"assessed,omitempty" doc:"What we rate it, where we have said something. This is what ranks; severity is what was published"`
	Score       float64  `json:"score,omitempty" doc:"The same judgment as a number, where one is published"`
	Vector      string   `json:"vector,omitempty" doc:"What the score assumes — reachability, privilege, interaction"`
	Exploited   bool     `json:"exploited,omitempty" doc:"Somebody is known to be exploiting this"`
	Likelihood  float64  `json:"likelihood,omitempty" doc:"Published probability of exploitation, 0 to 1"`
	Weaknesses  []string `json:"weaknesses,omitempty" doc:"What kind of flaw this is, as CWE identifiers"`
	Description string   `json:"description,omitempty"`
	Advisory    string   `json:"advisory,omitempty" doc:"Where the issue is written up"`
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
	Upstream  string `json:"upstream,omitempty" doc:"What a fork was made from, where it is one"`
	FixState  string `json:"fix_state,omitempty" enum:"fixed,none,wont-fix,unknown,mixed"`
	FixedIn   string `json:"fixed_in,omitempty" doc:"The version that resolves it"`
	// Matched and MatchedFrom are how this place was reached and where that
	// match came from. The source is here rather than on the issue because one
	// issue reached through two ecosystems has two answers, and the issue can
	// hold only one — which is how a package from one distribution came to
	// link to another's tracker.
	Matched     string `json:"matched,omitempty" enum:"advisory,identifier"`
	MatchedFrom string `json:"matched_from,omitempty" doc:"Where this match came from"`
	// The evidence for the judgment `matched` asks for, rather than a second
	// way of making it. Recorded as the scanner wrote them and never parsed:
	// deciding whether a version falls inside a range needs an ordering per
	// ecosystem, which this does not have and does not attempt.
	MatchedIn    string `json:"matched_in,omitempty" doc:"Which body of vulnerability data answered, as the scanner names it — an ecosystem's own advisories against the national database's identifiers"`
	MatchedRange string `json:"matched_range,omitempty" doc:"The version range this match fired on. For a distribution's package reached by identifier it is an upstream range, which names no packaging revision and so cannot see a backported fix"`
	FixedAt      string `json:"fixed_at,omitempty" doc:"When that version became available"`
	// ArrivedFrom says somebody moved this version and the issue came with it.
	// A different sentence aimed at a different person: whoever did the bump,
	// rather than whoever triages.
	ArrivedFrom string `json:"arrived_from,omitempty" doc:"The version this was bumped from, where the bump did not resolve it"`

	// Tags are the words people put on this, as they were typed.
	Tags []string `json:"tags,omitempty" doc:"Words somebody put on this. Free text, no fixed vocabulary"`

	// Opened and FoundBy are when this first appeared here and what
	// produced it. The run that answered is not the run that answers now,
	// so this cannot be worked out again later — and without it, "which
	// scanner and which vulnerability database produced the finding you
	// dismissed on 3 March" has no answer at all.
	Opened string `json:"opened,omitempty" doc:"When the earliest of these places first appeared here, as a date"`
	// Due and NoDeadline are the same pair the list carries, and the screen
	// somebody actually decides on carried neither.
	Due      string `json:"due,omitempty" doc:"When it runs out, as a date. The earliest among its places, which is the one that makes the whole finding late"`
	DaysLeft *int   `json:"days_left,omitempty" doc:"Negative once it is overdue"`
	// The same two words the list body declares. This said
	// `past-end-of-life`, which nothing produces, and omitted
	// `out-of-support`, which the store emits on every finding whose release
	// is past end of life — so a consumer validating against the published
	// document rejected the body, and a TypeScript one could not narrow on
	// the value it actually receives. Two bodies for one value, disagreeing.
	NoDeadline string        `json:"no_deadline,omitempty" enum:"below-the-line,out-of-support" doc:"Why there is no deadline: below-the-line when this product does not consider it worth triaging, out-of-support when its release is past end of life. Those are the only two, and both are deliberate. Blank would read as missing data on the row somebody is deciding about"`
	FoundBy    *MeasuredBody `json:"found_by,omitempty" doc:"What produced this: the scanner, its version, and the vulnerability database it read at the time. Absent on something a person recorded, which no run found"`

	// Recorded says a person entered this rather than a scanner reporting it,
	// which is the one thing that decides whether it can be closed by hand.
	Recorded bool `json:"recorded,omitempty" doc:"Somebody recorded this here rather than a scanner reporting it. Only such a finding can be closed as fixed by hand"`

	// Undisclosed says this has not been announced and DiscloseAt when the
	// embargo ends. The screen's standing notice is what somebody has to
	// be unable to miss before they say anything about it.
	Undisclosed bool   `json:"undisclosed,omitempty" doc:"This has not been announced. Anything said about it outside this deployment discloses it"`
	DiscloseAt  string `json:"disclose_at,omitempty" doc:"When the embargo ends, as a date. Reaching it discloses nothing by itself"`

	// What upstream has released. Absent unless this deployment has turned
	// asking on, which is off by default because it is the only thing here
	// that reaches the network.
	LatestVersion    string `json:"latest_version,omitempty" doc:"The newest version the ecosystem's own index knows of"`
	LatestReleasedAt string `json:"latest_released_at,omitempty" doc:"When that version shipped"`
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
	AssignedTo string `json:"assigned_to,omitempty" doc:"Who is dealing with this, by sign-in identity. Empty means nobody, or not everywhere the same person"`
	// RoutedBy names the standing rule that placed this, where a rule did
	// rather than a person. A placement nobody can explain is one nobody
	// can correct.
	RoutedBy string `json:"routed_by,omitempty" doc:"The standing rule that placed this, where one did. Empty means a person did, or nobody has"`

	// What has been decided here, so the finding is the working screen
	// after a decision as well as before it: the live claims covering any
	// of its places, the decisions that stopped applying with their
	// reasoning offered back, and approved claims about other issues at
	// the same places that may reach this one.
	Standing []StandingClaimBody `json:"standing" doc:"Live claims covering any of this finding's places, newest first. A proposed one is waiting for a second person"`
	Previous []EarlierBody       `json:"previous" doc:"Decisions made at these places that lapsed or were withdrawn, newest first, with their reasoning"`
	Similar  []SimilarBody       `json:"similar" doc:"Approved not-applicable claims about other issues at the same component and consumer, which extends can carry to this one. At most five"`

	// Vex is the third layer beside the build's own claims and our
	// decisions : what a distribution or an upstream security team has
	// published about this component in a VEX document. Evidence and a
	// prefill; never applied to anything by itself, because a third
	// party's claim standing as ours would put somebody else's judgment
	// inside a number we quote.
	Vex []VexSaidBody `json:"vex" doc:"What VEX documents uploaded here say about this. Evidence, never applied"`
}

func registerFindingDetail(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
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
			"**A component name is not unique within a build.** Where one ships at several " +
			"versions, `version` says which — without it, a name that matches more than one is " +
			"refused rather than guessed at.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Stream        string `path:"stream"`
		Variant       string `path:"variant"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Component     string `path:"component" doc:"The component's name, as the findings list gives it"`
		Version       string `query:"version" doc:"Which version, where the build ships that name at more than one"`
		Ecosystem     string `query:"ecosystem" doc:"Which ecosystem, for the few names one build holds at one version as two components — a source repository and the package built from it"`
	}) (*struct{ Body EvidenceBody }, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		named, err := locatedVisibly(ctx, in, subject, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		target, err := targetRow(ctx, in, named.StreamID, named.VariantID)
		if err != nil {
			return nil, err
		}

		issue, err := issueHere(ctx, in, subject, named.ProductID, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		// Name and version together, because a name alone is not unique: a
		// real image ships three vendored versions of one library, and
		// resolving the name on its own answers about whichever was interned
		// first — for two of the three rows, an issue it does not carry.
		component, err := graph.NewStore(in.DB.DB).
			ComponentAs(ctx, target.ID, input.Component, input.Version, input.Ecosystem)
		if err != nil {
			// Narrowed to the versions this issue is open at before it is
			// offered. The lookup raises the ambiguity before it knows which
			// issue is being asked about, so left alone it offers every
			// version of the name — fifteen, of which three carry the issue,
			// which is a list where four in five choices lead to "no such
			// finding".
			if errors.Is(err, graph.ErrAmbiguous) {
				carrying, second := finding.NewStore(in.DB.DB).VersionsWithIssue(
					ctx, subject, target.ID, issue, input.Component)
				if second != nil {
					// Logged rather than discarded. Silently falling through
					// makes a database failure indistinguishable from "the
					// issue is at none of them", and the caller gets the wide
					// list with nothing saying why.
					in.logger().Error("which versions carry this issue could not be read",
						"component", input.Component, "error", second)
				}
				switch {
				case len(carrying) == 1:
					// One choice is not a choice. Refusing here would hand
					// back the single URL we just worked out and make the
					// caller ask again for it.
					component, err = graph.NewStore(in.DB.DB).ComponentAs(ctx, target.ID,
						input.Component, carrying[0].Version, carrying[0].Ecosystem)
					if err != nil {
						return nil, ambiguousOrMissing(err)
					}
				case len(carrying) > 1:
					return nil, ambiguousAmong(input.Component, carrying)
				default:
					return nil, ambiguousOrMissing(err)
				}
			} else {
				return nil, ambiguousOrMissing(err)
			}
		}

		evidence, err := finding.NewStore(in.DB.DB).Detail(ctx, subject, target.ID, issue, component)
		if err != nil {
			return nil, noSuchFinding()
		}
		body := evidenceBody(*evidence)

		// The build's own places, with the versions it ships at each: what
		// stands is matched by key, and a key carries versions a place name
		// alone does not.
		keyed, err := finding.NewStore(in.DB.DB).PlacesFor(ctx, subject, target.ID, issue, component)
		if err != nil {
			return nil, wentWrong(in.Logger, "where this sits could not be read", err)
		}
		body.Standing, body.Previous, body.Similar, err = decidedAbout(ctx, in, subject,
			named.ProductID, issue, keyed)
		if err != nil {
			return nil, wentWrong(in.Logger, "what was decided here could not be read", err)
		}

		// What VEX documents say, matched on every name the issue is
		// known by: which identifier a publisher chose is a preference of
		// whichever database they consulted rather than a property of the
		// issue.
		said, err := finding.NewStore(in.DB.DB).SaidAbout(ctx, subject, named.ProductID,
			issue, append([]string{body.Vulnerability}, body.Aliases...),
			body.Component, evidence.Purl)
		if err != nil {
			return nil, wentWrong(in.Logger, "what VEX documents say could not be read", err)
		}
		for _, one := range said {
			offers, _ := one.Prefills()
			body.Vex = append(body.Vex, VexSaidBody{
				ID: one.ID, Publisher: one.Publisher, Status: one.Status,
				Justification: one.Justification, Statement: one.Statement,
				Document: one.Document, At: one.UploadedAt.Format(time.DateOnly),
				Offers: offers,
			})
		}
		return &struct{ Body EvidenceBody }{Body: body}, nil
	})
}

func evidenceBody(e finding.Evidence) EvidenceBody {
	body := EvidenceBody{
		Vulnerability: e.Vulnerability, Aliases: e.Aliases, Severity: e.Severity,
		Assessed: e.Assessed,
		Score:    float64(e.ScoreCenti) / 100, Vector: e.Vector,
		Exploited: e.Exploited, Likelihood: float64(e.LikelihoodPPM) / 1_000_000,
		Weaknesses: e.Weaknesses, Description: e.Description, Advisory: e.Advisory,
		Component: e.Component, Version: e.Version, Upstream: e.Upstream,
		FixState: string(e.FixState), FixedIn: e.FixedIn, ArrivedFrom: e.ArrivedFrom,
		Matched: string(e.Matched), MatchedFrom: e.MatchedFrom,
		MatchedIn: e.MatchedIn, MatchedRange: e.MatchedRange, Recorded: e.Recorded,
		LatestVersion: e.LatestVersion, NothingSince: e.NothingSince,
		AssignedTo: e.AssignedTo, Undisclosed: e.Undisclosed, RoutedBy: e.RoutedBy,
		Tags:     e.Tags,
		Places:   make([]SittingBody, 0, len(e.Places)),
		Standing: []StandingClaimBody{}, Previous: []EarlierBody{}, Similar: []SimilarBody{},
		Vex: []VexSaidBody{},
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
		body.FoundBy = &MeasuredBody{
			Scanner: e.FoundBy.Scanner, ScannerVersion: e.FoundBy.ScannerVersion,
			DatabaseVersion: e.FoundBy.DatabaseVersion, RanHere: e.FoundBy.RanHere,
		}
		if e.FoundBy.RanAt != nil {
			body.FoundBy.RanAt = stamp(*e.FoundBy.RanAt)
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
			})
		}
		body.Places = append(body.Places, sitting)
	}
	return body
}
