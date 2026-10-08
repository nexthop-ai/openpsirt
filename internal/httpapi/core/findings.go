// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// sortOrder is the query parameter for which order to page in, and it takes
// the orders it offers from the store rather than naming them again.
//
// A literal in a struct tag beside `finding.SortKeys` — which declares itself
// the one list "so the two cannot disagree" — is a second copy kept in step by
// a test rather than by construction, and the check is the thing that goes
// missing. The framework asks a type for its own schema, so the enum is built
// from the same slice the store looks the ordering up in.
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

// UpgradeBody is a version a component could move to, and what that would fix.
type UpgradeBody struct {
	To string `json:"to" doc:"The version, as whoever packages the component wrote it"`
	// Two counts, because they answer different questions and confusing them
	// reads backwards: a quiet release late on a maintained line fixes two of
	// its own while carrying every fix before it.
	FixedHere int  `json:"fixed_here" doc:"The number of open findings naming this exact version as their fix — that release's own security content"`
	Reached   int  `json:"reached" doc:"The number moving here would close altogether, counting everything fixed at or before it. Equal to fixed_here where the versions could not be ordered"`
	Ordered   bool `json:"ordered" doc:"Whether these versions could be ordered at all. False means the list is not ranked and reached says no more than fixed_here"`
}

// planned is the effect a promised upgrade has on the list. "either" is a word
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

// Filter turns the request's parameters into the store's narrowing.
//
// One mapping for both lists, for the same reason the parameters are one
// struct: two of these drift, and the drift is a filter that answers on one
// list and is quietly ignored on the other.
func (n Narrowing) Filter(floor finding.Floor) (finding.Filter, error) {
	narrowed := finding.Filter{
		MinSeverity:   string(n.Severity),
		Exploited:     n.Exploited,
		HasFix:        n.Fixable,
		Components:    n.Component,
		Tags:          n.Tag,
		Search:        n.Search,
		Ecosystems:    n.Ecosystem,
		Under:         n.Under,
		UnderTheBuild: n.UnderBuild,
		DeclaredAs:    n.DeclaredAs,
		States:        as[finding.ClaimStanding](n.State),
		Outcomes:      plainly(n.Outcome),
		Assigned:      n.Assigned,
		Reassessed:    n.Reassessed,
		Origin:        finding.Origin(n.Origin),
		Planned:       planned(n.Planned),
		Unconfirmed:   n.Unconfirmed,
		Exclude:       n.Exclude,
		Floor:         floor,
		BelowFloor:    n.BelowFloor,
		Workable:      finding.Working(plainly(n.On), n.Support),
		// Straight through: what reaches the statement is the
		// allowlist's own expression, chosen by this key, never the
		// key itself. A word that is not one of them is not a sort
		// and the list comes back in its own order.
		SortBy:    finding.SortKey(n.Sort),
		Ascending: n.Ascending,

		LikelihoodAtLeast: int(math.Round(n.Likelihood * 1_000_000)),
		OpenedBefore:      daysBack(n.OpenFor),
		DueBefore:         daysAhead(n.DueWithin, n.Overdue),
		Overdue:           n.Overdue,
		FixStates:         fixStates(n.FixState),
		Weaknesses:        n.Weakness,
		SentBack:          n.SentBack,
		Claim:             n.Claim,
		ClaimStates:       plainly(n.ClaimState),
		Publishers:        n.Publisher,
		VexStatus:         plainly(n.Said),
		BuildSays:         plainly(n.BuildSays),
		OpenedByRun:       n.OpenedByRun,
	}
	var openedBefore *time.Time
	for _, each := range []struct {
		text string
		at   **time.Time
	}{
		{n.OpenedAfter, &narrowed.OpenedAfter},
		{n.OpenedBefore, &openedBefore},
		{n.ClosedAfter, &narrowed.ClosedAfter},
		{n.DecidedAfter, &narrowed.ProposedAfter},
	} {
		when, err := finding.Since(each.text)
		if err != nil {
			// No store was reached, so no engine is involved: this is a date
			// nothing can read, which is the caller's.
			return narrowed, huma.Error422UnprocessableEntity(err.Error())
		}
		*each.at = when
	}
	// An age and a date bound the same moment from the same side, so both
	// asked keep the tighter of the two.
	narrowed.OpenedAfter = later(narrowed.OpenedAfter, daysBack(n.OpenUnder))
	narrowed.OpenedBefore = earlier(narrowed.OpenedBefore, openedBefore)
	return narrowed, nil
}

// later is the later of two moments, either of which may be absent.
func later(a, b *time.Time) *time.Time {
	if a == nil || (b != nil && b.After(*a)) {
		return b
	}
	return a
}

// earlier is the earlier of two moments, either of which may be absent.
func earlier(a, b *time.Time) *time.Time {
	if a == nil || (b != nil && b.Before(*a)) {
		return b
	}
	return a
}

// Narrowing is the filters both findings lists take: the per-product one and
// the one that spans products.
//
// Named once and embedded in both, because two lists narrowing by slightly
// different sets of words are two answers to the same question side by side,
// and the drift arrives one forgotten parameter at a time. Absent here is
// everything belonging to one build: a subtree is a walk over one build's
// edges, and "differs between builds" is a statement about a selection.
//
// Every array here carries a bound and every free-text field a length. Each
// element becomes a member of an IN clause on the findings, the counts and
// every export. A free-text array is bounded by a number of items; an array
// of words from a fixed set is bounded by that set, which holds only where a
// word may appear once.
type Narrowing struct {
	Severity   Rating   `query:"severity" doc:"Keep only issues rated this badly or worse. 'low' excludes nothing, including issues carrying no rating"`
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
	On           []LineKind    `query:"on,explode" uniqueItems:"true" doc:"Keep only what sits in releases of these kinds. Defaults to branches: no work lands in a tag, whatever anybody decides about it. Ask for both to see everything"`
	Support      []string      `query:"support,explode" enum:"in-support,past-eol" uniqueItems:"true" doc:"Keep only what sits in releases in this state of support, its own end-of-life date or the product's. Defaults to what is still in support. Ask for both to see everything"`
	Under        string        `query:"under" maxLength:"191" doc:"Keep only what sits inside the container of this name"`
	DeclaredAs   []string      `query:"declared_as,explode" enum:"required,optional,excluded,build,design,development,other,runtime" uniqueItems:"true" doc:"Keep only components a producer scoped one of these ways in this build, in the producer's own word: a CycloneDX component scope, or an SPDX lifecycle scope. Any of them, not all. Asked of the component's incoming edges, so one reached from two consumers scoped differently answers to both words. Nothing here ranks by it or decides anything from it — reading 'build' as 'does not ship' is wrong for every compiled language"`
	UnderBuild   bool          `query:"under_build" doc:"Keep only what the build holds directly, which is what has no container above it"`
	State        []Standing    `query:"state,explode" uniqueItems:"true" doc:"Keep only groups this far decided. A group covers every place an issue sits at in one component, so this is a statement about all of them: undecided means nothing stands, waits or has lapsed at any place, agreed means every place is answered"`
	Outcome      []Outcome     `query:"outcome,explode" uniqueItems:"true" doc:"Keep only groups a standing judgment of this kind covers — how to ask what has been dismissed, which state cannot answer: agreed says a judgment stands, not which one. Every place must be answered the same way, and only the claim standing now counts"`
	Assigned     []string      `query:"assigned,explode" enum:"me,somebody,nobody" uniqueItems:"true" doc:"Keep only groups by who is dealing with them. 'me' means mine or a team I am on. A group whose places are held by different parties is none of these. Several answers hold together: mine and whatever nobody has picked up is one question"`
	Likelihood   float64       `query:"epss_at_least" minimum:"0" maximum:"1" doc:"Keep only issues the published estimate rates at least this likely to be exploited, 0 to 1"`
	OpenFor      int           `query:"open_for" minimum:"1" doc:"Keep only what has been open here for at least this many days. The finding's own age, not the year in its identifier"`
	OpenUnder    int           `query:"open_under" minimum:"1" doc:"Keep only what has been open here for fewer than this many days. With open_for, the stretch between the two"`
	DueWithin    int           `query:"due_within" minimum:"1" doc:"Keep only what runs out within this many days. What is already past its deadline is asked for with overdue instead"`
	Overdue      bool          `query:"overdue" doc:"Keep only what is already past its deadline"`
	FixState     []string      `query:"fix_state,explode" enum:"fixed,none,wont-fix,unknown,mixed" uniqueItems:"true" doc:"Keep only what upstream has done one of these about. 'none' and 'wont-fix' are the rows that need a judgment rather than an upgrade, and the fixable flag cannot ask for either. 'unknown' is the scanner declining to say, which is not the same as upstream having released nothing. 'mixed' is a group whose places disagree — fixed in one build and not another — which has no single answer and is the population a half-landed upgrade shows up in"`
	Weakness     []string      `query:"weakness,explode" maxItems:"200" maxLength:"32" doc:"Keep only issues of these kinds of flaw, by CWE identifier — CWE-79. Any of them, not all: a class of flaw is usually several identifiers"`
	SentBack     bool          `query:"sent_back" doc:"Keep only groups where a claim is with its author, sent back for more"`
	Claim        int64         `query:"claim" minimum:"1" doc:"Keep only what sits at a place this claim wrote a decision for, by the claim's identifier"`
	ClaimState   []ClaimState  `query:"claim_state,explode" uniqueItems:"true" doc:"With claim, keep only the places where its decision is in one of these states. Any of them. Ignored without claim"`
	Publisher    []string      `query:"vex_publisher,explode" maxItems:"200" maxLength:"191" doc:"Keep only what one of these VEX publishers has a standing statement about"`
	OpenedAfter  string        `query:"opened_after" doc:"Keep only what was first seen here on or after this date, as 2026-03-31"`
	OpenedBefore string        `query:"opened_before" doc:"Keep only what was first seen here before this date, as 2026-03-31. The date itself is not included"`
	OpenedByRun  int64         `query:"opened_by_run" minimum:"1" doc:"Keep only what one scan run opened, by its identifier. What a run reports having opened, as the list of it"`
	ClosedAfter  string        `query:"closed_after" doc:"Accepted and matches nothing: this list holds open rows only"`
	DecidedAfter string        `query:"proposed_after" doc:"Keep only what somebody claimed something about after this date"`
	Said         []vexStatus   `query:"vex_status,explode" uniqueItems:"true" doc:"Keep only what a VEX statement says one of these about, in the format's own vocabulary. With a publisher, both must hold"`
	BuildSays    []buildSaying `query:"build_says,explode" uniqueItems:"true" doc:"Keep only what the build's own claims say one of these about, in the VEX vocabulary. 'affected' finds the places the build says the flaw applies at, with its workaround"`
	Reassessed   bool          `query:"reassessed" doc:"Keep only groups whose issue we rated differently from the world — what has been re-prioritized here"`
	Origin       origin        `query:"origin" doc:"Keep only what a person recorded here, or only what a scanner reported. Left out, both. The ones a person recorded are the only ones a person may close by hand"`
	Planned      string        `query:"planned" enum:"planned,unplanned,either" doc:"Keep only what a promised upgrade covers, or only what none covers. Derived from the decisions rather than stored, so withdrawing a promise puts what it covered back with nothing to clean up. 'unplanned' is the working list once planned work is out of view, and is what the by-issue list asks unless told otherwise; 'either' is how a reader asks for it back, and is what leaving this out means"`
	Unconfirmed  bool          `query:"unconfirmed" doc:"Keep only groups a scanner reached by comparing a published identifier against an upstream version range, never against an advisory for the package in its own ecosystem. A distribution backports fixes without moving the upstream version, so these are neither confirmed nor refuted — somebody has to look, and finding them one at a time is not a thing anybody does"`
	Exclude      []string      `query:"exclude,explode" maxItems:"200" maxLength:"191" doc:"Drop components of these names. One package can drown the list: on a switch image the kernel carried 4,943 of 6,822 rows"`
	Sort         sortOrder     `query:"sort" doc:"The order to page in. Urgency by default, which is what the list is designed around: what somebody with an hour should look at first. A finding with no deadline sorts last whichever direction is asked for"`
	Ascending    bool          `query:"asc" doc:"Order the other way — oldest, nearest deadline, fewest places, lowest first"`
}

// Paging is how much of a list to return, kept apart from the filters so that
// something answering the whole of a narrowing — an export — can take every
// filter without also offering a page size it does not honor. A parameter that
// changes nothing is worse than one that is missing.
type Paging struct {
	Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number returned"`
	Offset int `query:"offset" minimum:"0" doc:"The number skipped"`
}

// AtOneBuild narrows a list within a single product's builds, and has no
// meaning across products: a subtree is a walk over one build's edges, and
// "differs between builds" and the spread across variants are statements
// about a selection.
type AtOneBuild struct {
	Beneath          string `query:"beneath" doc:"Keep only what sits at this component or anywhere under it — what the dependency tree's cumulative count counts. The name must be in the build; a name that is not is refused, and one the build holds as more than one component is refused with 409 naming the choices"`
	BeneathVersion   string `query:"beneath_version" doc:"The version, where the build holds that name at several"`
	BeneathEcosystem string `query:"beneath_ecosystem" doc:"The ecosystem, for the few names a build holds at one version as two components"`
	BeneathNamespace string `query:"beneath_namespace" doc:"The namespace, for the few names a build holds at one version in one ecosystem as two components"`
	Differs          bool   `query:"differs" doc:"Keep only groups open in some builds of this selection and not others. Meaningless where the selection is one build, and ignored there"`
	AcrossVariants   string `query:"across_variants" enum:"only,every" doc:"Keep only what is spread over the variants of its own branch one of these ways. 'only' keeps what no other variant of that branch holds open, and is refused unless a variant is named. 'every' keeps what every build of that branch holds open. The same issue at another version is a different row and counts as not held"`
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
func beneathIn(ctx context.Context, in Deps, scope finding.Scope, name string,
	which graph.Choice) (*int64, error) {
	if name == "" {
		return nil, nil
	}
	targets, err := finding.NewStore(in.DB.DB).Builds(ctx, scope)
	if err != nil {
		return nil, WentWrong(in.Logger, "cannot tell which builds are in scope", err)
	}
	if len(targets) != 1 {
		return nil, huma.Error422UnprocessableEntity(
			"a subtree is a walk over one build's edges, so narrowing beneath a component" +
				" needs a branch and a variant that name exactly one build")
	}
	componentID, err := graph.NewStore(in.DB.DB).ComponentAs(ctx, targets[0], name, which)
	if err != nil {
		var several *graph.Ambiguous
		if errors.As(err, &several) {
			return nil, SeveralComponents(several,
				"&beneath_version= and, where two share a version, &beneath_ecosystem= and &beneath_namespace=")
		}
		return nil, huma.Error422UnprocessableEntity("this build does not hold a component called " + name)
	}
	return &componentID, nil
}

// RefusedFinding turns a store's refusal about a finding into an answer.
//
// Somebody who may not reach a finding is told it is not there, the same
// answer a name nobody ever used gets — otherwise the two differ and guessing
// becomes informative.
//
// Only the refusals it recognizes are reported to the caller. Anything else is
// a database that could not answer, and returning those as 422 tells somebody
// their request was wrong and puts a driver's error text — table names,
// statement fragments — in the response body. Anything other than a recognized
// refusal is logged and answered as ours.
func RefusedFinding(in Deps, err error) error {
	switch {
	case errors.Is(err, access.ErrDenied):
		return NoSuchFinding()
	case errors.Is(err, finding.ErrSamePerson):
		return Asked(in.Logger, err)
	case errors.Is(err, finding.ErrRecipientMayNotRead):
		return huma.Error422UnprocessableEntity(finding.ErrRecipientMayNotRead.Error())
	}
	return WentWrong(in.Logger, "that could not be recorded", err)
}
