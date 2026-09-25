// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// SettingBody is one thing a deployment has decided for everybody in it.
type SettingBody struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Default bool   `json:"default,omitempty" doc:"Nobody has set this; the shipped value is in use"`
	Title   string `json:"title" doc:"The setting's name as a screen shows it"`
	Section string `json:"section" enum:"deadlines,own,triage,disclosure,scanning,signin,limits,outbound" doc:"Which part of the settings it belongs to"`
	Summary string `json:"summary" doc:"What it decides, in one line"`
	Detail  string `json:"detail,omitempty" doc:"What a reader may want beyond the summary"`
	// Kind is the type of the value, so a client offers the control the value
	// takes rather than a text field somebody types a refused value into.
	//
	// Served rather than kept client-side: three tables in the interface keyed
	// on setting names, beside the server's own, are five copies of one fact,
	// and a setting added to any of them is a control that offers the wrong
	// thing or none.
	Kind string `json:"kind" enum:"duration,count,size,percent,word,switch" doc:"The kind of value: a length of time, a count of things, a count of bytes, a percentage, one of a few words, or on and off"`
	// Words is the values a word setting may take, in the order to offer them.
	// Empty for every other kind.
	Words []string `json:"words,omitempty" doc:"For a word setting, the values it takes, in the order to offer them"`
}

// settingKind is the type of a setting's value.
//
// Named because the four are checked differently, and a value checked as the
// wrong kind is stored and then silently ignored. Carried on the row rather
// than answered by four functions that each know about some of the names: a
// name missing from all four falls through to "a length of time", and a name
// missing from the shipped switch falls through to the empty string.
type settingKind string

const (
	aDuration settingKind = "duration"
	aCount    settingKind = "count"
	// aSize is a count of bytes. Checked exactly as a count is — the write
	// path cannot tell them apart and does not need to — and named separately
	// because a screen must: 26214400 is twenty-five megabytes and nobody
	// reads it as that, so the mistake available in a raw byte field is a
	// factor of a thousand.
	aSize settingKind = "size"
	// aPercent is a share of something the deployment holds rather than a
	// count of things. Checked as one to a hundred: a share above the whole
	// is a threshold nothing can reach, which is a setting somebody changed
	// and got nothing from.
	aPercent settingKind = "percent"
	aWord    settingKind = "word"
	aSwitch  settingKind = "switch"
)

// windows is the shipped deadline policy, read from the package that applies
// it rather than respelled here as string literals: a shipped number written
// twice is one that disagrees with itself the first time anybody moves it.
var windows = finding.DefaultWindows()

// ownWindows is the same for a flaw recorded in our own product.
var ownWindows = finding.DefaultOwnWindows()

// sessionLifetime is the one shipped value that is not a constant.
//
// A sign-in's length falls back to the environment before the built-in, so
// reporting the built-in says twelve hours on a deployment that has set
// something else — the screen contradicting the deployment about its own
// configuration.
func sessionLifetime(in Ingest) string {
	if in.SessionLifetime > 0 {
		return in.SessionLifetime.String()
	}
	return access.DefaultSessionLifetime.String()
}

// settable is every setting an operator may change, with what it decides,
// what kind of value it takes and what is in force where nobody has set one.
//
// A list rather than anything the store will accept, so that adding a setting
// is a deliberate act and a typo in a name is refused instead of quietly
// creating a setting nothing reads. One row per setting, because five tables
// keyed on the same name hold three of the names between them: the three
// disclosure settings report as blank on the screen while 90d, 30d and 14d are
// what the deployment enforces.
var settable = []struct {
	name string
	// title is the setting's name as a screen shows it: a noun phrase, the way
	// a settings screen anywhere else names one.
	title string
	// section is which part of the settings a screen files this under.
	// Served with the rest of the row, so a setting added here lands in a
	// section rather than in a list somebody forgot to extend.
	section string
	// summary is what the setting decides, in one line, and detail is what a
	// reader may want beyond it. Empty where the summary is the whole of it.
	summary string
	detail  string
	// kind is the type of this setting's value, which decides how it is
	// checked at the write and how the screen offers it.
	kind settingKind
	// words is the values this setting may take, in the order to offer them,
	// and the list the write path checks against. Nil for every kind but a
	// word or a switch.
	//
	// On the row rather than in a second table keyed on the name: keyed that
	// way, the next word setting anybody adds is offered nothing and then
	// checked against the triage floor's list.
	words []string
	// shipped is the value in force where nobody has set one, read from the
	// package that reads it rather than respelled here: a shipped number
	// written twice is one that disagrees with itself the first time anybody
	// moves it.
	//
	// A function rather than a constant for the one setting whose shipped
	// value is not one: a sign-in's length falls back to the environment
	// before the built-in, which is why this takes the Ingest.
	shipped func(Ingest) string
	// movesDeadlines says changing this invalidates every stored deadline,
	// so they are rewritten away from the request.
	movesDeadlines bool
}{
	{setting.DueExploited, "Known exploited", "deadlines",
		"How long a known-exploited finding may stay open",
		"Its own window, and the shortest. Severity is how bad a flaw is; being exploited is a fact about the world.",
		aDuration, nil, func(Ingest) string { return windows.Exploited.String() }, true},
	{setting.DueCritical, "Critical", "deadlines",
		"How long a critical finding may stay open",
		"",
		aDuration, nil, func(Ingest) string { return windows.Critical.String() }, true},
	{setting.DueHigh, "High", "deadlines",
		"How long a high finding may stay open",
		"",
		aDuration, nil, func(Ingest) string { return windows.High.String() }, true},
	{setting.DueMedium, "Medium", "deadlines",
		"How long a medium finding may stay open",
		"",
		aDuration, nil, func(Ingest) string { return windows.Medium.String() }, true},
	{setting.DueLow, "Low", "deadlines",
		"How long a low finding may stay open",
		"",
		aDuration, nil, func(Ingest) string { return windows.Low.String() }, true},
	{setting.OwnDueExploited, "Known exploited", "own",
		"How long a known-exploited flaw in our own product may stay open",
		"Counted from when the flaw was first rated.",
		aDuration, nil, func(Ingest) string { return ownWindows.Exploited.String() }, true},
	{setting.OwnDueCritical, "Critical", "own",
		"How long a critical flaw in our own product may stay open",
		"Counted from when the flaw was first rated.",
		aDuration, nil, func(Ingest) string { return ownWindows.Critical.String() }, true},
	{setting.OwnDueHigh, "High", "own",
		"How long a high flaw in our own product may stay open",
		"Counted from when the flaw was first rated.",
		aDuration, nil, func(Ingest) string { return ownWindows.High.String() }, true},
	{setting.OwnDueMedium, "Medium", "own",
		"How long a medium flaw in our own product may stay open",
		"Counted from when the flaw was first rated.",
		aDuration, nil, func(Ingest) string { return ownWindows.Medium.String() }, true},
	{setting.OwnDueLow, "Low", "own",
		"How long a low flaw in our own product may stay open",
		"Counted from when the flaw was first rated.",
		aDuration, nil, func(Ingest) string { return ownWindows.Low.String() }, true},
	{setting.DeferralThreshold, "Second approver above", "triage",
		"How long something may be put off before a second person must agree",
		"Measured against everything the finding has already been put off for, not against the postponement being asked for.",
		aDuration, nil, func(Ingest) string { return triage.DefaultDeferralThreshold.String() }, false},
	{setting.SessionLifetime, "Session lifetime", "signin",
		"How long a sign-in lasts",
		"",
		aDuration, nil, sessionLifetime, false},
	{setting.MaxTokenLifetime, "Personal token lifetime", "signin",
		"The longest a personal token may be valid for",
		"",
		aDuration, nil, func(Ingest) string { return access.MaxTokenLifetime.String() }, false},
	{setting.ClaimWindow, "Authorization redemption window", "signin",
		"How long an authorization for somebody who has never signed in stays redeemable",
		"It is the one window where a name, not an identifier, decides who gets a set of roles, so it ends.",
		aDuration, nil, func(Ingest) string { return access.DefaultClaimWindow.String() }, false},
	{setting.TogetherCap, "Bulk claim limit", "triage",
		"How many findings one action may claim about, or reports one ruling may cover",
		"",
		aCount, nil, func(Ingest) string { return strconv.Itoa(triage.DefaultTogetherCap) }, false},
	{setting.TriageFloor, "Minimum severity", "triage",
		"The severity below which findings stay out of the working list",
		"Below it, findings are still recorded and counted. A product may state its own.",
		aWord, theFloor, func(Ingest) string { return theFloor[0] }, true},
	{setting.QuietAfter, "Quiet build threshold", "scanning",
		"How long a build may go without a scan before it is reported as quiet",
		"Measured from the last arrival, or from when the build was declared if nothing has arrived.",
		aDuration, nil, func(Ingest) string { return setting.DefaultQuietAfter.String() }, false},
	{setting.VulnerabilityDataStaleAfter, "Stale vulnerability data", "scanning",
		"How long the vulnerability data may go unchanged before you are told",
		"A scan against data that has not moved answers the same way it did last month, with nothing saying so.",
		aDuration, nil, func(Ingest) string { return setting.DefaultVulnerabilityDataStaleAfter.String() }, false},
	{setting.DeltaShare, "Inventory change share", "scanning",
		"The share of a build's inventory one upload may move before readers are told",
		"Both this and the inventory change floor have to be passed, so three names moving in a small inventory is not reported every time.",
		aPercent, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultDeltaShare) }, false},
	{setting.PairShare, "Approval pair share", "triage",
		"The share of a product's agreements one pair may reach before administrators are told",
		"Only asked where the product has at least as many approvers as the setting below, and over at least ten claims agreed in ninety days. A product may state its own.",
		aPercent, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultPairShare) }, false},
	{setting.PairApprovers, "Approvers for pair alerts", "triage",
		"The fewest approvers a product needs before pair shares are checked",
		"Below it, one pair doing everything is what a small team looks like. A product may state its own.",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultPairApprovers) }, false},
	{setting.DeltaFloor, "Inventory change floor", "scanning",
		"The fewest component names an upload must move to be reported",
		"",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultDeltaFloor) }, false},
	{setting.ScanEvery, "Rescan interval", "scanning",
		"How often everything tracked is scanned against the day's vulnerability data",
		"A release that is never rebuilt gets a different answer every month, so this is what finds an advisory published after it shipped. It is also how often each supplier is read again, so shortening it sends more requests to third parties.",
		aDuration, nil, func(Ingest) string { return setting.DefaultScanEvery.String() }, false},
	{setting.SupplierSilentAfter, "Silent supplier threshold", "scanning",
		"How long a supplier may go unread before administrators are told",
		"Never shorter in effect than two scan intervals, since a supplier is read once each.",
		aDuration, nil, func(Ingest) string { return setting.DefaultSupplierSilentAfter.String() }, false},
	{setting.SupplierHistory, "Supplier history", "scanning",
		"How many days back a newly configured supplier is read from",
		"A distribution lists every advisory it has ever issued, so this bounds how much is asked for. A year of the largest takes a couple of weeks to read.",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultSupplierHistory) }, false},
	{setting.UpstreamCurrency, "Upstream version checks", "outbound",
		"Ask public package indexes for each component's newest version",
		"One request per component, carrying its name and nothing else. Names this deployment calls its own are held back. Without it, what a scan reports is unaffected.",
		aSwitch, theSwitch, func(Ingest) string { return setting.Off }, false},
	{setting.AttachmentMaxSize, "Maximum attachment size", "limits",
		"The largest single file this deployment accepts",
		"",
		aSize, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultAttachmentMaxSize) }, false},
	{setting.AttachmentQuota, "Total attachment storage", "limits",
		"How much this deployment holds in attachments in total",
		"",
		aSize, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultAttachmentQuota) }, false},
	{setting.QueueBacklog, "Queued work limit", "limits",
		"How much background work of one kind may wait before more is refused",
		"Counted per kind, so a producer that has filled its own queue does not refuse everybody else's work.",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultQueueBacklog) }, false},
	{setting.RoutingBatch, "Findings placed per pass", "limits",
		"How many findings one pass of the routing sweep places, at most",
		"On a large estate a pass can be too big to hold a connection through, or too small to drain the backlog.",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultRoutingBatch) }, false},
	{setting.SavedPerPerson, "Saved filters per person", "limits",
		"How many saved filters one person may keep for one product",
		"The panel that lists them reads every one on every open.",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultSavedPerPerson) }, false},
	{setting.AttachmentShare, "Attachment storage per person", "limits",
		"How much of the attachment total any one person may hold",
		"Without it, one person can fill the store and block everybody else's next upload.",
		aSize, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultAttachmentShare) }, false},
	{setting.AbsentAfter, "Inactive account threshold", "signin",
		"How long somebody may go without signing in before their held work is raised",
		"It only asks: long leave and having left look the same from here.",
		aDuration, nil, func(Ingest) string { return setting.DefaultAbsentAfter.String() }, false},
	{setting.WaitingAfter, "Awaiting approval", "triage",
		"How long a claim may wait on a second person before approvers are told",
		"",
		aDuration, nil, func(Ingest) string { return setting.DefaultWaitingAfter.String() }, false},
	{setting.SentBackAfter, "Returned, untouched", "triage",
		"How long a returned claim may sit before its proposer is told again",
		"Shorter than awaiting approval: the question was asked of the person already holding it.",
		aDuration, nil, func(Ingest) string { return setting.DefaultSentBackAfter.String() }, false},
	{setting.DeferralLead, "Deferral expiry warning", "triage",
		"How long before a deferral ends its proposer is told",
		"The end date itself puts the finding back in the queue, which is the last moment to act, not the first.",
		aDuration, nil, func(Ingest) string { return setting.DefaultDeferralLead.String() }, false},
	{setting.QueuedAfter, "Unclaimed in a team queue", "triage",
		"How long work may sit in a team's queue with nobody taking it",
		"",
		aDuration, nil, func(Ingest) string { return setting.DefaultQueuedAfter.String() }, false},
	{setting.DiscloseAfter, "Default embargo period", "disclosure",
		"How long an undisclosed finding stays that way before its date",
		"What the deployment's coordinated-disclosure policy says. An embargo somebody outside can hold us to is one they were told the length of.",
		aDuration, nil, func(Ingest) string { return setting.DefaultDiscloseAfter.String() }, false},
	{setting.MovementThreshold, "Embargo movement threshold", "disclosure",
		"How far an embargo's end may move in total before a second person must agree",
		"Measured against every move already made, and a date brought forward counts the same as one pushed back.",
		aDuration, nil, func(Ingest) string { return setting.DefaultMovementThreshold.String() }, false},
	{setting.DisclosureLead, "Embargo expiry warning", "disclosure",
		"How long before an embargo's date the people who could move it are told",
		"An extension nobody can agree to in time is an approval in name only.",
		aDuration, nil, func(Ingest) string { return setting.DefaultDisclosureLead.String() }, false},
}

// theSwitch is the two values an on-or-off setting may take.
var theSwitch = []string{setting.On, setting.Off}

// theFloor is the words the triage line may be set to, from the package that
// owns the ordering they are drawn from.
//
// "everything" is not a severity: it is the line that keeps nothing out, and a
// word an operator sets rather than a rating anything is compared against.
var theFloor = finding.TriageFloors()

func registerSettings(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-settings", Method: http.MethodGet, Path: "/v1/settings",
		Summary: "List this deployment's settings",
		Description: "Returns every setting an operator may change, its value, and what it " +
			"decides. `default` means nobody has set it and the shipped value is in use.\n\n" +
			"The shipped numbers are a starting point rather than a recommendation. What a " +
			"deployment can hold to is a question about that deployment, and a deadline nobody " +
			"agreed to produces an estate that is permanently late and a signal everybody " +
			"ignores.",
		Tags: []string{"Administration"},
	}, deploymentRecords, ""), func(ctx context.Context, _ *struct{}) (*listOutput[SettingBody], error) {
		if err := readingTheDeployment(ctx); err != nil {
			return nil, err
		}
		// From the accessor, which answers nothing where there is no
		// database. Built from `in.DB.DB` directly it panics into the recovery
		// middleware and answers 500, where the route already has words for a
		// process that has no database.
		settings := in.settings(in.handle())
		if settings == nil {
			return nil, noDatabase(in.logger())
		}
		out := &listOutput[SettingBody]{}
		out.Body.Items = make([]SettingBody, 0, len(settable))
		for _, each := range settable {
			value, set, err := settings.Get(ctx, each.name)
			if err != nil {
				return nil, wentWrong(in.Logger, "the settings could not be read", err)
			}
			if !set {
				value = each.shipped(in)
			}
			out.Body.Items = append(out.Body.Items, SettingBody{
				Name: each.name, Value: value, Default: !set, Title: each.title, Section: each.section,
				Summary: each.summary, Detail: each.detail,
				Kind: string(each.kind), Words: each.words,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-setting", Method: http.MethodPut, Path: "/v1/settings/{name}",
		Summary: "Change one setting",
		Description: "Sets one value for everybody here. Durations are written the way Go writes " +
			"them — `72h`, `30m` — and a value that cannot be read is refused rather than " +
			"stored, since a setting nothing can parse is a policy silently reverting to the " +
			"shipped one.\n\n" +
			"Only the settings this deployment recognizes may be set. A name it does not know is " +
			"refused, because storing it would create something nothing ever reads.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Name string `path:"name"`
		Body struct {
			Value string `json:"value" minLength:"1"`
		}
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		row, known := settingRow(input.Name)
		if !known {
			return nil, huma.Error404NotFound("this deployment has no setting by that name")
		}
		// Checked before it is stored. A value nothing can read would leave
		// every caller falling back to the shipped one, which is a policy that
		// quietly stopped applying — and every reader here treats zero and
		// negative as unset, so those would do the same while looking set.
		switch settable[row].kind {
		case aSwitch, aWord:
			// Against the row's own list, which is the one the response
			// offers. Two tables keyed on the name is how an offered word and
			// an accepted word come to differ.
			if !slices.Contains(settable[row].words, input.Body.Value) {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not one this setting takes — write one of %s",
						input.Body.Value, strings.Join(settable[row].words, ", ")))
			}
		case aCount, aSize:
			n, err := strconv.Atoi(input.Body.Value)
			if err != nil || n <= 0 {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not a count — write a whole number above zero",
						input.Body.Value))
			}
		case aPercent:
			n, err := strconv.Atoi(input.Body.Value)
			if err != nil || n <= 0 || n > 100 {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not a share — write a whole number of percent "+
						"between 1 and 100", input.Body.Value))
			}
		case aDuration:
			d, err := time.ParseDuration(input.Body.Value)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not a length of time — write it as 72h, 30m or 45s",
						input.Body.Value))
			}
			if d <= 0 {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not a length of time anything can wait for — "+
						"every reader treats it as unset and falls back to the shipped value",
						input.Body.Value))
			}
			// Refused here as well as at the sign-in that would use it, for
			// the reason the markdown policy is enforced before storage:
			// somebody who asks for a year should be told the limit now
			// rather than discover it when nobody can sign in.
			if input.Name == setting.SessionLifetime && d > access.MaxSessionLifetime {
				return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
					"a sign-in may last at most %s. Group membership is read at "+
						"sign-in and never again, so this is how long a role a group "+
						"withdrew can still be held", access.MaxSessionLifetime))
			}
		}
		// The prior value, answered by the write that replaced it: it is not
		// derivable afterwards, and the person who raised the floor to
		// critical is half of what somebody asks. Read in a statement of its
		// own it is the value at some earlier moment — two administrators
		// moving the same setting at once both read the original, and the
		// second writes a prior value into an append-only trail that nothing
		// ever held.
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
			settings := in.settings(tx)
			if settings == nil {
				return noDatabase(in.logger())
			}
			before, had, err := settings.Change(ctx, input.Name, input.Body.Value)
			if err != nil {
				return recording(in.Logger, "that setting could not be recorded", err)
			}
			if err := noted(ctx, tx, trail.Setting, input.Name,
				trail.Said(before, had), trail.Said(input.Body.Value, true)); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}

		// A deadline is stored on the finding when it is first seen,
		// so changing how long something may stay open makes every
		// stored one wrong. Rewritten here rather than left until the
		// next scan: a number somebody just typed that moves nothing
		// is worse than a slow screen, and it is the difference
		// between this and urgency, which nobody edits.
		if settable[row].movesDeadlines {
			// Off the request. The rewrite is bounded by how much is open
			// rather than by anything the caller sent — measured at nineteen
			// seconds against 441,108 findings — and a write that long is a
			// request no proxy will wait for. It is not on the queue either,
			// which would survive a restart: what a half-finished rewrite
			// costs is some findings keeping the old deadline until the next
			// scan or the next edit, which is the state they were already in
			// a moment ago.
			deadlinesRewritten(in)(ctx, input.Name, input.Body.Value)
		}
		return &struct{}{}, nil
	})
}

// deadlinesRewritten returns the way a handler asks for stored deadlines to be
// brought in line with a policy that just changed.
//
// One of these rather than each caller starting its own goroutine: the
// deployment's windows, the deployment's line and a product's line all
// invalidate the same stored answer, and three spellings of "and then rewrite
// them" is three places for one of them to be forgotten.
func deadlinesRewritten(in Ingest) func(context.Context, string, string) {
	return func(ctx context.Context, what, value string) {
		logger, db, replica := in.Logger, in.DB, in.Replica
		if db == nil {
			return
		}
		go func() {
			at := context.WithoutCancel(ctx)
			at, stop := context.WithTimeout(at, recomputeLimit)
			defer stop()
			rewriteDeadlines(at, db, replica, logger, what, value)
		}()
	}
}

// rewriteDeadlines applies a changed policy to every open finding, one replica
// at a time.
//
// The policy is read after the lease is taken, not before. Two replicas
// each handling a change would otherwise rewrite the same rows from whatever
// each read when it started, and whichever finished last would win — so the
// stored deadlines could end up describing a policy that had already been
// superseded, with nothing saying so. Waiting rather than skipping is the
// other half: a policy somebody just typed has to be applied, so the replica
// that loses the race applies it afterwards, and the last rewrite is the one
// holding the newest policy.
func rewriteDeadlines(ctx context.Context, db *database.DB, replica string,
	logger *slog.Logger, name, value string) {

	leases := queue.NewLeases(db.DB)
	if err := leases.Await(ctx, deadlineLease, replica, recomputeLimit, betweenTries); err != nil {
		logger.Error("deadlines could not be rewritten: no turn came",
			"setting", name, "value", value, "error", err)
		return
	}
	defer func() {
		// Handed back on a context of its own: this runs after work that may
		// have used up the bound, and a lease left held would stop the next
		// change being applied until it lapsed.
		back, stop := context.WithTimeout(context.WithoutCancel(ctx), settleLease)
		defer stop()
		if err := leases.Release(back, deadlineLease, replica); err != nil {
			logger.Warn("the deadline rewrite could not hand its turn back", "error", err)
		}
	}()

	windows, err := finding.LoadWindows(ctx, db.DB)
	if err != nil {
		logger.Error("deadlines could not be rewritten: cannot tell when things are due",
			"setting", name, "value", value, "error", err)
		return
	}
	started := time.Now()
	changed, err := finding.NewStore(db.DB).Recompute(ctx, windows)
	if err != nil {
		logger.Error("deadlines could not be rewritten",
			"setting", name, "value", value, "rewritten", changed, "error", err)
		return
	}
	logger.Info("deadlines rewritten after a policy change",
		"setting", name, "value", value, "findings", changed,
		"took", time.Since(started).Round(time.Millisecond).String())
}

// deadlineLease names the work of rewriting deadlines after a policy change,
// so that one replica does it at a time.
const deadlineLease = "deadline.rewrite"

// recomputeLimit bounds the rewrite that follows a policy change, waiting for
// a turn included. Long enough for a large estate, short enough that a rewrite
// which has stopped making progress does not sit there for the life of the
// process.
const recomputeLimit = 30 * time.Minute

// betweenTries is how often a replica waiting for its turn asks for it. Short
// against the length of a rewrite, so a turn is not left idle.
const betweenTries = 2 * time.Second

// settleLease bounds handing a lease back once the work is over, so a database
// that is not answering cannot hold a goroutine open.
const settleLease = 5 * time.Second

// settingRow finds a setting's row, and whether it is one.
//
// A name with no row is impossible rather than a fall-through: the struct
// literal will not compile without every field, so a setting added to the list
// carries its kind and its shipped value or the build stops.
func settingRow(name string) (int, bool) {
	for i := range settable {
		if settable[i].name == name {
			return i, true
		}
	}
	return 0, false
}
