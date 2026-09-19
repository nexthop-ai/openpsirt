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
	Means   string `json:"means" doc:"The thing it decides"`
	// Kind is what the value is, so a client offers the control the value
	// takes rather than a text field somebody types a refused value into.
	//
	// Served rather than kept client-side: it was three tables in the
	// interface keyed on setting names, beside the server's own — five copies
	// of one fact, and a setting added to any of them was a control that
	// offered the wrong thing or none.
	Kind string `json:"kind" enum:"duration,count,size,word,switch" doc:"The kind of value: a length of time, a count of things, a count of bytes, one of a few words, or on and off"`
	// Words is what a word setting may be set to, in the order to offer them.
	// Empty for every other kind.
	Words []string `json:"words,omitempty" doc:"For a word setting, the values it takes, in the order to offer them"`
}

// settingKind is what a value of a setting is.
//
// Named because the four are checked differently, and a value checked as the
// wrong kind is stored and then silently ignored. Carried on the row rather
// than answered by four functions that each knew about some of the names: a
// name missing from all four fell through to "a length of time", and a name
// missing from the shipped switch fell through to the empty string.
type settingKind string

const (
	aDuration settingKind = "duration"
	aCount    settingKind = "count"
	// aSize is a count of bytes. Checked exactly as a count is — the write
	// path cannot tell them apart and does not need to — and named separately
	// because a screen must: 26214400 is twenty-five megabytes and nobody
	// reads it as that, so the mistake available in a raw byte field is a
	// factor of a thousand.
	aSize   settingKind = "size"
	aWord   settingKind = "word"
	aSwitch settingKind = "switch"
)

// windows is the shipped deadline policy, read from the package that applies
// it. Five of these were respelled as string literals here, and a shipped
// number written twice is one that disagrees with itself the first time
// anybody moves it.
var windows = finding.DefaultWindows()

// sessionLifetime is the one shipped value that is not a constant.
//
// A sign-in's length falls back to the environment before the built-in, so
// reporting the built-in said twelve hours on a deployment that had set
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
// creating a setting nothing reads. **One row per setting**, because it was
// five tables keyed on the same name and three of the names were in some of
// them: the three disclosure settings reported as blank on the screen while
// 90d, 30d and 14d were what the deployment enforced.
var settable = []struct {
	name  string
	means string
	// kind is what a value of this setting is, which decides how it is
	// checked at the write and how the screen offers it.
	kind settingKind
	// words is what this setting may be set to, in the order to offer them,
	// and is the list the write path checks against. Nil for every kind but a
	// word or a switch.
	//
	// On the row rather than in a second table keyed on the name: keyed that
	// way, the next word setting anybody adds is offered nothing and then
	// checked against the triage floor's list, which is the shape the rest of
	// this commit removes.
	words []string
	// shipped is the value in force where nobody has set one, read from the
	// package that reads it rather than respelled here — five of them were
	// respelled, and a shipped number written twice is one that disagrees with
	// itself the first time anybody moves it.
	//
	// A function rather than a constant for the one setting whose shipped
	// value is not one: a sign-in's length falls back to the environment
	// before the built-in, which is why this takes the Ingest.
	shipped func(Ingest) string
	// movesDeadlines says changing this invalidates every stored deadline,
	// so they are rewritten away from the request.
	movesDeadlines bool
}{
	{setting.DueExploited, "How long a known-exploited finding may stay open. Its own window, and the shortest: severity is how bad a flaw is, being exploited is a fact about the world",
		aDuration, nil, func(Ingest) string { return windows.Exploited.String() }, true},
	{setting.DueCritical, "How long a critical may stay open",
		aDuration, nil, func(Ingest) string { return windows.Critical.String() }, true},
	{setting.DueHigh, "How long a high may stay open",
		aDuration, nil, func(Ingest) string { return windows.High.String() }, true},
	{setting.DueMedium, "How long a medium may stay open",
		aDuration, nil, func(Ingest) string { return windows.Medium.String() }, true},
	{setting.DueLow, "How long a low may stay open",
		aDuration, nil, func(Ingest) string { return windows.Low.String() }, true},
	{setting.DeferralThreshold, "How long something may be put off before a second person has to agree. Measured against everything the finding has already been put off for, not against the postponement being asked for",
		aDuration, nil, func(Ingest) string { return triage.DefaultDeferralThreshold.String() }, false},
	{setting.SessionLifetime, "How long a sign-in lasts",
		aDuration, nil, sessionLifetime, false},
	{setting.MaxTokenLifetime, "The longest a personal token may be valid for",
		aDuration, nil, func(Ingest) string { return access.MaxTokenLifetime.String() }, false},
	{setting.ClaimWindow, "How long an authorization written for somebody who has never signed in stays redeemable. It is the one window where a name rather than an identifier decides who gets a set of roles, so it ends",
		aDuration, nil, func(Ingest) string { return access.DefaultClaimWindow.String() }, false},
	{setting.TogetherCap, "How many findings one action may claim about at once. A whole number, not a length of time",
		aCount, nil, func(Ingest) string { return strconv.Itoa(triage.DefaultTogetherCap) }, false},
	{setting.TriageFloor, "What counts as worth triaging: everything, or a severity word below which findings are still recorded and counted but kept out of the working list. A product may state its own instead",
		aWord, theFloor, func(Ingest) string { return theFloor[0] }, true},
	{setting.QuietAfter, "How long a build may go without a scan arriving before it is reported as having gone quiet. Measured from the last arrival, or from when the build was declared where nothing has ever arrived",
		aDuration, nil, func(Ingest) string { return setting.DefaultQuietAfter.String() }, false},
	{setting.VulnerabilityDataStaleAfter, "How long the vulnerability data may go without moving before the deployment is told. A scan against data that has not moved answers the same way it did last month, with the same confidence and nothing saying so",
		aDuration, nil, func(Ingest) string { return setting.DefaultVulnerabilityDataStaleAfter.String() }, false},
	{setting.ScanEvery, "How often everything tracked is scanned again against the vulnerability data of the day. A release that is never rebuilt has the same components it always had and a different answer every month, so this is what finds an advisory published after it shipped",
		aDuration, nil, func(Ingest) string { return setting.DefaultScanEvery.String() }, false},
	{setting.UpstreamCurrency, "Whether to ask public package indexes what the newest version of a component is. Off unless turned on: it is the only thing here that reaches the network, and a deployment that cannot reach out loses this answer and nothing else. What goes out is a component's name, one request per component, carrying the name and nothing else — so names this deployment calls its own are held back, and the report of what has no upstream answer says which",
		aSwitch, theSwitch, func(Ingest) string { return setting.Off }, false},
	{setting.AttachmentMaxSize, "The largest single file this deployment accepts, in bytes. A whole number, not a length of time",
		aSize, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultAttachmentMaxSize) }, false},
	{setting.AttachmentQuota, "How much this deployment will hold in attachments in total, in bytes. Storage somebody else fills on our behalf needs a ceiling, and this is it",
		aSize, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultAttachmentQuota) }, false},
	{setting.QueueBacklog, "How much background work of one kind may be waiting before more of that kind is refused. A whole number, not a length of time. Counted per kind, so a producer that has filled its own queue does not refuse everybody else's work",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultQueueBacklog) }, false},
	{setting.RoutingBatch, "How many findings one pass of the routing sweep places, at most. A bulk judgment is bounded and the bound belongs here rather than in the binary: on a large estate a pass can be too big to hold a connection through or too small to drain the backlog",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultRoutingBatch) }, false},
	{setting.SavedPerPerson, "How many saved filters one person may keep for one product. A whole number, not a length of time. The panel that lists them reads every one on every open, so the ceiling is what keeps that a list rather than a table scan",
		aCount, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultSavedPerPerson) }, false},
	{setting.AttachmentShare, "How much of that total any one person may hold, in bytes. A ceiling on the whole store is one person's to reach, and what it costs is everybody else's next upload",
		aSize, nil, func(Ingest) string { return strconv.Itoa(setting.DefaultAttachmentShare) }, false},
	{setting.AbsentAfter, "How long somebody may go without signing in before work they are holding is raised with administrators. It only ever asks: long leave and having left look the same from here",
		aDuration, nil, func(Ingest) string { return setting.DefaultAbsentAfter.String() }, false},
	{setting.WaitingAfter, "How long a claim may wait on a second person before whoever can approve it is told. What is wrong is that nothing has happened, which is the one thing no message driven by an event can report",
		aDuration, nil, func(Ingest) string { return setting.DefaultWaitingAfter.String() }, false},
	{setting.SentBackAfter, "How long a claim an approver asked more of may sit untouched before its proposer is told again. Shorter than the wait above: the question was asked of the person already holding it",
		aDuration, nil, func(Ingest) string { return setting.DefaultSentBackAfter.String() }, false},
	{setting.DeferralLead, "How long before a deferral's end date its proposer hears that it is coming. The date arriving puts the finding back in the queue, which is the last moment rather than the first useful warning",
		aDuration, nil, func(Ingest) string { return setting.DefaultDeferralLead.String() }, false},
	{setting.QueuedAfter, "How long work may sit in a team's queue with nobody having taken it. Neither owned nor unowned, which is the gap where it looks handled and is not",
		aDuration, nil, func(Ingest) string { return setting.DefaultQueuedAfter.String() }, false},
	{setting.DiscloseAfter, "How long a finding nobody has announced stays that way before its date. What a deployment's coordinated-disclosure policy says, which is the deployment's to state rather than ours: an embargo somebody outside can hold us to is one they were told the length of",
		aDuration, nil, func(Ingest) string { return setting.DefaultDiscloseAfter.String() }, false},
	{setting.ExtensionThreshold, "How much an embargo may be moved by in total before a second person has to agree. Measured against everything the date has already been moved by, not against the extension being asked for",
		aDuration, nil, func(Ingest) string { return setting.DefaultExtensionThreshold.String() }, false},
	{setting.DisclosureLead, "How long before an embargo's date the people who could still move it are told it is coming. An extension nobody can agree to in time is an approval in name only",
		aDuration, nil, func(Ingest) string { return setting.DefaultDisclosureLead.String() }, false},
}

// theSwitch is what an on-or-off setting may be set to.
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
		// database. Built from `in.DB.DB` directly this panicked into the
		// recovery middleware and answered 500, where the route already has
		// words for a process that has no database.
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
				Name: each.name, Value: value, Default: !set, Means: each.means,
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
		// What it held, answered by the write that replaced it: it is not
		// derivable afterwards, and "who raised the floor to critical" is half
		// the question somebody asks. Read in a statement of its own it was
		// the value at some earlier moment — two administrators moving the
		// same setting at once both read the original, and the second wrote a
		// prior value into an append-only trail that nothing ever held.
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
// **The policy is read after the lease is taken, not before.** Two replicas
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
