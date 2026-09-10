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
	Means   string `json:"means" doc:"What it decides"`
}

// settable is every setting an operator may change, with what it decides.
//
// A list rather than anything the store will accept, so that adding a setting
// is a deliberate act and a typo in a name is refused instead of quietly
// creating a setting nothing reads.
var settable = []struct {
	name  string
	means string
}{
	{setting.DueExploited, "How long a known-exploited finding may stay open. Its own window, and the shortest: severity is how bad a flaw is, being exploited is a fact about the world"},
	{setting.DueCritical, "How long a critical may stay open"},
	{setting.DueHigh, "How long a high may stay open"},
	{setting.DueMedium, "How long a medium may stay open"},
	{setting.DueLow, "How long a low may stay open"},
	{setting.DeferralThreshold, "How long something may be put off before a second person has to agree. Measured against everything the finding has already been put off for, not against the postponement being asked for"},
	{setting.SessionLifetime, "How long a sign-in lasts"},
	{setting.MaxTokenLifetime, "The longest a personal token may be valid for"},
	{setting.TogetherCap, "How many findings one action may claim about at once. A whole number, not a length of time"},
	{setting.TriageFloor, "What counts as worth triaging: everything, or a severity word below which findings are still recorded and counted but kept out of the working list. A product may state its own instead"},
	{setting.QuietAfter, "How long a build may go without a scan arriving before it is reported as having gone quiet. Measured from the last arrival, or from when the build was declared where nothing has ever arrived"},
	{setting.ScanEvery, "How often everything tracked is scanned again against the vulnerability data of the day. A release that is never rebuilt has the same components it always had and a different answer every month, so this is what finds an advisory published after it shipped"},
	{setting.UpstreamCurrency, "Whether to ask public package indexes what the newest version of a component is. Off unless turned on: it is the only thing here that reaches the network, and a deployment that cannot reach out loses this answer and nothing else"},
	{setting.AttachmentMaxSize, "The largest single file this deployment accepts, in bytes. A whole number, not a length of time"},
	{setting.AttachmentQuota, "How much this deployment will hold in attachments in total, in bytes. Storage somebody else fills on our behalf needs a ceiling, and this is it"},
	{setting.AttachmentShare, "How much of that total any one person may hold, in bytes. A ceiling on the whole store is one person's to reach, and what it costs is everybody else's next upload"},
	{setting.AbsentAfter, "How long somebody may go without signing in before work they are holding is raised with administrators. It only ever asks: long leave and having left look the same from here"},
	{setting.WaitingAfter, "How long a claim may wait on a second person before whoever can approve it is told. What is wrong is that nothing has happened, which is the one thing no message driven by an event can report"},
	{setting.SentBackAfter, "How long a claim an approver asked more of may sit untouched before its proposer is told again. Shorter than the wait above: the question was asked of the person already holding it"},
	{setting.DeferralLead, "How long before a deferral's end date its proposer hears that it is coming. The date arriving puts the finding back in the queue, which is the last moment rather than the first useful warning"},
	{setting.QueuedAfter, "How long work may sit in a team's queue with nobody having taken it. Neither owned nor unowned, which is the gap where it looks handled and is not"},
	{setting.DiscloseAfter, "How long a finding nobody has announced stays that way before its date. What a deployment's coordinated-disclosure policy says, which is the deployment's to state rather than ours: an embargo somebody outside can hold us to is one they were told the length of"},
	{setting.ExtensionThreshold, "How much an embargo may be moved by in total before a second person has to agree. Measured against everything the date has already been moved by, not against the extension being asked for"},
	{setting.DisclosureLead, "How long before an embargo's date the people who could still move it are told it is coming. An extension nobody can agree to in time is an approval in name only"},
}

// aSwitch is the settings that are on or off. The fourth kind.
func aSwitch(name string) bool { return name == setting.UpstreamCurrency }

// theSwitch is what one may be set to.
var theSwitch = []string{setting.On, setting.Off}

// theFloor is the words the triage line may be set to. \"everything\" is not a
// severity — it is the absence of a line, and it is what a deployment starts
// with, because a tool that quietly hid findings on the day it was installed
// would be deciding something nobody asked it to.
var theFloor = []string{"everything", "low", "medium", "high", "critical"}

// aSeverity is the settings whose value is one of a few words rather than a
// length of time or a count. A third kind, checked as one: a value checked as
// the wrong kind is stored and then silently ignored.
func aSeverity(name string) bool { return name == setting.TriageFloor }

// aCount is the settings whose value is a number of things rather than a
// length of time. Named here because the two are checked differently, and a
// value checked as the wrong kind is stored and then silently ignored.
func aCount(name string) bool {
	switch name {
	case setting.TogetherCap, setting.AttachmentMaxSize, setting.AttachmentQuota,
		setting.AttachmentShare:
		return true
	}
	return false
}

func registerSettings(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-settings", Method: http.MethodGet, Path: "/v1/settings",
		Summary: "List what this deployment has decided",
		Description: "Returns every setting an operator may change, its value, and what it " +
			"decides. `default` means nobody has set it and the shipped value is in use.\n\n" +
			"The shipped numbers are a starting point rather than a recommendation. What a " +
			"deployment can hold to is a question about that deployment, and a deadline nobody " +
			"agreed to produces an estate that is permanently late and a signal everybody " +
			"ignores.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*listOutput[SettingBody], error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		settings := setting.NewStore(in.DB.DB)
		out := &listOutput[SettingBody]{}
		out.Body.Items = make([]SettingBody, 0, len(settable))
		for _, each := range settable {
			value, set, err := settings.Get(ctx, each.name)
			if err != nil {
				return nil, wentWrong(in.Logger, "the settings could not be read", err)
			}
			if !set {
				value = shipped(each.name)
			}
			out.Body.Items = append(out.Body.Items, SettingBody{
				Name: each.name, Value: value, Default: !set, Means: each.means,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-setting", Method: http.MethodPut, Path: "/v1/settings/{name}",
		Summary: "Change something for this deployment",
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
		known := false
		for _, each := range settable {
			if each.name == input.Name {
				known = true
				break
			}
		}
		if !known {
			return nil, huma.Error404NotFound("this deployment has no setting by that name")
		}
		// Checked before it is stored. A value nothing can read would leave
		// every caller falling back to the shipped one, which is a policy that
		// quietly stopped applying — and every reader here treats zero and
		// negative as unset, so those would do the same while looking set.
		if aSwitch(input.Name) {
			if !slices.Contains(theSwitch, input.Body.Value) {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not on or off — write one of %s",
						input.Body.Value, strings.Join(theSwitch, ", ")))
			}
		} else if aSeverity(input.Name) {
			if !slices.Contains(theFloor, input.Body.Value) {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not a line to triage from — write one of %s",
						input.Body.Value, strings.Join(theFloor, ", ")))
			}
		} else if aCount(input.Name) {
			n, err := strconv.Atoi(input.Body.Value)
			if err != nil || n <= 0 {
				return nil, huma.Error422UnprocessableEntity(
					fmt.Sprintf("%q is not a count — write a whole number above zero",
						input.Body.Value))
			}
		} else {
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
		}
		// What it held, read before it is overwritten: it is not
		// derivable afterwards, and "who raised the floor to critical"
		// is half the question somebody asks.
		before, had, err := setting.NewStore(in.DB.DB).Get(ctx, input.Name)
		if err != nil {
			return nil, wentWrong(in.Logger, "that setting could not be read", err)
		}
		if err := setting.NewStore(in.DB.DB).Set(ctx, input.Name, input.Body.Value); err != nil {
			return nil, wentWrong(in.Logger, "that setting could not be recorded", err)
		}
		noteChange(ctx, in, trail.Setting, input.Name,
			trail.Said(before, had), trail.Said(input.Body.Value, true))

		// A deadline is stored on the finding when it is first seen,
		// so changing how long something may stay open makes every
		// stored one wrong. Rewritten here rather than left until the
		// next scan: a number somebody just typed that moves nothing
		// is worse than a slow screen, and it is the difference
		// between this and urgency, which nobody edits.
		if deadline(input.Name) {
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

// deadline reports whether this setting decides how long something may stay
// open, and therefore whether changing it invalidates what is stored.
func deadline(name string) bool {
	switch name {
	case setting.DueExploited, setting.DueCritical, setting.DueHigh,
		setting.DueMedium, setting.DueLow:
		return true
	// Moving the line moves what has a deadline at all: below it nothing
	// does. So this invalidates what is stored for the same reason the
	// windows do, from the other direction.
	case setting.TriageFloor:
		return true
	}
	return false
}

// shipped is the value in force when nobody has set one.
func shipped(name string) string {
	switch name {
	case setting.DueExploited:
		return "72h"
	case setting.DueCritical:
		return "168h"
	case setting.DueHigh:
		return "720h"
	case setting.DueMedium:
		return "2160h"
	case setting.DueLow:
		return "4320h"
	case setting.DeferralThreshold:
		return "720h"
	case setting.SessionLifetime:
		return access.DefaultSessionLifetime.String()
	case setting.MaxTokenLifetime:
		return access.MaxTokenLifetime.String()
	case setting.TogetherCap:
		return strconv.Itoa(triage.DefaultTogetherCap)
	case setting.AttachmentMaxSize:
		return strconv.Itoa(setting.DefaultAttachmentMaxSize)
	case setting.AttachmentQuota:
		return strconv.Itoa(setting.DefaultAttachmentQuota)
	case setting.AttachmentShare:
		return strconv.Itoa(setting.DefaultAttachmentShare)
	case setting.AbsentAfter:
		return setting.DefaultAbsentAfter.String()
	case setting.WaitingAfter:
		return setting.DefaultWaitingAfter.String()
	case setting.SentBackAfter:
		return setting.DefaultSentBackAfter.String()
	case setting.DeferralLead:
		return setting.DefaultDeferralLead.String()
	case setting.QueuedAfter:
		return setting.DefaultQueuedAfter.String()
	case setting.TriageFloor:
		// Nothing hidden until somebody decides to hide it.
		return "everything"
	case setting.ScanEvery:
		return setting.DefaultScanEvery.String()
	case setting.QuietAfter:
		// A week. Long enough that a nightly build missing one night is not an
		// alert, short enough that a pipeline switched off is noticed in the
		// week it happens rather than the month.
		return "168h"
	case setting.UpstreamCurrency:
		// Nobody talked to until somebody says to.
		return setting.Off
	}
	return ""
}
