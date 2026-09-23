package main

import (
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// The passes a deployment runs beside the server, and the ones it does not.
//
// Ten loops were each guarded against a nil constructor result, and the doc
// comment above them said any of the ten might be absent because the thing it
// works on is not configured. Four of those guards could never be false — the
// constructors behind them return a value unconditionally — and three further
// passes were started with no guard at all, and were not the optional ones. So
// a reader working out which passes a deployment actually runs had to open six
// packages to find out that the answer was almost always "all of them".
//
// Held to here rather than left to reading, and without starting anything: the
// methods are taken as values, which a nil receiver allows because nothing
// calls them.

func TestWhatADeploymentWithNothingConfiguredStillRuns(t *testing.T) {
	// Mail and attachment storage are what a deployment may not have, and
	// everything else runs whatever is configured.
	running := named((passes{}).loops())
	for _, want := range []string{
		"read what arrived",
		"scan what arrived",
		"schedule rescans",
		"ask upstream what is current",
		"read what suppliers publish",
		"look up the branches patches are on",
		"watch for quiet builds",
		"send what is owed outward",
		"route unheld work to teams",
		"set aside work whose worker died",
	} {
		if !running[want] {
			t.Errorf("%q does not run in a deployment with nothing configured", want)
		}
	}
	for _, absent := range []string{"send mail", "sweep unattached files"} {
		if running[absent] {
			t.Errorf("%q runs with nothing configured to do it with", absent)
		}
	}
	if len(running) != 10 {
		t.Errorf("a deployment with nothing configured runs %d passes, want 10: %v",
			len(running), keysOf(running))
	}
}

func TestMailAndAttachmentSweepingRunWhenTheyAreConfigured(t *testing.T) {
	// The two that are absent above, present here — which is what makes the
	// count above a statement about configuration rather than about nil.
	configured := passes{
		post:   &notify.Post{},
		keeper: &attach.Keeper{},
	}
	running := named(configured.loops())
	for _, want := range []string{"send mail", "sweep unattached files"} {
		if !running[want] {
			t.Errorf("%q does not run where it is configured", want)
		}
	}
	if len(running) != 12 {
		t.Errorf("a deployment with everything configured runs %d passes, want 12: %v",
			len(running), keysOf(running))
	}
}

func TestEveryPassSaysWhatItIsAndHowOftenItRuns(t *testing.T) {
	// A pass added to the struct and left out of the list is one that stops
	// running with nothing saying so, and an unnamed one is a line in a
	// failure message that names nothing.
	for _, one := range (passes{}).loops() {
		if one.what == "" {
			t.Error("a pass runs under no name")
		}
		if one.run == nil {
			t.Errorf("%q is listed and has nothing to run", one.what)
		}
		if one.every < 0 {
			t.Errorf("%q runs every %s", one.what, one.every)
		}
	}
}

func named(loops []loop) map[string]bool {
	out := make(map[string]bool, len(loops))
	for _, one := range loops {
		out[one.what] = true
	}
	return out
}

func keysOf(running map[string]bool) []string {
	out := make([]string, 0, len(running))
	for what := range running {
		out = append(out, what)
	}
	return out
}

// TestAnUnknownSubcommandIsRefused pins the one that silently started a server.
//
// `openpsirt migrat` — a typo in a job meant to apply migrations and nothing
// else — fell through to serving, against whatever schema was there.
// runMigrate already refuses an action it does not know, which is the contrast
// that made this an omission rather than a choice.
func TestAnUnknownSubcommandIsRefused(t *testing.T) {
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()

	for _, c := range []struct {
		args    []string
		refused bool
	}{
		{[]string{"migrat"}, true},
		{[]string{"serve"}, true},
		// A flag nobody defined is the parser's to refuse, and it already
		// does — with a better message than this could give.
		{[]string{"migrate"}, false},
		{[]string{"migrate", "status"}, false},
	} {
		// No database is configured here, so the one that is *not* refused as
		// unknown fails further on — which is the distinction being pinned.
		err := run(c.args, quiet, quiet)
		named := err != nil && strings.Contains(err.Error(), "unknown command")
		if named != c.refused {
			t.Errorf("%v: refused as unknown = %v, want %v (err %v)",
				c.args, named, c.refused, err)
		}
	}
}
