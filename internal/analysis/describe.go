// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// Stated is what a run says about itself: in its documents, or beside them in
// the request where the documents say nothing.
type Stated struct {
	Series  string
	Commit  string
	BuiltAt time.Time
	Params  series.Params
}

// Describe is what an upload's documents state about the run, with what the
// request states filling what they leave out. The documents win where both
// state a value: the client writes into them what a plain producer passes
// beside them.
func Describe(logs []sarif.Log, given Stated) Stated {
	out := given
	var (
		tool, version, client string
		expected, analyzed    *int
		exit                  *int
		completed             *bool
		listed                = map[string]bool{}
		fired                 = map[string]bool{}
	)
	for _, log := range logs {
		for _, run := range log.Runs {
			if sarif.Scanner(run.Tool.Name) {
				continue
			}
			if tool == "" {
				tool, version = run.Tool.Name, run.Tool.Version
			}
			p := run.Properties
			if p.Client != "" {
				client = p.Client
			}
			if p.UnitsExpected != nil && p.UnitsAnalyzed != nil {
				expected, analyzed = add(expected, p.UnitsExpected), add(analyzed, p.UnitsAnalyzed)
			}
			for _, inv := range run.Invocations {
				if inv.ExitCode != nil && (exit == nil || *exit == 0) {
					exit = inv.ExitCode
				}
				if inv.Successful != nil && (completed == nil || *completed) {
					completed = inv.Successful
				}
			}
			for _, rule := range run.Tool.Rules {
				if rule.ID != "" {
					listed[rule.ID] = true
				}
			}
			for _, res := range run.Results {
				fired[res.RuleID] = true
			}
			if name, built, ok := automation(run.AutomationID); ok {
				out.Series, out.BuiltAt = name, built
			}
			if p.Series != "" {
				out.Series = p.Series
			}
			if t, err := time.Parse(time.RFC3339, p.Built); err == nil {
				out.BuiltAt = t
			}
			if p.Commit != "" {
				out.Commit = p.Commit
			}
		}
	}
	if tool != "" {
		out.Params.ToolName = tool
	}
	if version != "" {
		out.Params.ToolVersion = version
	}
	if client != "" {
		out.Params.ClientVersion = client
	}
	if expected != nil {
		out.Params.UnitsExpected, out.Params.UnitsAnalyzed = expected, analyzed
	}
	if exit != nil {
		out.Params.ExitStatus = exit
	}
	if completed != nil {
		out.Params.Completed = completed
	}
	// A rule list is the rule set only where it lists rules that never fired.
	// A tool listing just the rules that fired says nothing about the others.
	if unfired(listed, fired) {
		ids := make([]string, 0, len(listed))
		for id := range listed {
			ids = append(ids, id)
		}
		out.Params.RulesDigest, out.Params.RulesCount = RuleSet(ids)
	}
	return out
}

// RuleSet is a digest of the rules enabled, and how many there are.
func RuleSet(ids []string) (string, *int) {
	seen := map[string]bool{}
	var kept []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			kept = append(kept, id)
		}
	}
	if len(kept) == 0 {
		return "", nil
	}
	sort.Strings(kept)
	sum := sha256.Sum256([]byte(strings.Join(kept, "\n")))
	n := len(kept)
	return hex.EncodeToString(sum[:]), &n
}

func unfired(listed, fired map[string]bool) bool {
	for id := range listed {
		if !fired[id] {
			return true
		}
	}
	return false
}

func add(total, n *int) *int {
	sum := *n
	if total != nil {
		sum += *total
	}
	return &sum
}

// automation is a run's series and build time from its automation
// identifier, written as the series, a slash, and the build time. A series
// name may hold slashes of its own.
func automation(id string) (string, time.Time, bool) {
	at := strings.LastIndexByte(id, '/')
	if at <= 0 {
		return "", time.Time{}, false
	}
	built, err := time.Parse(time.RFC3339, id[at+1:])
	if err != nil {
		return "", time.Time{}, false
	}
	return id[:at], built, true
}

// RunHash identifies a run by its documents' digests and the build time it
// states. Two builds whose analyzer wrote the same bytes are two runs; the
// same documents sent again for one build are one. A zero build time is one
// dated on arrival, which a retry does not repeat, so it is left out.
func RunHash(digests []string, built time.Time) string {
	sorted := append([]string(nil), digests...)
	sort.Strings(sorted)
	whole := sha256.New()
	for _, d := range sorted {
		whole.Write([]byte("sarif " + d + "\n"))
	}
	if !built.IsZero() {
		whole.Write([]byte("built " + built.UTC().Format(time.RFC3339Nano) + "\n"))
	}
	return hex.EncodeToString(whole.Sum(nil))
}
