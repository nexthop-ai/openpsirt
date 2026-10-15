// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

// slowLink is a patch link to a commit in a project on a host of its own.
func slowLink(name, hash string) string {
	return "https://slow.example/x/" + name + "/commit/" + hash
}

func slowRepository(name string) string { return "https://slow.example/x/" + name + ".git" }

// passOn is a pass over projects at any address, keyed on the repository.
func passOn(t *testing.T, db *database.DB, projects map[string]upstream) *patchbranch.Pass {
	t.Helper()
	return patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota, outward.Excluded{},
		func(repository string) string {
			if each, ok := projects[repository]; ok {
				return each.dir
			}
			t.Fatalf("a repository no test made was fetched: %s", repository)
			return ""
		})
}

func TestAHostPastItsShareOfThePassWaitsBehindEveryOtherHost(t *testing.T) {
	// The share is counted from when each visit began to when the visit
	// recorded that it ended, and a visit that failed held the pass as long
	// as one that reached the repository.
	for name, reaches := range map[string]bool{"Reached": true, "Failed": false} {
		t.Run(name, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				ctx := t.Context()
				first, second, other := project(t), project(t), project(t)
				if !reaches {
					first.dir = t.TempDir()
				}
				pass := passOn(t, db, map[string]upstream{
					slowRepository("first"): first, slowRepository("second"): second,
					repositoryOf("other"): other,
				})
				issue(t, db, "CVE-2025-0101", "critical", slowLink("first", first.fix))
				if visited, err := pass.Once(ctx); err != nil || visited != slowRepository("first") {
					t.Fatalf("visited %q, %v", visited, err)
				}
				repositories, _, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
				if err != nil {
					t.Fatal(err)
				}
				if failed := len(repositories) == 1 && repositories[0].State == patchbranch.Failed; failed == reaches {
					t.Fatalf("the first visit is reported as %+v", repositories)
				}
				// The visit began longer ago than the host's share. When it
				// ended is what the visit recorded. A failed visit's host was
				// reached earlier in the day, so it answers and does not wait
				// out.
				began := time.Now().UTC().Add(-patchbranch.HostShare - time.Hour)
				if _, err := db.DB.NewRaw(`UPDATE "patch_repository" SET "fetched_at" = ? WHERE "url" = ?`,
					began, slowRepository("first")).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				if !reaches {
					if _, err := db.DB.NewRaw(`UPDATE "patch_repository" SET "reached_at" = ? WHERE "url" = ?`,
						began.Add(-time.Hour), slowRepository("first")).Exec(ctx); err != nil {
						t.Fatal(err)
					}
				}
				issue(t, db, "CVE-2025-0102", "critical", slowLink("second", second.fix))
				issue(t, db, "CVE-2025-0103", "low", link("other", other.fix))
				visited, err := pass.Once(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if visited != repositoryOf("other") {
					t.Errorf("visited %q, want the low on a host that has not had its share", visited)
				}
				if visited, err = pass.Once(ctx); err != nil || visited != slowRepository("second") {
					t.Errorf("then visited %q, %v; want the host past its share once nothing else is due",
						visited, err)
				}
			})
		})
	}
}

func TestAHostWhoseRepositoryFailedAndNoneWasReachedWaitsADay(t *testing.T) {
	// A host whose every visit fails costs the pass one failed visit a day,
	// whatever number of repositories its links name. A host that answered
	// for one repository within the day keeps its others in the plan.
	for name, answered := range map[string]bool{"Unanswered": false, "Answered": true} {
		t.Run(name, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				ctx := t.Context()
				first, second := project(t), project(t)
				first.dir = t.TempDir()
				pass := passOn(t, db, map[string]upstream{
					slowRepository("first"): first, slowRepository("second"): second,
				})
				issue(t, db, "CVE-2025-0107", "critical", slowLink("first", first.fix))
				if visited, err := pass.Once(ctx); err != nil || visited != slowRepository("first") {
					t.Fatalf("visited %q, %v", visited, err)
				}
				if answered {
					if _, err := db.DB.NewRaw(`UPDATE "patch_repository" SET "reached_at" = ? WHERE "url" = ?`,
						time.Now().UTC().Add(-time.Hour), slowRepository("first")).Exec(ctx); err != nil {
						t.Fatal(err)
					}
				}
				issue(t, db, "CVE-2025-0108", "critical", slowLink("second", second.fix))
				visited, err := pass.Once(ctx)
				if err != nil {
					t.Fatal(err)
				}
				want := ""
				if answered {
					want = slowRepository("second")
				}
				if visited != want {
					t.Errorf("visited %q, want %q", visited, want)
				}
				repositories, _, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
				if err != nil {
					t.Fatal(err)
				}
				for _, each := range repositories {
					if each.URL == slowRepository("second") && !answered && each.Position != 0 {
						t.Errorf("the report places a repository on a host waiting out at %d", each.Position)
					}
				}
			})
		})
	}
}

func TestAHostHasOneFirstFetchInACycleBeforeAnyHostHasTwo(t *testing.T) {
	// Two repositories on one host plus one on another: the second host is
	// visited before the first host's second repository, although the first
	// host's are the more urgent.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		first, second, other := project(t), project(t), project(t)
		projects := map[string]upstream{
			slowRepository("first"): first, slowRepository("second"): second,
			repositoryOf("other"): other,
		}
		var order []string
		pass := passOn(t, db, projects).Locating(func(_ context.Context, repository string) string {
			if !slices.Contains(order, repository) {
				order = append(order, repository)
			}
			return projects[repository].dir
		})
		issue(t, db, "CVE-2025-0109", "critical", slowLink("first", first.fix))
		issue(t, db, "CVE-2025-0110", "critical", slowLink("second", second.fix))
		issue(t, db, "CVE-2025-0111", "low", link("other", other.fix))
		if visits := pass.Cycle(ctx); visits != 3 {
			t.Fatalf("the cycle visited %d repositories, want 3", visits)
		}
		if len(order) != 3 || order[1] != repositoryOf("other") {
			t.Errorf("fetched in the order %v, want the other host second", order)
		}
	})
}

func TestARemoteErrorInBytesThatAreNotTextIsRecordedAndWaitsADay(t *testing.T) {
	// git quotes what a remote said, and a remote says what it likes. The
	// failure is recorded whatever its bytes, and a failure that cannot be
	// recorded leaves the repository first in line at every wake.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		made := project(t)
		issue(t, db, "CVE-2025-0104", "critical", link("project", made.fix))
		// A git that dies the way it does when a remote answers its
		// advertisement with an error in bytes of the remote's choosing.
		wrapper := filepath.Join(t.TempDir(), "git")
		script := "#!/bin/sh\nprintf 'fatal: remote error: caf\\351 \\377\\376\\000 and so on\\n' >&2\nexit 128\n"
		if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil { //nolint:gosec // G306: the wrapper has to be executable
			t.Fatal(err)
		}
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"project": made}).Running(wrapper)
		if _, err := pass.Once(ctx); err != nil {
			t.Fatalf("the failure was not recorded: %v", err)
		}
		repositories, _, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 || repositories[0].State != patchbranch.Failed {
			t.Fatalf("the report says %+v, want the repository failed", repositories)
		}
		reason := repositories[0].Reason
		if !strings.Contains(reason, "remote error: caf\uFFFD") || !strings.Contains(reason, " and so on") ||
			strings.Contains(reason, "\x00") || !utf8.ValidString(reason) {
			t.Errorf("the reason recorded is %q", reason)
		}
		if visited, err := pass.Once(ctx); err != nil || visited != "" {
			t.Errorf("a repository that just failed was visited again: %q, %v", visited, err)
		}
	})
}

// grypeReporting is the scanner's report of two issues, each at the severity
// given and linking the commit given as its fix.
func grypeReporting(t *testing.T, issues map[string][2]string) scanner.Result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "scanner", "testdata", "grype-output.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	template := report["matches"].([]any)[0].(map[string]any)
	var matches []any
	for id, said := range issues {
		var match map[string]any
		copied, _ := json.Marshal(template)
		if err := json.Unmarshal(copied, &match); err != nil {
			t.Fatal(err)
		}
		vulnerability := match["vulnerability"].(map[string]any)
		vulnerability["id"], vulnerability["severity"] = id, said[0]
		vulnerability["urls"] = []string{said[1]}
		delete(match, "relatedVulnerabilities")
		matches = append(matches, match)
	}
	report["matches"] = matches
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ParseGrype(bytes.NewReader(out), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTheSeverityAScannerReportsOrdersTheRepositoriesItLinks(t *testing.T) {
	// The whole of the path a link takes: the scanner's report, the issue
	// recorded from it, and the order the pass takes the repositories in.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		mild, severe := project(t), project(t)
		result := grypeReporting(t, map[string][2]string{
			"CVE-2025-0105": {"Low", link("mild", mild.fix)},
			"CVE-2025-0106": {"Critical", slowLink("severe", severe.fix)},
		})
		var named []finding.Named
		for _, one := range result.Reported {
			named = append(named, one.Issue)
		}
		if _, err := finding.NewVulnerabilities(db.DB).Intern(ctx, named); err != nil {
			t.Fatal(err)
		}
		pass := passOn(t, db, map[string]upstream{
			repositoryOf("mild"): mild, slowRepository("severe"): severe,
		})
		visited, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if visited != slowRepository("severe") {
			t.Errorf("visited %q first, want the one the critical links", visited)
		}
	})
}
