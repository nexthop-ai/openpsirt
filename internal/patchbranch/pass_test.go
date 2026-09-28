// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// upstream is a repository a test made, shaped like a project that backports:
// a fix on main, a branch cut after it that carries it, and an older branch
// that got its own copy of the fix as a separate commit.
type upstream struct {
	dir      string
	fix      string
	backport string
}

// gitIn runs git in dir with an identity and nothing from whoever runs the
// test.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{ //nolint:gosec // G204: the arguments are this file's own literals and hashes git printed
		"-c", "user.name=test", "-c", "user.email=test@example.test",
		"-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false",
	}, args...)...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func project(t *testing.T) upstream {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("these tests need git, which a deployment carries in its image")
	}
	dir := t.TempDir()
	gitIn(t, dir, "init", "--quiet")
	commit := func(message string) string {
		gitIn(t, dir, "commit", "--quiet", "--allow-empty", "-m", message)
		return gitIn(t, dir, "rev-parse", "HEAD")
	}
	commit("start")
	gitIn(t, dir, "branch", "release-1.y")
	fix := commit("fix the flaw")
	gitIn(t, dir, "branch", "release-2.y")
	commit("carry on")
	gitIn(t, dir, "checkout", "--quiet", "release-1.y")
	backport := commit("fix the flaw, backported")
	gitIn(t, dir, "checkout", "--quiet", "main")
	return upstream{dir: dir, fix: fix, backport: backport}
}

// link is a patch link to a commit in a named project.
func link(name, hash string) string {
	return "https://github.com/example/" + name + "/commit/" + hash
}

// repositoryOf is the address a project's links resolve to.
func repositoryOf(name string) string {
	return "https://github.com/example/" + name + ".git"
}

// issue records an issue rated severity whose report links to each of links as
// a patch.
func issue(t *testing.T, db *database.DB, identifier, severity string, links ...string) {
	t.Helper()
	ctx := t.Context()
	interned, err := finding.NewVulnerabilities(db.DB).Intern(ctx,
		[]finding.Named{{Identifier: identifier, Severity: severity}})
	if err != nil {
		t.Fatalf("record %s: %v", identifier, err)
	}
	row := &finding.Vulnerability{ID: interned[strings.ToUpper(identifier)]}
	for i, each := range links {
		reference := &finding.Reference{
			VulnerabilityID: row.ID, URL: each, Kind: finding.Patch,
			URLIdentity: identifier + "-" + string(rune('a'+i)),
		}
		if _, err := db.DB.NewInsert().Model(reference).Exec(ctx); err != nil {
			t.Fatalf("record a link for %s: %v", identifier, err)
		}
	}
}

// empty clears every table. What is due and what the report counts are
// questions about the whole table, and on a server engine the tests of a
// package share one database.
func empty(t *testing.T, db *database.DB) {
	t.Helper()
	dbtest.Reset(t, db)
}

// A copies directory given relative to where the process runs holds the copy
// where it is measured and renamed from.
func TestARelativeCopiesDirectoryHoldsItsCopies(t *testing.T) {
	up := project(t)
	t.Chdir(t.TempDir())
	pass := patchbranch.NewLocalPass(nil, "copies", patchbranch.DefaultQuota, outward.Excluded{},
		func(string) string { return up.dir })
	if err := pass.Fetch(t.Context(), repositoryOf("relative")); err != nil {
		t.Fatalf("a relative copies directory could not hold a copy: %v", err)
	}
	if !pass.Held(repositoryOf("relative")) {
		t.Error("the copy is not where the pass looks for it")
	}
}

// A visit asks for the lease again as it runs, and stops when another
// replica has it.
func TestAVisitRenewsItsLeaseAndStopsWhenItIsLost(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		issue(t, db, "CVE-2025-0019", "critical", link("project", made.fix))
		leases := queue.NewLeases(db.DB)
		heldUntil := func() time.Time {
			t.Helper()
			var row queue.Lease
			if err := db.DB.NewSelect().Model(&row).Where("name = ?", patchbranch.Lease).
				Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if row.HeldUntil == nil {
				return time.Time{}
			}
			return *row.HeldUntil
		}

		// Held through a slow fetch: the lease moves on while it runs.
		if mine, err := leases.Take(ctx, patchbranch.Lease, "one", 30*time.Minute); err != nil || !mine {
			t.Fatalf("taking the lease: %v %v", mine, err)
		}
		var during time.Time
		slow := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota,
			outward.Excluded{}, func(string) string {
				during = heldUntil()
				time.Sleep(200 * time.Millisecond)
				return made.dir
			}).Leased(db.DB, "one", 20*time.Millisecond)
		if _, err := slow.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if after := heldUntil(); !after.After(during) {
			t.Errorf("the lease stood at %v during the fetch and %v after, so it was not renewed",
				during, after)
		}

		// Lost part way: another replica takes it, and the visit stops rather
		// than writing what the other replica is also writing.
		if _, err := db.DB.NewUpdate().Table("patch_repository").
			Set("fetched_at = NULL").Set("reached_at = NULL").Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewUpdate().Table("patch_commit").
			Set("looked_at = NULL").Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		lost := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota,
			outward.Excluded{}, func(string) string {
				if _, err := db.DB.NewUpdate().Model((*queue.Lease)(nil)).
					Set("held_until = ?", time.Now().UTC().Add(-time.Hour)).
					Where("name = ?", patchbranch.Lease).Exec(ctx); err != nil {
					t.Error(err)
				}
				if mine, err := leases.Take(ctx, patchbranch.Lease, "two", time.Hour); err != nil || !mine {
					t.Errorf("the other replica could not take the lease: %v %v", mine, err)
				}
				time.Sleep(200 * time.Millisecond)
				return made.dir
			}).Leased(db.DB, "one", 20*time.Millisecond)
		if _, err := lost.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if lost.Held(repositoryOf("project")) {
			t.Error("a visit that lost its lease went on to keep a copy")
		}
	})
}

// A replica shutting down part way through a visit hands the lease back, so
// the next one carries on at once rather than waiting for it to lapse.
func TestAPassStoppedMidVisitHandsTheLeaseBack(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		made := project(t)
		issue(t, db, "CVE-2025-0020", "critical", link("project", made.fix))
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		pass := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota,
			outward.Excluded{}, func(string) string {
				stop()
				return made.dir
			}).Leased(db.DB, "one", time.Minute)
		pass.Cycle(ctx)
		mine, err := queue.NewLeases(db.DB).Take(t.Context(), patchbranch.Lease, "two", time.Hour)
		if err != nil || !mine {
			t.Errorf("the next replica could not take the work at once: %v %v", mine, err)
		}
	})
}

// passOver is a pass that fetches each named project from its directory.
func passOver(t *testing.T, db *database.DB, quota int64, excluded outward.Excluded, projects map[string]upstream) *patchbranch.Pass {
	t.Helper()
	return patchbranch.NewLocalPass(db.DB, t.TempDir(), quota, excluded, func(repository string) string {
		for name, each := range projects {
			if repositoryOf(name) == repository {
				return each.dir
			}
		}
		t.Fatalf("a repository no test made was fetched: %s", repository)
		return ""
	})
}

func TestEachPatchLinkIsLabeledWithTheBranchesHoldingItsCommit(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		missing := strings.Repeat("ab", 20)
		links := []string{
			link("project", made.fix),
			link("project", made.backport[:12]),
			link("project", missing),
		}
		issue(t, db, "CVE-2025-0001", "high", links...)
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"project": made})

		visited, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if visited != repositoryOf("project") {
			t.Fatalf("visited %q, want the project", visited)
		}
		labels, err := patchbranch.Labels(ctx, db.DB, append(links, "https://example.org/advisory"))
		if err != nil {
			t.Fatal(err)
		}
		for _, each := range []struct {
			link     string
			found    bool
			branches []string
		}{
			{links[0], true, []string{"main", "release-2.y"}},
			{links[1], true, []string{"release-1.y"}},
			{links[2], false, nil},
		} {
			label, ok := labels[each.link]
			switch {
			case !ok:
				t.Errorf("%s has no label", each.link)
			case label.Found != each.found:
				t.Errorf("%s found = %v, want %v", each.link, label.Found, each.found)
			case !slices.Equal(label.Branches, each.branches) || label.Count != len(each.branches):
				t.Errorf("%s is on %v (%d), want %v", each.link, label.Branches, label.Count, each.branches)
			}
		}
		if _, ok := labels["https://example.org/advisory"]; ok {
			t.Error("a link naming no commit was labeled")
		}
	})
}

func TestACopyMadeWithoutFilesTakesTheCommitsThatLandAfter(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		// Served through the protocol a host speaks, with the filter a host
		// honors, so the copy holds commits and no files — which a copy of a
		// plain directory never does.
		gitIn(t, made.dir, "config", "uploadpack.allowFilter", "true")
		// A file the copy never holds, which the commit landing later still
		// carries. A host sending that commit leaves it out, because the
		// copy has the commit it came from.
		if err := os.WriteFile(filepath.Join(made.dir, "readme"), []byte("readme\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitIn(t, made.dir, "add", "readme")
		gitIn(t, made.dir, "commit", "--quiet", "-m", "say what this is")
		issue(t, db, "CVE-2025-0015", "high", link("project", made.fix))
		pass := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota,
			outward.Excluded{}, func(string) string { return "file://" + made.dir })
		if visited, err := pass.Once(ctx); err != nil || visited != repositoryOf("project") {
			t.Fatalf("visited %q, %v", visited, err)
		}
		// A fix lands upstream after the copy was made, with a file in it.
		if err := os.WriteFile(filepath.Join(made.dir, "fixed"), []byte("fixed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitIn(t, made.dir, "add", "fixed")
		gitIn(t, made.dir, "commit", "--quiet", "-m", "fix another flaw")
		later := gitIn(t, made.dir, "rev-parse", "HEAD")
		issue(t, db, "CVE-2025-0016", "high", link("project", later))
		if visited, err := pass.Once(ctx); err != nil || visited != repositoryOf("project") {
			t.Fatalf("the second visit went to %q, %v", visited, err)
		}
		repositories, _, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 || repositories[0].Reason != "" {
			t.Fatalf("the second visit failed: %+v", repositories)
		}
		labels, err := patchbranch.Labels(ctx, db.DB, []string{link("project", later)})
		if err != nil {
			t.Fatal(err)
		}
		if got := labels[link("project", later)]; !got.Found || !slices.Equal(got.Branches, []string{"main"}) {
			t.Errorf("the commit that landed later is labeled %+v, want on main", got)
		}
	})
}

func TestABranchNameNoEngineCanStoreIsCountedAndNotKept(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		// git allows any byte in a branch name; two of the four engines refuse
		// text that is not UTF-8.
		gitIn(t, made.dir, "branch", "release-\xff", made.fix)
		issue(t, db, "CVE-2025-0017", "high", link("project", made.fix))
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"project": made})
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		labels, err := patchbranch.Labels(ctx, db.DB, []string{link("project", made.fix)})
		if err != nil {
			t.Fatal(err)
		}
		got := labels[link("project", made.fix)]
		if !slices.Equal(got.Branches, []string{"main", "release-2.y"}) || got.Count != 3 {
			t.Errorf("labeled %v of %d, want main and release-2.y of 3", got.Branches, got.Count)
		}
	})
}

func TestNothingIsFetchedWhileTheLookupsAreOff(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		made := project(t)
		issue(t, db, "CVE-2025-0002", "critical", link("project", made.fix))
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"project": made}).TurnOff()
		visited, err := pass.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if visited != "" || pass.Held(repositoryOf("project")) {
			t.Errorf("a repository was fetched with the lookups off: %q", visited)
		}
	})
}

func TestTheRepositoryBehindTheWorstIssueIsVisitedFirst(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		mild, severe := project(t), project(t)
		issue(t, db, "CVE-2025-0003", "low", link("mild", mild.fix))
		issue(t, db, "CVE-2025-0004", "critical", link("severe", severe.fix))
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"mild": mild, "severe": severe})
		visited, err := pass.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if visited != repositoryOf("severe") {
			t.Errorf("visited %q first, want the one behind the critical", visited)
		}
	})
}

func TestARepositoryAlreadyCopiedIsVisitedFirstForNewCommits(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		mild, severe := project(t), project(t)
		issue(t, db, "CVE-2025-0005", "low", link("mild", mild.fix))
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"mild": mild, "severe": severe})
		if visited, err := pass.Once(ctx); err != nil || visited != repositoryOf("mild") {
			t.Fatalf("visited %q, %v", visited, err)
		}
		// A new low issue in the copied repository, and a critical in one
		// never fetched. The copy is already here, so its new commit is the
		// cheap one.
		issue(t, db, "CVE-2025-0006", "low", link("mild", mild.backport))
		issue(t, db, "CVE-2025-0007", "critical", link("severe", severe.fix))
		visited, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if visited != repositoryOf("mild") {
			t.Errorf("visited %q, want the repository already copied", visited)
		}
		if visited, err = pass.Once(ctx); err != nil || visited != repositoryOf("severe") {
			t.Errorf("then visited %q, %v; want the one behind the critical", visited, err)
		}
	})
}

func TestARepositoryOnAnExcludedHostIsNeverVisited(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		issue(t, db, "CVE-2025-0008", "critical", link("project", made.fix))
		excluded, err := outward.ParseExcluded("github.com")
		if err != nil {
			t.Fatal(err)
		}
		pass := passOver(t, db, patchbranch.DefaultQuota, excluded,
			map[string]upstream{"project": made})
		visited, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if visited != "" || pass.Held(repositoryOf("project")) {
			t.Errorf("a repository on an excluded host was visited: %q", visited)
		}
		repositories, _, err := patchbranch.Progress(ctx, db.DB, excluded)
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 || repositories[0].State != patchbranch.Refused {
			t.Errorf("the report says %+v, want the one repository excluded", repositories)
		}
	})
}

// A host longer than the stored column is judged on the address, which is
// stored whole, so the suffix an exclusion names is not cut off first.
func TestARepositoryOnALongExcludedHostIsNeverVisited(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." +
			strings.Repeat("c", 60) + ".excluded.example"
		issue(t, db, "CVE-2025-0018", "critical", "https://"+long+"/example/project/commit/"+made.fix)
		excluded, err := outward.ParseExcluded("excluded.example")
		if err != nil {
			t.Fatal(err)
		}
		pass := passOver(t, db, patchbranch.DefaultQuota, excluded, map[string]upstream{})
		if visited, err := pass.Once(ctx); err != nil || visited != "" {
			t.Errorf("a repository on a long excluded host was visited: %q %v", visited, err)
		}
		repositories, _, err := patchbranch.Progress(ctx, db.DB, excluded)
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 || repositories[0].State != patchbranch.Refused {
			t.Errorf("the report says %+v, want the one repository excluded", repositories)
		}
	})
}

// Git is given none of the configuration, credentials or proxy of the process
// it runs under, and every invocation refuses what could send a request or a
// credential somewhere a report chose.
func TestGitIsGivenNoConfigurationOrCredentialsOfTheProcess(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test")
	t.Setenv("GIT_CONFIG_GLOBAL", "/somewhere/else")
	want := map[string]bool{
		"HOME=/copies": true, "GIT_CONFIG_NOSYSTEM=1": true, "GIT_CONFIG_GLOBAL=" + os.DevNull: true,
		"GIT_TERMINAL_PROMPT=0": true, "GIT_ASKPASS=": true, "SSH_ASKPASS=": true,
		"GIT_NO_LAZY_FETCH=1": true, "LC_ALL=C": true,
	}
	for _, each := range patchbranch.Environment("/copies") {
		if strings.HasPrefix(each, "PATH=") {
			continue
		}
		if !want[each] {
			t.Errorf("git is given %q", each)
		}
		delete(want, each)
	}
	for each := range want {
		t.Errorf("git is not given %q", each)
	}

	said := map[string]bool{}
	settings := patchbranch.Settings("")
	for i := 0; i+1 < len(settings); i += 2 {
		if settings[i] == "-c" {
			said[settings[i+1]] = true
		}
	}
	for _, each := range []string{"protocol.allow=never", "credential.helper=", "core.askPass=",
		"http.followRedirects=false", "core.hooksPath=" + os.DevNull} {
		if !said[each] {
			t.Errorf("git runs without %q", each)
		}
	}
}

func TestACopyLargerThanTheCacheIsNotKeptAndWaitsADay(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		issue(t, db, "CVE-2025-0009", "critical", link("project", made.fix))
		pass := passOver(t, db, 1, outward.Excluded{}, map[string]upstream{"project": made})
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if pass.Held(repositoryOf("project")) {
			t.Error("a copy larger than the cache was kept")
		}
		repositories, _, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 || repositories[0].State != patchbranch.Failed ||
			!strings.Contains(repositories[0].Reason, "larger than the cache") {
			t.Fatalf("the report says %+v, want a failure saying it did not fit", repositories)
		}
		if visited, err := pass.Once(ctx); err != nil || visited != "" {
			t.Errorf("a repository that just failed was visited again: %q, %v", visited, err)
		}
		pass.Now = func() time.Time { return time.Now().Add(patchbranch.RetryAfter + time.Minute) }
		if visited, err := pass.Once(ctx); err != nil || visited != repositoryOf("project") {
			t.Errorf("a day later it was not tried again: %q, %v", visited, err)
		}
	})
}

func TestAVisitStoppedPartwayIsNeitherFinishedNorFailed(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		made := project(t)
		issue(t, db, "CVE-2025-0014", "critical", link("project", made.fix))
		// Shutdown arrives as the fetch begins.
		ctx, stop := context.WithCancel(t.Context())
		pass := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota,
			outward.Excluded{}, func(string) string {
				stop()
				return made.dir
			})
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		repositories, _, err := patchbranch.Progress(t.Context(), db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 {
			t.Fatalf("the report says %+v", repositories)
		}
		got := repositories[0]
		if got.State != patchbranch.Waiting || got.ReachedAt != nil || got.Reason != "" {
			t.Errorf("a stopped visit reads as %s, finished %v, reason %q; want waiting, unfinished, no reason",
				got.State, got.ReachedAt, got.Reason)
		}
	})
}

func TestAVisitKeepsTheLeaseAsItGoes(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		pass := patchbranch.NewLeasedPass(db.DB, "this-replica")
		if err := pass.StillMine(ctx); err != nil {
			t.Fatal(err)
		}
		// Another replica asking now is refused: the visit holds the work.
		other, err := queue.NewLeases(db.DB).Take(ctx, patchbranch.Lease, "other-replica", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if other {
			t.Error("a second replica took the lease from a visit in progress")
		}
	})
}

func TestAVisitStoppedPartwayLeavesAnEarlierFailureStanding(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		made := project(t)
		issue(t, db, "CVE-2025-0018", "critical", link("project", made.fix))
		// A visit that fails: the copy cannot fit.
		failing := patchbranch.NewLocalPass(db.DB, t.TempDir(), 1, outward.Excluded{},
			func(string) string { return made.dir })
		if _, err := failing.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		before, _, err := patchbranch.Progress(t.Context(), db.DB, outward.Excluded{})
		if err != nil || len(before) != 1 || before[0].Reason == "" {
			t.Fatalf("the first visit did not fail: %+v, %v", before, err)
		}
		// A day on, the retry is cut short by a shutdown.
		ctx, stop := context.WithCancel(t.Context())
		retry := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota,
			outward.Excluded{}, func(string) string {
				stop()
				return made.dir
			})
		retry.Now = func() time.Time { return time.Now().Add(patchbranch.RetryAfter + time.Minute) }
		if visited, err := retry.Once(ctx); err != nil || visited == "" {
			t.Fatalf("the retry did not begin: %q, %v", visited, err)
		}
		after, _, err := patchbranch.Progress(t.Context(), db.DB, outward.Excluded{})
		if err != nil || len(after) != 1 {
			t.Fatalf("the report says %+v, %v", after, err)
		}
		if after[0].Reason != before[0].Reason || after[0].State != patchbranch.Failed ||
			!after[0].FetchedAt.Equal(*before[0].FetchedAt) {
			t.Errorf("after a stopped retry the repository reads %s, %q, began %v; want it as it was: %s, %q, began %v",
				after[0].State, after[0].Reason, after[0].FetchedAt,
				before[0].State, before[0].Reason, before[0].FetchedAt)
		}
	})
}

func TestAFailureOfOursIsNotRecordedAsTheRepositorys(t *testing.T) {
	// SQLite alone: what this pins is which side a failure is charged to, not
	// what any engine does, and breaking a table under a shared server
	// database would break the tests beside it.
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		made := project(t)
		issue(t, db, "CVE-2025-0019", "critical", link("project", made.fix))
		// The table a lookup is recorded in goes away once the visit begins,
		// which is this deployment failing and not the repository.
		pass := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota,
			outward.Excluded{}, func(string) string {
				if _, err := db.ExecContext(t.Context(),
					`ALTER TABLE "patch_commit_branch" RENAME TO "patch_commit_branch_away"`); err != nil {
					t.Fatal(err)
				}
				return made.dir
			})
		if _, err := pass.Once(t.Context()); err == nil {
			t.Error("a visit that could not record what it found reported nothing")
		}
		repositories, _, err := patchbranch.Progress(t.Context(), db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 || repositories[0].State == patchbranch.Failed || repositories[0].Reason != "" {
			t.Errorf("the repository reads %+v, want it not blamed", repositories)
		}
	})
}

func TestProgressCountsWhatIsLookedUpAgainstWhatIsLinked(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		made := project(t)
		issue(t, db, "CVE-2025-0010", "high",
			link("project", made.fix), link("project", strings.Repeat("cd", 20)),
			"https://github.com/example/project/pull/7")
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"project": made})
		_, before, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if before != (patchbranch.Totals{Links: 3, Commits: 2}) {
			t.Errorf("before the pass the totals are %+v", before)
		}
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		repositories, after, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 1 || repositories[0].State != patchbranch.Done ||
			repositories[0].HeldBytes == nil || *repositories[0].HeldBytes == 0 {
			t.Fatalf("the report says %+v, want the repository done and its size", repositories)
		}
		want := patchbranch.Totals{Links: 3, Commits: 2, Looked: 2, Found: 1,
			HeldBytes: *repositories[0].HeldBytes}
		if after != want {
			t.Errorf("after the pass the totals are %+v, want %+v", after, want)
		}
	})
}

func TestTheLeastRecentlyUsedCopyIsRemovedFirst(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		first, second, third := project(t), project(t), project(t)
		cache := t.TempDir()
		projects := map[string]upstream{"first": first, "second": second, "third": third}
		locate := func(repository string) string {
			for name, each := range projects {
				if repositoryOf(name) == repository {
					return each.dir
				}
			}
			return ""
		}
		// Room for two copies of this size and not three.
		probe := patchbranch.NewLocalPass(db.DB, cache, patchbranch.DefaultQuota, outward.Excluded{}, locate)
		issue(t, db, "CVE-2025-0011", "critical", link("first", first.fix))
		if _, err := probe.Once(ctx); err != nil {
			t.Fatal(err)
		}
		one := dirSize(t, cache)
		// Measured after each visit only. A copy arriving is briefly larger
		// than it ends, so room made while it arrives can take a second copy
		// — the order is the same, and the order is what this pins.
		pass := patchbranch.NewLocalPass(db.DB, cache, 2*one+one/2, outward.Excluded{}, locate).Unpolled()
		issue(t, db, "CVE-2025-0012", "high", link("second", second.fix))
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		issue(t, db, "CVE-2025-0013", "medium", link("third", third.fix))
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]bool{"first": false, "second": true, "third": true} {
			if got := pass.Held(repositoryOf(name)); got != want {
				t.Errorf("%s held = %v, want %v", name, got, want)
			}
		}
		// And the removal is recorded: a copy no longer on the disk holds no
		// bytes, so the report does not count it and the next plan does not
		// take it as held.
		progress, totals, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		var held int64
		seen := 0
		for _, repository := range progress {
			for name, want := range map[string]bool{"first": false, "second": true, "third": true} {
				if repository.URL != repositoryOf(name) {
					continue
				}
				seen++
				if got := repository.HeldBytes != nil; got != want {
					t.Errorf("%s is reported holding bytes = %v, want %v", name, got, want)
				}
				if repository.HeldBytes != nil {
					held += *repository.HeldBytes
				}
			}
		}
		if seen != 3 {
			t.Fatalf("the report named %d of the three repositories", seen)
		}
		if totals.HeldBytes != held {
			t.Errorf("the report totals %d bytes held, and the copies still held take %d",
				totals.HeldBytes, held)
		}
	})
}

// dirSize is how many bytes a directory holds.
func dirSize(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return total
}
