// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package build_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pages is a published documentation branch on a remote, a build of one set
// on top of it bundled as the build job bundles it, and a clone to push from.
type pages struct {
	t                     *testing.T
	remote, build, pusher string
	bundle                string
}

// git runs git in dir and answers what it printed.
func (p *pages) git(dir string, args ...string) string {
	p.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir,
		"-c", "init.defaultBranch=gh-pages", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = isolated()
	out, err := cmd.CombinedOutput()
	if err != nil {
		p.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// isolated is the environment every git run here gets: an identity of its
// own, and no global or system configuration, so a host's identity, signing
// or hooks neither stand in for one nor change what runs.
func isolated() []string {
	return append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
}

// commit writes files in dir and commits them.
func (p *pages) commit(dir string, files map[string]string) {
	p.t.Helper()
	for name, body := range files {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755); err != nil {
			p.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			p.t.Fatal(err)
		}
	}
	p.git(dir, "add", "-A")
	p.git(dir, "commit", "-q", "-m", "pages")
}

// newPages makes a remote whose branch holds one set, and a build adding
// built on top of it.
func newPages(t *testing.T, built map[string]string) *pages {
	t.Helper()
	root := t.TempDir()
	p := &pages{t: t, remote: filepath.Join(root, "remote.git"), build: filepath.Join(root, "build"),
		pusher: filepath.Join(root, "pusher"), bundle: filepath.Join(root, "pages.bundle")}
	p.git(root, "init", "-q", "--bare", p.remote)
	p.git(root, "clone", "-q", p.remote, p.build)
	p.git(p.build, "checkout", "-q", "-b", "gh-pages")
	p.commit(p.build, map[string]string{"versions.json": `[{"version":"main"}]`, "main/index.html": "one"})
	p.git(p.build, "push", "-q", "origin", "gh-pages")
	p.git(root, "clone", "-q", p.remote, p.pusher)
	published := p.git(p.build, "rev-parse", "HEAD")
	p.commit(p.build, built)
	p.git(p.build, "bundle", "create", p.bundle, "gh-pages", "^"+published)
	return p
}

// elsewhere publishes another set while the build ran.
func (p *pages) elsewhere(files map[string]string) {
	p.t.Helper()
	other := filepath.Join(p.t.TempDir(), "other")
	p.git(filepath.Dir(other), "clone", "-q", "-b", "gh-pages", p.remote, other)
	p.commit(other, files)
	p.git(other, "push", "-q", "origin", "gh-pages")
}

// push runs the publish step, answering what it printed and whether it passed.
func (p *pages) push() (string, bool) {
	p.t.Helper()
	script, err := filepath.Abs("../../.github/scripts/push-pages.sh")
	if err != nil {
		p.t.Fatal(err)
	}
	cmd := exec.Command(script, p.bundle)
	cmd.Dir = p.pusher
	// No identity: the script names its own committer, as a runner has none.
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// published is a file as the remote's branch holds it.
func (p *pages) published(name string) string {
	p.t.Helper()
	return p.git(p.remote, "show", "gh-pages:"+name)
}

func TestPagesBuiltOnThePublishedBranchArePushed(t *testing.T) {
	p := newPages(t, map[string]string{"main/index.html": "two"})
	if out, ok := p.push(); !ok {
		t.Fatalf("the push failed: %s", out)
	}
	if got := p.published("main/index.html"); got != "two" {
		t.Errorf("the branch holds %q, want the built page", got)
	}
}

func TestPagesBuiltBeforeTheBranchMovedAreAppliedOnItsNewHead(t *testing.T) {
	p := newPages(t, map[string]string{"main/index.html": "two"})
	p.elsewhere(map[string]string{"v1.0.0/index.html": "release"})
	if out, ok := p.push(); !ok {
		t.Fatalf("the push failed: %s", out)
	}
	if got := p.published("main/index.html"); got != "two" {
		t.Errorf("the branch holds %q, want the built page", got)
	}
	if got := p.published("v1.0.0/index.html"); got != "release" {
		t.Errorf("the branch holds %q, want the other set kept", got)
	}
	if merges := p.git(p.remote, "rev-list", "--merges", "gh-pages"); merges != "" {
		t.Errorf("the branch holds merges %s, want a line", merges)
	}
}

func TestPagesThatConflictWithTheMovedBranchAreRefused(t *testing.T) {
	for _, c := range []struct {
		what        string
		built, gone map[string]string
		says        string
	}{
		{"one page written twice", map[string]string{"main/index.html": "two"},
			map[string]string{"main/index.html": "three"}, "do not apply on top of it"},
		// Two version lists merged by line can parse and still be wrong.
		{"the version list changed by both", map[string]string{"versions.json": "[\n{\"version\":\"main\"},\n{\"version\":\"v1\"}]"},
			map[string]string{"versions.json": "[\n{\"version\":\"v2\"},\n{\"version\":\"main\"}]"}, "both changed the version list"},
	} {
		t.Run(c.what, func(t *testing.T) {
			p := newPages(t, c.built)
			p.elsewhere(c.gone)
			before := p.git(p.remote, "rev-parse", "gh-pages")
			out, ok := p.push()
			if ok || !strings.Contains(out, c.says) {
				t.Errorf("a conflicting push answered %v: %s; want it refused saying %q", ok, out, c.says)
			}
			if after := p.git(p.remote, "rev-parse", "gh-pages"); after != before {
				t.Error("a refused push moved the branch")
			}
		})
	}
}

func TestPagesTheBranchAlreadyHoldsArePublished(t *testing.T) {
	p := newPages(t, map[string]string{"main/index.html": "two"})
	p.git(p.build, "push", "-q", "origin", "gh-pages")
	p.elsewhere(map[string]string{"v1.0.0/index.html": "release"})
	before := p.git(p.remote, "rev-parse", "gh-pages")
	if out, ok := p.push(); !ok {
		t.Fatalf("the push failed: %s", out)
	}
	if after := p.git(p.remote, "rev-parse", "gh-pages"); after != before {
		t.Error("pages the branch already held were pushed again")
	}
}
