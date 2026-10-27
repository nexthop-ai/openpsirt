// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestARemoteBecomesTheWebAddressOfItsRepository(t *testing.T) {
	for in, want := range map[string]string{ //nolint:gosec // G101: example remotes, one carrying a placeholder credential to be removed
		"https://github.com/sonic-net/sonic-buildimage.git":              "https://github.com/sonic-net/sonic-buildimage",
		"git@github.com:sonic-net/sonic-swss.git":                        "https://github.com/sonic-net/sonic-swss",
		"ssh://git@gitlab.example.com:2222/net/frr.git":                  "https://gitlab.example.com/net/frr",
		"https://x-access-token:ghs_secret@github.com/org/private.git":   "https://github.com/org/private",
		"https://GitHub.com/opencomputeproject/SAI/":                     "https://github.com/opencomputeproject/SAI",
		"git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux",
		"gitea.example.com:org/repo":                                     "https://gitea.example.com/org/repo",
		"/srv/mirrors/frr.git":                                           "",
		"file:///srv/mirrors/frr.git":                                    "",
		"C:/mirrors/frr":                                                 "",
		"":                                                               "",
	} {
		if got := webAddress(in); got != want {
			t.Errorf("%q: %q; want %q", in, got, want)
		}
	}
}

func TestARelativeAddressResolvesAgainstItsParents(t *testing.T) {
	for _, c := range []struct{ parent, address, want string }{
		{"https://github.com/sonic-net/sonic-buildimage.git", "../sonic-swss.git", "https://github.com/sonic-net/sonic-swss.git"},
		{"https://github.com/sonic-net/sonic-buildimage", "./sub", "https://github.com/sonic-net/sonic-buildimage/sub"},
		{"git@github.com:sonic-net/sonic-buildimage.git", "../sonic-sairedis.git", "git@github.com:sonic-net/sonic-sairedis.git"},
		{"https://github.com/opencomputeproject/sairedis", "../../opencomputeproject/SAI.git", "https://github.com/opencomputeproject/SAI.git"},
		{"", "../orphan.git", ""},
	} {
		if got := resolveRelative(c.parent, c.address); got != c.want {
			t.Errorf("%q from %q: %q; want %q", c.address, c.parent, got, c.want)
		}
	}
}

// gitRepo makes a repository holding one committed file, with origin set to
// remote.
func gitRepo(t *testing.T, dir, remote string) {
	t.Helper()
	runIn(t, dir, "init", "-q", "-b", "main")
	runIn(t, dir, "config", "user.email", "builder@example.com")
	runIn(t, dir, "config", "user.name", "Builder")
	if err := os.WriteFile(filepath.Join(dir, "file.c"), []byte("int x;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runIn(t, dir, "add", "file.c")
	runIn(t, dir, "commit", "-q", "-m", "first")
	if remote != "" {
		runIn(t, dir, "remote", "add", "origin", remote)
	}
}

func runIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "protocol.file.allow=always"}, args...)...) //nolint:gosec // G204: the test's own arguments
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestEveryRepositoryTheCheckoutHoldsIsListed builds a checkout holding a
// submodule that holds one of its own, each declared by an address relative
// to its parent's, as sonic-buildimage declares its own.
func TestEveryRepositoryTheCheckoutHoldsIsListed(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	base := t.TempDir()
	sai := filepath.Join(base, "SAI.git")
	sairedis := filepath.Join(base, "sonic-sairedis.git")
	top := filepath.Join(base, "sonic-buildimage")
	for _, d := range []string{sai, sairedis, top} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	gitRepo(t, sai, "")
	gitRepo(t, sairedis, "")
	runIn(t, sairedis, "submodule", "add", "-q", sai, "SAI")
	runIn(t, sairedis, "config", "--file", ".gitmodules", "submodule.SAI.url", "../SAI.git")
	runIn(t, sairedis, "commit", "-q", "-am", "pin SAI")
	gitRepo(t, top, "git@github.com:sonic-net/sonic-buildimage.git")
	runIn(t, top, "submodule", "add", "-q", sairedis, "src/sonic-sairedis")
	runIn(t, top, "config", "--file", ".gitmodules", "submodule.src/sonic-sairedis.url", "../sonic-sairedis.git")
	runIn(t, top, "commit", "-q", "-am", "pin sairedis")
	runIn(t, filepath.Join(top, "src", "sonic-sairedis"), "submodule", "update", "-q", "--init")
	// The build patches the submodule it holds.
	if err := os.WriteFile(filepath.Join(top, "src", "sonic-sairedis", "SAI", "file.c"), []byte("int y;\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := repositories(context.Background(), runGit, top, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i].Commit = map[bool]string{true: "a commit", false: ""}[len(got[i].Commit) == 40]
	}
	want := []repository{
		{Path: "", Remote: "https://github.com/sonic-net/sonic-buildimage", Commit: "a commit"},
		{Path: "src/sonic-sairedis", Remote: "https://github.com/sonic-net/sonic-sairedis", Commit: "a commit"},
		{Path: "src/sonic-sairedis/SAI", Remote: "https://github.com/sonic-net/SAI", Commit: "a commit", Changed: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("repositories\n %+v\nwant\n %+v", got, want)
	}

	paths, err := indexed(context.Background(), runGit, top)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(paths, "src/sonic-sairedis/SAI/file.c") {
		t.Errorf("index %v; want the files of every submodule", paths)
	}
}

func TestASubmoduleWhosePathHoldsASpaceIsListed(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	base := t.TempDir()
	inner := filepath.Join(base, "inner.git")
	top := filepath.Join(base, "top")
	for _, d := range []string{inner, top} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	gitRepo(t, inner, "")
	runIn(t, inner, "tag", "v1")
	gitRepo(t, top, "https://github.com/example/top.git")
	runIn(t, top, "submodule", "add", "-q", inner, "third party/inner")
	runIn(t, top, "config", "--file", ".gitmodules", "submodule.third party/inner.url", "https://github.com/example/inner.git")
	runIn(t, top, "commit", "-q", "-am", "pin inner")

	got, err := repositories(context.Background(), runGit, top, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Path != "third party/inner" || got[1].Remote != "https://github.com/example/inner" ||
		len(got[1].Commit) != 40 {
		t.Errorf("repositories %+v; want the submodule at its whole path", got)
	}
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}
