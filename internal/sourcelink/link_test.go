// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sourcelink

import (
	"strings"
	"testing"
)

const (
	top = "0123456789abcdef0123456789abcdef01234567"
	sai = "fedcba9876543210fedcba9876543210fedcba98"
)

// hosted is a product linking GitHub, a GitLab of its own, and a mirror of
// GitHub that its builds check out from.
func hosted(t *testing.T) Config {
	t.Helper()
	c := Config{Hosts: []Host{
		{Remote: "github.com", Web: "https://github.com", Style: GitHub},
		{Remote: "gitlab.example.com", Web: "https://gitlab.example.com/", Style: GitLab},
		{Remote: "git.example.com/mirror/github", Web: "https://github.com", Style: GitHub},
		{Remote: "forge.example.com", Web: "https://forge.example.com", Style: Gitea},
	}}
	if err := c.Valid(); err != nil {
		t.Fatal(err)
	}
	return c
}

// checkout is sonic-buildimage holding SAI two submodules deep and swss by a
// relative remote.
var checkout = []Module{
	{Path: "", Remote: "https://github.com/sonic-net/sonic-buildimage.git", Revision: top},
	{Path: "src/sonic-sairedis", Remote: "../sonic-sairedis.git", Revision: top},
	{Path: "src/sonic-sairedis/SAI", Remote: "git@github.com:opencomputeproject/SAI.git", Revision: sai, Changed: true},
	{Path: "src/sonic-frr/frr", Remote: "https://git.example.com/mirror/github/FRRouting/frr", Revision: sai},
	{Path: "src/private", Remote: "https://gitlab.example.com/net/private.git", Revision: top},
	{Path: "src/forged", Remote: "https://forge.example.com/net/forged", Revision: top},
	{Path: "src/elsewhere", Remote: "https://code.example.org/x/y", Revision: top},
	{Path: "src/branch", Remote: "https://github.com/x/branch", Revision: "master"},
}

func TestALocationLinksIntoTheInnermostRepositoryHoldingIt(t *testing.T) {
	got := hosted(t).File(checkout, "src/sonic-sairedis/SAI/inc/saiport.h", 10, 12)
	want := "https://github.com/opencomputeproject/SAI/blob/" + sai + "/inc/saiport.h#L10-L12"
	if got.URL != want || got.Within != "inc/saiport.h" || got.Revision != sai {
		t.Errorf("linked %+v; want %s", got, want)
	}
	if !got.Patched || got.Approximate {
		t.Errorf("patched %v, approximate %v; want a repository patched at build time, linked exactly", got.Patched, got.Approximate)
	}
}

func TestARelativeRemoteLinksIntoTheRepositoryItNames(t *testing.T) {
	got := hosted(t).File(checkout, "src/sonic-sairedis/lib/a.cpp", 3, 3)
	if want := "https://github.com/sonic-net/sonic-sairedis/blob/" + top + "/lib/a.cpp#L3-L3"; got.URL != want {
		t.Errorf("linked %q; want %q", got.URL, want)
	}
}

func TestAMirroredRemoteLinksToTheHostItMirrors(t *testing.T) {
	got := hosted(t).File(checkout, "src/sonic-frr/frr/bgpd/bgp_attr.c", 40, 0)
	if want := "https://github.com/FRRouting/frr/blob/" + sai + "/bgpd/bgp_attr.c#L40-L40"; got.URL != want {
		t.Errorf("linked %q; want %q", got.URL, want)
	}
}

func TestEachKnownServerWritesItsOwnAddress(t *testing.T) {
	c := hosted(t)
	for path, want := range map[string]string{
		"src/private/a.c": "https://gitlab.example.com/net/private/-/blob/" + top + "/a.c#L5-7",
		"src/forged/a.c":  "https://forge.example.com/net/forged/src/commit/" + top + "/a.c#L5-L7",
	} {
		if got := c.File(checkout, path, 5, 7); got.URL != want {
			t.Errorf("%s linked %q; want %q", path, got.URL, want)
		}
	}
}

func TestACustomHostWritesItsTemplate(t *testing.T) {
	c := Config{Hosts: []Host{{Remote: "code.example.org", Web: "https://code.example.org", Style: Custom,
		FileTemplate: "{repo}/view/{commit}/{path}?line={start}", CompareTemplate: "{repo}/diff/{from}/{to}"}}}
	if err := c.Valid(); err != nil {
		t.Fatal(err)
	}
	if got := c.File(checkout, "src/elsewhere/z.go", 9, 9); got.URL != "https://code.example.org/x/y/view/"+top+"/z.go?line=9" {
		t.Errorf("linked %q", got.URL)
	}
}

func TestARepositoryOnNoNamedHostIsShownAsText(t *testing.T) {
	got := hosted(t).File(checkout, "src/elsewhere/z.go", 1, 1)
	if got.URL != "" || got.Unlinked != NoHost || got.Repository != "https://code.example.org/x/y" {
		t.Errorf("linked %+v; want the remote as text", got)
	}
}

func TestARemoteShownAsTextCarriesNoCredential(t *testing.T) {
	modules := []Module{{Path: "", Remote: "https://ci-token:SECRET@code.example.org/x/y.git?private_token=SECRET", Revision: top}} //nolint:gosec // G101: a placeholder credential to be removed
	got := hosted(t).File(modules, "z.go", 1, 1)
	if got.Unlinked != NoHost || got.Repository != "https://code.example.org/x/y.git" {
		t.Errorf("linked %+v; want the remote without its credential", got)
	}
}

func TestARevisionThatIsNotACommitIsShownUnlinked(t *testing.T) {
	if got := hosted(t).File(checkout, "src/branch/a.c", 1, 1); got.URL != "" || got.Unlinked != NotACommit {
		t.Errorf("linked %+v; want no link to a branch the upload named", got)
	}
}

func TestAPathIsEscapedSoNothingInItSteersTheLink(t *testing.T) {
	got := hosted(t).File(checkout, "src/forged/what?is#this %.c", 1, 1)
	if !strings.Contains(got.URL, "/what%3Fis%23this%20%25.c#L1") {
		t.Errorf("linked %q; want each segment encoded", got.URL)
	}
	if got := hosted(t).File(checkout, "src/forged/../../etc/passwd", 1, 1); got.URL != "" || got.Unlinked != NotAPath {
		t.Errorf("linked %+v; want a climbing path unlinked", got)
	}
}

func TestALocationWithNoLineOpensTheFile(t *testing.T) {
	if got := hosted(t).File(checkout, "src/forged/a.c", 0, 0); strings.Contains(got.URL, "#") {
		t.Errorf("linked %q; want no line fragment", got.URL)
	}
}

func TestAPathNoUploadNamesLinksApproximatelyToTheBranchAProductNames(t *testing.T) {
	c := hosted(t)
	c.Paths = []Path{{Prefix: "src/sonic-swss", Remote: "https://github.com/sonic-net/sonic-swss", Branch: "release/202605"}}
	if err := c.Valid(); err != nil {
		t.Fatal(err)
	}
	got := c.File(nil, "src/sonic-swss/orchagent/orch.cpp", 12, 12)
	want := "https://github.com/sonic-net/sonic-swss/blob/release/202605/orchagent/orch.cpp#L12-L12"
	if got.URL != want || !got.Approximate {
		t.Errorf("linked %+v; want %s, approximate", got, want)
	}
	if got := c.File(nil, "src/other/a.c", 1, 1); got.Unlinked != NoRepository {
		t.Errorf("linked %+v; want no repository known", got)
	}
}

func TestTwoBuildsOfOneRepositoryCompareTheirCommits(t *testing.T) {
	c := hosted(t)
	after := append([]Module(nil), checkout...)
	after[2].Revision = top
	address, unchanged := c.Compare(checkout, after, "src/sonic-sairedis/SAI/inc/saiport.h")
	if want := "https://github.com/opencomputeproject/SAI/compare/" + sai + "..." + top; address != want || unchanged {
		t.Errorf("compared %q, unchanged %v; want %q", address, unchanged, want)
	}
	address, unchanged = c.Compare(checkout, checkout, "src/sonic-frr/frr/bgpd/a.c")
	if address != "" || !unchanged {
		t.Errorf("compared %q, unchanged %v; want the same commit said so", address, unchanged)
	}
}

// SAI is patched at build time in the checkout, so its commit alone does not
// say what was analyzed.
func TestTheSameCommitPatchedOnEitherSideIsNotUnchanged(t *testing.T) {
	c := hosted(t)
	clean := append([]Module(nil), checkout...)
	clean[2].Changed = false
	for name, runs := range map[string][2][]Module{
		"patched before":  {checkout, clean},
		"patched after":   {clean, checkout},
		"patched in both": {checkout, checkout},
	} {
		if address, unchanged := c.Compare(runs[0], runs[1], "src/sonic-sairedis/SAI/inc/saiport.h"); address != "" || unchanged {
			t.Errorf("%s: compared %q, unchanged %v; want neither", name, address, unchanged)
		}
	}
	if _, unchanged := c.Compare(clean, clean, "src/sonic-sairedis/SAI/inc/saiport.h"); !unchanged {
		t.Errorf("the same commit unpatched in both is not unchanged")
	}
}

func TestTheNearestPrefixStatingItDecidesWhetherSnippetsAreKept(t *testing.T) {
	yes, no := true, false
	c := Config{Paths: []Path{
		{Prefix: "", Snippets: &no},
		{Prefix: "src/sonic-frr", Snippets: &yes},
		{Prefix: "src/sonic-frr/private", Snippets: &no},
		{Prefix: "src/sonic-frr/private/named", Remote: "https://github.com/a/b", Branch: "main"},
	}}
	if err := c.Valid(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"README":                          false,
		"src/sonic-frr/bgpd/a.c":          true,
		"src/sonic-frr/private/named/x.c": false,
		"src/sonic-frrouting/a.c":         false,
	} {
		if got := c.Snippets(path); got != want {
			t.Errorf("%s keeps snippets %v; want %v", path, got, want)
		}
	}
	if (Config{}).Snippets("a.c") {
		t.Errorf("a product saying nothing keeps snippets")
	}
}

func TestAConfigurationThatCannotBeUsedIsRefusedNamingTheEntry(t *testing.T) {
	yes := true
	for name, c := range map[string]Config{
		"plain http":       {Hosts: []Host{{Remote: "github.com", Web: "http://github.com", Style: GitHub}}},
		"a credential":     {Hosts: []Host{{Remote: "github.com", Web: "https://u:p@github.com", Style: GitHub}}}, //nolint:gosec // G101: a placeholder credential the check refuses
		"no remote":        {Hosts: []Host{{Web: "https://github.com", Style: GitHub}}},
		"twice":            {Hosts: []Host{{Remote: "github.com", Web: "https://github.com", Style: GitHub}, {Remote: "GitHub.com/", Web: "https://github.com", Style: GitHub}}},
		"unknown style":    {Hosts: []Host{{Remote: "github.com", Web: "https://github.com", Style: "svn"}}},
		"another host":     {Hosts: []Host{{Remote: "a.example", Web: "https://a.example", Style: Custom, FileTemplate: "https://evil.example/{path}"}}},
		"a placeholder":    {Hosts: []Host{{Remote: "a.example", Web: "https://a.example", Style: Custom, FileTemplate: "{repo}/{secret}"}}},
		"a compare one":    {Hosts: []Host{{Remote: "a.example", Web: "https://a.example", Style: Custom, FileTemplate: "{repo}/{path}", CompareTemplate: "{repo}/{path}"}}},
		"climbing":         {Paths: []Path{{Prefix: "src/../..", Snippets: &yes}}},
		"half a repo":      {Paths: []Path{{Prefix: "src", Remote: "https://github.com/a/b"}}},
		"nothing said":     {Paths: []Path{{Prefix: "src"}}},
		"not a repository": {Paths: []Path{{Prefix: "src", Remote: "github.com", Branch: "main"}}},
		"not a branch":     {Paths: []Path{{Prefix: "src", Remote: "https://github.com/a/b", Branch: "a b"}}},
		"a path twice":     {Paths: []Path{{Prefix: "src", Snippets: &yes}, {Prefix: "/src/", Snippets: &yes}}},
	} {
		if err := c.Valid(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAComparisonNeedsAnExactCommitOnEachSideOfOneRepository(t *testing.T) {
	c := hosted(t)
	c.Paths = []Path{{Prefix: "src/approximate", Remote: "https://github.com/a/b", Branch: "main"}}
	if err := c.Valid(); err != nil {
		t.Fatal(err)
	}
	moved := append([]Module(nil), checkout...)
	moved[2].Path = "src/sonic-sairedis/SAI/inc"
	for name, c2 := range map[string]struct {
		before, after []Module
		path          string
	}{
		"a branch, not a commit": {checkout, checkout, "src/branch/a.c"},
		"approximate":            {nil, nil, "src/approximate/a.c"},
		"another repository":     {checkout, moved, "src/sonic-sairedis/SAI/inc/saiport.h"},
		"no repository after":    {checkout, nil, "src/forged/a.c"},
		"a host with no compare": {checkout, checkout[:1], "src/elsewhere/a.c"},
	} {
		if address, unchanged := c.Compare(c2.before, c2.after, c2.path); address != "" || unchanged {
			t.Errorf("%s: compared %q, unchanged %v; want neither", name, address, unchanged)
		}
	}
}

func TestARulesDocumentationIsKeptOnlyOnAnAnalyzersHost(t *testing.T) {
	for address, want := range map[string]string{
		"https://clang.llvm.org/docs/analyzer/checkers.html#unix-malloc": "https://clang.llvm.org/docs/analyzer/checkers.html#unix-malloc",
		"https://CodeQL.GitHub.com/codeql-query-help/cpp/cpp-overflow/":  "https://CodeQL.GitHub.com/codeql-query-help/cpp/cpp-overflow/",
		"http://clang.llvm.org/docs/analyzer/checkers.html":              "",
		"https://user@clang.llvm.org/docs":                               "",
		"https://clang.llvm.org:8443/docs":                               "",
		"https://evil.example/clang.llvm.org":                            "",
		"javascript:alert(1)":                                            "",
		"":                                                               "",
	} {
		if got := Documentation(address); got != want {
			t.Errorf("%q kept as %q; want %q", address, got, want)
		}
	}
}
