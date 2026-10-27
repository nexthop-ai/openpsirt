// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"os"
	"path/filepath"
	"testing"
)

// The fingerprint of one function's lines, whatever line endings and
// indentation the checkout gives them. Worked out by hand from the
// normalized lines, never by this code: a change to the normalization fails
// here before it reopens every lead a pipeline has.
const (
	// Line 2, `int d = 0;`, with the line either side.
	goldenLine2 = "6068ce7eef28160d5cc6621d43275dc90f180092a1e663de9eb2a68e31fa5ee8"
	// Line 3, `return x / d;`, with the line either side.
	goldenLine3 = "182cf06841a03d90014c4fd82f16c03843b9a44c82cc507bbcbdd87c796b536f"
)

func TestOneCheckoutFingerprintsAlikeOnEverySystem(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("testdata", "endings"))
	if err != nil {
		t.Fatal(err)
	}
	src := &source{root: root, files: map[string][]string{}}
	for _, file := range []string{"lf.c", "crlf.c", "auto.c"} {
		if got := src.contextPrint(file, 2); got != goldenLine2 {
			t.Errorf("%s line 2: %s; want %s", file, got, goldenLine2)
		}
		if got := src.contextPrint(file, 3); got != goldenLine3 {
			t.Errorf("%s line 3: %s; want %s", file, got, goldenLine3)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "crlf.c")) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	// The pair is only a test of line endings while the checkout keeps one
	// of them as it was committed.
	if !containsCR(data) {
		t.Fatal("crlf.c was checked out without its carriage returns; its attributes are not in force")
	}
}

func containsCR(b []byte) bool {
	for _, c := range b {
		if c == '\r' {
			return true
		}
	}
	return false
}

func TestASnippetCarriesNoCarriageReturn(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("testdata", "endings"))
	if err != nil {
		t.Fatal(err)
	}
	src := &source{root: root, files: map[string][]string{}}
	loc := obj{"physicalLocation": obj{
		"artifactLocation": obj{"uri": "crlf.c", "uriBaseId": rootBase},
		"region":           obj{"startLine": 3},
	}}
	src.snippets(loc)
	physical := child(loc, "physicalLocation")
	if got := str(child(child(physical, "region"), "snippet"), "text"); got != "    return x / d;" {
		t.Errorf("snippet %q", got)
	}
	if got := str(child(child(physical, "contextRegion"), "snippet"), "text"); got != "int f(int x) {\n\tint d = 0;\n    return x / d;\n}" {
		t.Errorf("context %q", got)
	}
}

func TestALineOutsideTheFileHasNoFingerprint(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("testdata", "endings"))
	if err != nil {
		t.Fatal(err)
	}
	src := &source{root: root, files: map[string][]string{}}
	for _, line := range []int{0, 99} {
		if got := src.contextPrint("lf.c", line); got != "" {
			t.Errorf("line %d: %q; want none", line, got)
		}
	}
	if got := src.contextPrint("absent.c", 1); got != "" {
		t.Errorf("a file not in the checkout: %q; want none", got)
	}
}

func TestALinkOutOfTheCheckoutIsNotRead(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.c"), []byte("password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret.c"), filepath.Join(root, "linked.c")); err != nil {
		t.Skip("this system makes no symbolic link: ", err)
	}
	src := &source{root: root, files: map[string][]string{}}
	if got := src.lines("linked.c"); got != nil {
		t.Errorf("read %q through a link out of the checkout", got)
	}
}

func TestEveryPathIsPlacedTheSameWayOnEverySystem(t *testing.T) {
	unix := newPlacer("/home/builder/sonic", "/home/builder/sonic/build", []string{"src/Port.cpp", "a.c"})
	windows := newPlacer(`C:\builds\sonic`, `C:\builds\sonic`, []string{"src/Port.cpp"})
	bases := map[string]obj{
		"SRC":    {"uri": "file:///home/builder/sonic/src/"},
		"NESTED": {"uri": "inner/", "uriBaseId": "SRC"},
	}
	for _, c := range []struct {
		name      string
		at        *placer
		uri, base string
		where     placement
		want      string
	}{
		{"a file address", unix, "file:///home/builder/sonic/a.c", "", inside, "a.c"},
		{"a bare absolute path", unix, "/home/builder/sonic/SRC/port.CPP", "", inside, "src/Port.cpp"},
		{"relative to the working directory", unix, "../a.c", "", inside, "a.c"},
		{"the checkout's undefined name", unix, "src/Port.cpp", "SRCROOT", inside, "src/Port.cpp"},
		{"a chain of named points", unix, "x.c", "NESTED", inside, "src/inner/x.c"},
		{"a name left undefined", unix, "x.c", "ELSEWHERE", unplaced, ""},
		{"a system header", unix, "/usr/include/stdlib.h", "", outside, "/usr/include/stdlib.h"},
		{"a step out of the checkout", unix, "../../../etc/passwd", "SRCROOT", outside, "/etc/passwd"},
		{"a home directory beside the checkout", unix, "/home/builder/sonic-old/a.c", "", outside, "/home/builder/sonic-old/a.c"},
		{"a drive letter", windows, `C:\builds\sonic\src\Port.cpp`, "", inside, "src/Port.cpp"},
		{"a drive letter in another case", windows, `c:\Builds\Sonic\src\port.cpp`, "", inside, "src/Port.cpp"},
		{"a file address with a drive", windows, "file:///C:/builds/sonic/src/Port.cpp", "", inside, "src/Port.cpp"},
		{"another drive", windows, `D:\sdk\include\x.h`, "", outside, "D:/sdk/include/x.h"},
	} {
		where, got := c.at.place(c.uri, c.base, bases)
		if where != c.where || got != c.want {
			t.Errorf("%s: placed %d %q; want %d %q", c.name, where, got, c.where, c.want)
		}
	}
}

func TestAPathOutsideTheCheckoutIsWrittenAsTheAddressItIs(t *testing.T) {
	at := newPlacer(`C:\builds\sonic`, `C:\builds\sonic`, nil)
	art := obj{"uri": `D:\sdk\x.h`}
	at.rewrite(art, nil)
	if art["uri"] != "file:///D:/sdk/x.h" || art["uriBaseId"] != nil {
		t.Errorf("written %v", art)
	}
	inside := obj{"uri": `C:\builds\sonic\a b.c`, "uriBaseId": "SRCROOT"}
	at.rewrite(inside, nil)
	if inside["uri"] != "a%20b.c" || inside["uriBaseId"] != rootBase {
		t.Errorf("written %v", inside)
	}
}

func TestTwoIndexedPathsDifferingByCaseAreLeftAsTheToolWroteThem(t *testing.T) {
	at := newPlacer("/r", "/r", []string{"Makefile", "makefile"})
	if got := at.cased("MAKEFILE"); got != "MAKEFILE" {
		t.Errorf("cased %q; want it left", got)
	}
}
