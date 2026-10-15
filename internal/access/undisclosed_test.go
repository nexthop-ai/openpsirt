// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// orderedOverVisibility matches the smallest or largest visibility word taken
// over a group, which answers "is any of this undisclosed" only while the
// words happen to sort that way.
//
// The column may be qualified or not, and either part quoted or not.
var orderedOverVisibility = regexp.MustCompile(`(?i)\b(MIN|MAX)\s*\(\s*(?:"?[a-z_]+"?\.)?"?visibility"?\s*\)`)

// visibilityOrderedOver is every line of Go source taking the smallest or
// largest visibility word over a group, as "file:line".
func visibilityOrderedOver(name, source string) []string {
	var found []string
	for i, line := range strings.Split(source, "\n") {
		if orderedOverVisibility.MatchString(line) {
			found = append(found, name+":"+strconv.Itoa(i+1))
		}
	}
	return found
}

func TestTheDetectorFindsAVisibilityWordOrderedOver(t *testing.T) {
	if got := visibilityOrderedOver("a.go", "x\nColumnExpr(`MIN(f.visibility) AS \"v\"`)"); len(got) != 1 || got[0] != "a.go:2" {
		t.Errorf("a minimum over the visibility word was reported as %v", got)
	}
	for _, spelling := range []string{
		`MIN("f"."visibility")`,
		`max(visibility)`,
		`MAX("visibility")`,
		`MIN(f."visibility")`,
	} {
		if got := visibilityOrderedOver("c.go", spelling); len(got) != 1 {
			t.Errorf("%s was not reported", spelling)
		}
	}
	expr, _ := access.AnyPrivate(`"f"."visibility"`)
	if got := visibilityOrderedOver("b.go", expr); len(got) != 0 {
		t.Errorf("the one spelling was reported as %v", got)
	}
}

func TestWhetherAnyRowIsUndisclosedIsNeverAskedByOrderingTheWords(t *testing.T) {
	// "private" sorts before "public", so a minimum over the word answers the
	// question by alphabetical accident; a third visibility, or a renamed
	// one, would make a mixed group read as disclosed in exactly the places
	// that decide whether an outbound message may name the issue.
	//
	// The whole module is read, so a query under cmd/ is held to it too.
	root := filepath.Join("..", "..")
	examined := 0
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", ".git", ".claude":
				// Somebody else's source, and copies of this tree.
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path) //nolint:gosec // G304: this repository's own source
		if err != nil {
			return err
		}
		examined++
		found = append(found, visibilityOrderedOver(path, string(source))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if examined == 0 {
		t.Fatal("no Go source was found, so this checked nothing")
	}
	for _, at := range found {
		t.Errorf("%s orders the visibility word; ask access.AnyPrivate instead", at)
	}
}

func TestAPrivateCountIsAskedOnlyOfAVisibilityColumn(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a column that is not a visibility was accepted into the statement")
		}
	}()
	access.PrivateCount("f.visibility; DROP TABLE finding")
}

func TestAPrivateCountIsSelectedOnlyUnderAPlainName(t *testing.T) {
	for name, ask := range map[string]func(){
		"PrivateCountAs": func() { access.PrivateCountAs(`"f"."visibility"`, `x", "y`) },
		"AnyPrivateAs":   func() { access.AnyPrivateAs(`"f"."visibility"`, `x", "y`) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("a name that closes its quotes was accepted into the statement")
				}
			}()
			ask()
		})
	}
	if expr, _ := access.PrivateCountAs(`"f"."visibility"`, "private_rows"); !strings.HasSuffix(expr, ` AS "private_rows"`) {
		t.Errorf("a plain name was selected as %s", expr)
	}
}
