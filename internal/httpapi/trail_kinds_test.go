package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// TestEveryTrailKindIsOffered pins that the kinds an administrative change can
// have and the kinds a caller may filter by are the same set.
//
// Three places spell the list out as a struct tag, and a kind reaching the
// constants without reaching all three is one nothing can be filtered by. That
// fails as an empty screen rather than as an error, which is why it is checked
// here: the third copy was already one kind short of the other two when this
// was written.
func TestEveryTrailKindIsOffered(t *testing.T) {
	t.Parallel()

	declared := map[string]bool{}
	for _, kind := range trail.Kinds() {
		declared[string(kind)] = true
	}
	if len(declared) == 0 {
		t.Fatal("no kinds were found in the source, so this checked nothing")
	}

	tags := trailKindEnums(t)
	if len(tags) == 0 {
		t.Fatal("no enum tags over a trail kind were found, so this checked nothing")
	}

	for where, offered := range tags {
		offeredSet := map[string]bool{}
		for _, one := range offered {
			offeredSet[one] = true
			if !declared[one] {
				t.Errorf("%s offers %q, which no kind in the trail package declares", where, one)
			}
		}
		for one := range declared {
			if !offeredSet[one] {
				t.Errorf("%s does not offer %q, so nobody can filter by it", where, one)
			}
		}
	}
}

// trailKindEnums reads every enum tag on a field named Kind in this package,
// keyed by where it was found.
//
// Read from the source rather than from a value, because two of the three sit
// on a struct declared inside a function and no type of this package's own
// reaches them.
func trailKindEnums(t *testing.T) map[string][]string {
	t.Helper()

	found := map[string][]string{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok || field.Tag == nil || len(field.Names) != 1 || field.Names[0].Name != "Kind" {
				return true
			}
			raw, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				return true
			}
			offered := reflect.StructTag(raw).Get("enum")
			if offered == "" || !strings.Contains(offered, "setting") {
				return true
			}
			at := filepath.Join(name, strconv.Itoa(fset.Position(field.Pos()).Line))
			parts := strings.Split(offered, ",")
			sort.Strings(parts)
			found[at] = parts
			return true
		})
	}
	return found
}
