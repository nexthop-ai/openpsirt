// attached refuses a doc comment describing something other than the
// declaration it sits on.
//
// Go's own convention is that a doc comment opens with the name of the thing
// it documents, which makes the drift mechanically visible: a comment opening
// "DefaultAttachmentMaxSize is …" above `const DefaultRoutingBatch` is a block
// that was left behind when its symbol moved. Nineteen of those arrived in one
// round of file splits and insertions, each of them making `godoc` render one
// symbol's documentation under another's name — and each invisible to every
// other check here, because the code is correct.
//
// Only the opening word is read, and only where it looks like a name this
// repository uses: a comment that opens with a sentence rather than a symbol
// is the ordinary case and is left alone, because the convention is a
// convention and this is a check for a specific accident.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// opens is a doc comment beginning with what looks like a Go identifier
// followed by a verb — the shape the convention produces.
var opens = regexp.MustCompile(`^(\w+) (is|are|reports|returns|says|holds|names|answers|builds|reads|writes|takes|does|makes|turns|gives|refuses|keeps|carries|counts|resolves|records|stands|walks|has|can|may|wraps|bounds|charges|fills|puts|sends|tells|asks|adds|applies|opens|closes|marks|moves|picks|shows|spells|states|works) `)

func main() {
	var bad []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "site", "dist", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		path = strings.TrimPrefix(path, "./")
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			// Not this program's business: the build says so, and better.
			return nil //nolint:nilerr // a file that does not parse is the compiler's to report
		}
		for _, decl := range file.Decls {
			doc, names := documented(decl)
			if doc == nil || len(names) == 0 {
				continue
			}
			first := strings.TrimSpace(doc.List[0].Text)
			first = strings.TrimPrefix(first, "//")
			match := opens.FindStringSubmatch(strings.TrimSpace(first))
			if match == nil {
				continue
			}
			named := match[1]
			if slicesContains(names, named) {
				continue
			}
			// A comment naming some other symbol entirely is the accident.
			// One naming nothing in this file is prose that happens to start
			// with a capitalized word, and is left alone.
			if !declaredIn(file, named) {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s:%d: the comment above %s describes %s",
				path, fset.Position(doc.Pos()).Line, strings.Join(names, ", "), named))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(bad) == 0 {
		fmt.Println("every doc comment sits on the declaration it describes")
		return
	}
	sort.Strings(bad)
	for _, one := range bad {
		fmt.Fprintln(os.Stderr, one)
	}
	fmt.Fprintf(os.Stderr, "\n%d doc comment(s) left on the wrong declaration. "+
		"Move the block, or delete it where it survives on the symbol it moved with.\n", len(bad))
	os.Exit(1)
}

// documented is a declaration's doc comment and the names it declares.
func documented(decl ast.Decl) (*ast.CommentGroup, []string) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return d.Doc, []string{d.Name.Name}
	case *ast.GenDecl:
		var names []string
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				names = append(names, s.Name.Name)
			case *ast.ValueSpec:
				for _, name := range s.Names {
					names = append(names, name.Name)
				}
			}
		}
		return d.Doc, names
	}
	return nil, nil
}

// declaredIn reports whether this file declares the name a comment opens with,
// which is what tells a stale block from ordinary prose.
func declaredIn(file *ast.File, name string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == name {
				found = true
			}
		case *ast.TypeSpec:
			if d.Name.Name == name {
				found = true
			}
		case *ast.ValueSpec:
			for _, one := range d.Names {
				if one.Name == name {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func slicesContains(all []string, want string) bool {
	for _, one := range all {
		if one == want {
			return true
		}
	}
	return false
}
