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
// Only the opening word is read, and only where it names a symbol this
// repository declares: a comment that opens with a sentence rather than a
// symbol is the ordinary case and is left alone, because the convention is a
// convention and this is a check for a specific accident.
//
// A symbol's kind is decided over the package rather than over the file in
// hand. Read per file, the check could not see the very accident it is for —
// a block left behind when its symbol moved to another file names something
// the file it sits in does not declare, so the same-file test read it as
// prose and passed it, and file splits are where these come from.
//
// The package rather than the whole tree, which was measured: against every
// name the tree declares, the check reports forty-three comments and about
// forty of them are English. "Default", "Reading", "Two", "Only", "Scope" and
// "Set" are all symbols somewhere, and a comment here opening with one of
// them is a sentence. A check that fires on prose is a check people learn to
// ignore, so the question asked is whether the comment names something its
// own package declares.
//
// The opening is any declared name followed by any word, rather than a name
// followed by one of a list of verbs. Go's convention puts no constraint on
// the verb, and a list of them leaves every comment opening with a verb
// nobody thought of unread.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// opens is a doc comment beginning with an identifier followed by a word —
// the shape the convention produces. Whether the identifier is a symbol is
// asked of the tree rather than of the expression.
var opens = regexp.MustCompile(`^(\w+) (\w)`)

func main() {
	// web holds the interface, which is TypeScript: nothing under it parses
	// as Go, so reading it is work with no answer.
	const skip = "web"

	// Every name each package declares, read first, because a comment left
	// behind by a symbol that moved names something its own file no longer
	// declares.
	declared := map[string]map[string]bool{}
	if _, err := walk.Only(".go", []string{skip}, func(path string, source []byte) error {
		where := filepath.Dir(path)
		if declared[where] == nil {
			declared[where] = map[string]bool{}
		}
		declares(source, declared[where])
		return nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var bad []string
	read, err := walk.Only(".go", []string{skip}, func(path string, source []byte) error {
		bad = append(bad, detached(path, source, declared[filepath.Dir(path)])...)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(bad) == 0 {
		fmt.Printf("every doc comment sits on the declaration it describes (%d files)\n", read)
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

// detached reports every doc comment in one file that sits on a declaration it
// does not describe.
//
// Lifted out of the walk so that it can be asked a question. A gate whose
// detection is reachable only by running the program over the tree is one
// whose only consumer is an exit code, and an exit code cannot tell a check
// that found nothing from a check that looked at nothing.
func detached(path string, source []byte, declared map[string]bool) []string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.ParseComments)
	if err != nil {
		// Not this program's business: the build says so, and better.
		return nil
	}
	var bad []string
	for _, block := range documented(file) {
		first := strings.TrimSpace(block.doc.List[0].Text)
		first = strings.TrimPrefix(first, "//")
		match := opens.FindStringSubmatch(strings.TrimSpace(first))
		if match == nil {
			continue
		}
		named := match[1]
		if slicesContains(block.names, named) {
			continue
		}
		// A test's own name is a sentence rather than a symbol, so the
		// convention does not apply to it and its comment opens with whatever
		// the test is about — usually the symbol under test, which is exactly
		// what this looks for. Every one of them is prose.
		if aTest(block.names) {
			continue
		}
		// A comment naming some other symbol entirely is the accident. One
		// naming nothing the tree declares is prose that happens to open with
		// a word, and is left alone.
		if !declared[named] {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s:%d: the comment above %s describes %s",
			path, fset.Position(block.doc.Pos()).Line, strings.Join(block.names, ", "), named))
	}
	bad = append(bad, glued(path, fset, file, declared)...)
	bad = append(bad, floating(path, fset, file, declared)...)
	return bad
}

// glued reports a doc comment that is two blocks with no blank line between
// them, so Go hands both to the second one's declaration.
//
// The shape a block left behind takes once somebody corrects its opening word
// to match: the first paragraph documents something else and reads as this
// declaration's, and godoc renders both under one name. It is found by the
// declaration's own name opening a line that is not the first — the real doc
// starting part way down means everything above it belongs to somebody else.
func glued(path string, fset *token.FileSet, file *ast.File,
	declared map[string]bool) []string {
	var bad []string
	for _, block := range documented(file) {
		// Only where the block above is itself somebody's doc comment, which
		// is what makes this two blocks rather than one. A run of constants
		// introduced by a paragraph about the run is the ordinary shape here,
		// and its opening names no symbol.
		opening := strings.TrimSpace(strings.TrimPrefix(
			strings.TrimSpace(block.doc.List[0].Text), "//"))
		if head := opens.FindStringSubmatch(opening); head == nil || !declared[head[1]] {
			continue
		}
		for i, line := range block.doc.List {
			if i == 0 {
				continue
			}
			// Only where the line before it ended something. A doc comment
			// wraps, and a wrapped line beginning with the symbol's own name
			// mid-sentence is ordinary prose — "the published\n// score where
			// there is not" is not a second block.
			before := strings.TrimSpace(strings.TrimPrefix(
				strings.TrimSpace(block.doc.List[i-1].Text), "//"))
			if before != "" && !strings.HasSuffix(before, ".") {
				continue
			}
			text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line.Text), "//"))
			match := opens.FindStringSubmatch(text)
			if match == nil || !slicesContains(block.names, match[1]) {
				continue
			}
			bad = append(bad, fmt.Sprintf(
				"%s:%d: the doc for %s starts part way down its own comment, so the block "+
					"above it is somebody else's", path, fset.Position(line.Pos()).Line,
				strings.Join(block.names, ", ")))
			break
		}
	}
	return bad
}

// floating reports a comment block at file scope that Go attaches to nothing.
//
// A block separated from the declaration it describes by another comment block
// is not a doc comment at all: godoc shows it nowhere, and the declaration it
// was written for has none. The block reads as documentation to anybody
// looking at the file, which is why it survives file splits and insertions.
//
// Only blocks opening with a name the package declares are reported, for the
// reason the check above reads only that: a paragraph of prose between two
// declarations is an ordinary thing to write.
func floating(path string, fset *token.FileSet, file *ast.File,
	declared map[string]bool) []string {

	// Every group the tree hands to something: a declaration, a struct field,
	// an interface method. A field's comment is documentation of that field
	// and is not floating, and reading only declaration docs made every one
	// of them a report.
	attached := map[*ast.CommentGroup]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.Field:
			attached[n.Doc], attached[n.Comment] = true, true
		case *ast.FuncDecl:
			attached[n.Doc] = true
		case *ast.GenDecl:
			attached[n.Doc] = true
		case *ast.TypeSpec:
			attached[n.Doc], attached[n.Comment] = true, true
		case *ast.ValueSpec:
			attached[n.Doc], attached[n.Comment] = true, true
		case *ast.ImportSpec:
			attached[n.Doc], attached[n.Comment] = true, true
		}
		return true
	})
	// Everything inside a function body, which is where an ordinary comment
	// lives and where none of this applies.
	var bodies []*ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			bodies = append(bodies, fn.Body)
		}
	}
	inside := func(at token.Pos) bool {
		for _, body := range bodies {
			if at > body.Pos() && at < body.End() {
				return true
			}
		}
		return false
	}

	// A file header, which this tree writes as a block between the package
	// clause and the imports. It belongs to the file rather than to any
	// declaration, and it opens by naming what the file is about — which is
	// usually a symbol the file declares. The imports are what tell it from a
	// block left floating above a declaration: nothing is documented by a
	// comment that an import list follows.
	var header token.Pos
	if len(file.Decls) > 0 {
		if imports, ok := file.Decls[0].(*ast.GenDecl); ok && imports.Tok == token.IMPORT {
			header = imports.Pos()
		}
	}

	var bad []string
	for _, group := range file.Comments {
		if attached[group] || group == file.Doc || inside(group.Pos()) {
			continue
		}
		if group.Pos() < header {
			continue
		}
		first := strings.TrimSpace(strings.TrimPrefix(
			strings.TrimSpace(group.List[0].Text), "//"))
		match := opens.FindStringSubmatch(first)
		if match == nil || !declared[match[1]] {
			continue
		}
		bad = append(bad, fmt.Sprintf(
			"%s:%d: the comment about %s is attached to nothing, so %s has none",
			path, fset.Position(group.Pos()).Line, match[1], match[1]))
	}
	return bad
}

// aTest says whether a declaration is one the testing package runs.
func aTest(names []string) bool {
	for _, name := range names {
		for _, prefix := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	}
	return false
}

// block is one doc comment and the names the declaration under it declares.
type block struct {
	doc   *ast.CommentGroup
	names []string
}

// documented is every doc comment in a file with what it sits on.
//
// A spec inside a grouped declaration carries its own doc comment, and reading
// only the group's left every comment inside a const or var block unread —
// which is where a good part of this tree's documentation is.
func documented(file *ast.File) []block {
	var blocks []block
	keep := func(doc *ast.CommentGroup, names ...string) {
		if doc != nil && len(doc.List) > 0 && len(names) > 0 {
			blocks = append(blocks, block{doc: doc, names: names})
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			keep(d.Doc, d.Name.Name)
		case *ast.GenDecl:
			var all []string
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					all = append(all, s.Name.Name)
					keep(s.Doc, s.Name.Name)
				case *ast.ValueSpec:
					var named []string
					for _, name := range s.Names {
						named = append(named, name.Name)
					}
					all = append(all, named...)
					keep(s.Doc, named...)
				}
			}
			keep(d.Doc, all...)
		}
	}
	return blocks
}

// declares adds every name one file declares at package level to the set.
//
// Package level only. A local variable and a struct field are named for what
// they hold in one function or one record, and half the ordinary English
// words in this tree are one of those somewhere — reading them as symbols is
// what turns the check into noise.
func declares(source []byte, into map[string]bool) {
	file, err := parser.ParseFile(token.NewFileSet(), "", source, parser.SkipObjectResolution)
	if err != nil {
		return
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			into[d.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					into[s.Name.Name] = true
				case *ast.ValueSpec:
					for _, one := range s.Names {
						into[one.Name] = true
					}
				}
			}
		}
	}
}

func slicesContains(all []string, want string) bool {
	for _, one := range all {
		if one == want {
			return true
		}
	}
	return false
}
