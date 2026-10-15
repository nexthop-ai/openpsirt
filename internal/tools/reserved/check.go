// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// tablesDeclared adds the tables a migration file creates to schema.
func tablesDeclared(path string, body []byte, schema map[string]bool) {
	if !strings.Contains(path, "database/migrate/migrations/") {
		return
	}
	for _, match := range creating.FindAllStringSubmatch(string(body), -1) {
		schema[strings.ToLower(match[1])] = true
	}
}

// checkFile reports every name one parsed source file writes wrongly: a bare
// name a query invents, a bare table or declared column a query names, a
// reserved word a migration declares, and a reserved alias a struct tag
// declares. elsewhere is the names queries in the rest of the tree invent.
// It also answers how many pieces of SQL it read for columns, and
// how many literals of the code that runs it read for the qualified form.
func checkFile(fset *token.FileSet, path string, file *ast.File,
	schema, columns, reserved, elsewhere map[string]bool) (bad []found, examined, qualified int) {
	packages := importedNames(file)

	// The data-definition half. Read from the string literals in a migration
	// rather than from the file, because the prose beside them is full of the
	// same words — and with the SQL comments inside those strings taken off
	// first, for the same reason. It reads the migrations and not their tests:
	// every string in a migration is DDL, and a test beside them writes
	// English about what it declared — "the index's table reads as" is a
	// sentence, and read as a declaration it names a word two engines reserve.
	definitions := strings.Contains(path, "database/migrate/migrations/") &&
		!strings.HasSuffix(path, "_test.go")
	// Every SQL literal, wherever it is written. A pass of its own, and first,
	// so the walk below can tell whether a literal it reaches has already been
	// read as a statement in its own right — a node is visited before its
	// children, so one walk could not. Keyed by the literal's position, since
	// a line can carry a statement and a fragment that is not one.
	seen := map[token.Pos]bool{}
	// columnsRead is seen and every literal the qualified pass read, so a
	// column it reported is not reported again where the literal is used.
	columnsRead := map[token.Pos]bool{}
	quotedHere := quotedArguments(file)
	// The qualified form is read in the code that runs. A test is where a
	// detector is handed the bare spellings it exists to find.
	production := !definitions && !strings.HasSuffix(path, "_test.go")
	// The names queries invent, here and in the rest of the tree, which a
	// reference qualifies the way it qualifies a declared column, and the two
	// together. A derived table built in one file is often read in another.
	madeUp := inventedNames(file, columns)
	for word := range elsewhere {
		if !columns[word] {
			madeUp[word] = true
		}
	}
	named := make(map[string]bool, len(columns)+len(madeUp))
	for word := range columns {
		named[word] = true
	}
	for word := range madeUp {
		named[word] = true
	}
	ast.Inspect(file, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			text = lit.Value
		}
		text = withoutSQLComments(text)
		at := fset.Position(lit.Pos()).Line
		// The table half reads every literal, because what admits one is this
		// schema's own table names rather than a marker: a query whose tables
		// are all bare carries no quoted table to be recognized by, and that
		// is exactly the query nothing looked at.
		if !definitions {
			bad = append(bad, unquotedTables(text, schema, path, at)...)
		}
		// The alias half still needs the marker. An invented name is any bare
		// word after AS, and "as" is a word in nearly every English sentence
		// in this repository.
		if !statement.MatchString(text) {
			if production && !quotedHere[lit.Pos()] {
				qualified++
				if hits := qualifiedColumns(text, named, path, at); len(hits) > 0 {
					bad = append(bad, hits...)
					columnsRead[lit.Pos()] = true
				}
			}
			return true
		}
		seen[lit.Pos()] = true
		columnsRead[lit.Pos()] = true
		for _, match := range invented.FindAllStringSubmatch(text, -1) {
			bad = append(bad, found{word: match[1], file: path, line: at, bare: true})
		}
		examined++
		bad = append(bad, unquotedColumns(text, columns, path, at)...)
		// A declared column is read above; an invented one is read here,
		// where a reference qualifies it.
		if production {
			qualified++
			bad = append(bad, qualifiedIn(text, madeUp, path, at)...)
		}
		return true
	})

	if production {
		bad = append(bad, handedNames(fset, path, file, named, standardNames(file))...)
	}

	ast.Inspect(file, func(node ast.Node) bool {
		if definitions {
			if lit, ok := node.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				for _, match := range declared.FindAllStringSubmatch(withoutSQLComments(text), -1) {
					word := strings.ToLower(match[1])
					if reserved[word] && !clause[word] {
						bad = append(bad, found{
							word: word, file: path,
							line: fset.Position(lit.Pos()).Line,
						})
					}
				}
			}
		}
		// The alias a model declares, which is written in a struct tag rather
		// than passed to anything.
		if field, ok := node.(*ast.Field); ok && field.Tag != nil {
			for _, match := range aliased.FindAllStringSubmatch(field.Tag.Value, -1) {
				word := strings.ToLower(match[1])
				if reserved[word] {
					bad = append(bad, found{
						word: word, file: path,
						line: fset.Position(field.Tag.Pos()).Line,
					})
				}
			}
			return true
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		named, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !writing[named.Sel.Name] {
			return true
		}
		for _, arg := range call.Args {
			parts := piecesOf(fset, arg)
			if len(parts) == 0 {
				continue
			}
			text := joined(parts)
			// A table expression may be the table and nothing else, which no
			// pattern over the text alone can tell from a constant.
			if naming[named.Sel.Name] && !definitions {
				if match := alone.FindStringSubmatch(text); match != nil {
					word := strings.ToLower(match[2])
					if match[1] != `"` && schema[word] {
						bad = append(bad, found{
							word: word, file: path, line: parts[0].line,
							table: true, bare: true,
						})
					}
				}
			}
			// A name inside one piece the statement pass read is already
			// reported; everything else in the argument, including a name
			// spanning two pieces, is read here.
			for _, match := range invented.FindAllStringSubmatchIndex(text, -1) {
				one, whole := pieceAt(parts, match[0], match[1])
				if whole && seen[one.pos] {
					continue
				}
				bad = append(bad, found{word: text[match[2]:match[3]], file: path, line: one.line, bare: true})
			}
			// The statement pass read every piece for tables, so only a name
			// spanning two pieces is new here.
			if !definitions {
				for _, bare := range bareTables(text, schema) {
					one, whole := pieceAt(parts, bare.start, bare.end)
					if whole {
						continue
					}
					bad = append(bad, found{word: bare.word, file: path, line: one.line, table: true, bare: true})
				}
			}
		}
		// Columns are read in the argument holding the SQL alone: the others
		// are values, and a value is free to be a word the schema has a
		// column of.
		if arg := queryArgument(call, named.Sel.Name, packages); arg != nil {
			// A Set that assigns nothing is a map's, a header's or a query
			// string's: the builder's always writes "column = value".
			parts := piecesOf(fset, arg)
			if named.Sel.Name == "Set" && !strings.Contains(joined(parts), "=") {
				parts = nil
			}
			if len(parts) > 0 {
				examined++
				text := withoutSQLComments(joined(parts))
				for _, bare := range bareColumns(text, columns) {
					one, whole := pieceAt(parts, bare.start, bare.end)
					if whole && columnsRead[one.pos] {
						continue
					}
					bad = append(bad, found{word: bare.word, file: path, line: one.line, bare: true, column: bare.quoted()})
				}
			}
		}
		return true
	})
	// A clause handed over as a variable rather than written at the call.
	// literal() reads what it can see and returns nothing for the rest, so a
	// fragment assembled a line earlier is read from the variable.
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		pieces := assembled(fn, seen, nil)
		quoted := assembled(fn, columnsRead, quotedByBuilder)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !writing[method.Sel.Name] {
				return true
			}
			for _, arg := range call.Args {
				if _, _, readable := literal(fset, arg); readable {
					continue // read at the call, above
				}
				text, ok := pieces[assembledFrom(arg)]
				if !ok {
					continue
				}
				at := fset.Position(arg.Pos()).Line
				for _, match := range invented.FindAllStringSubmatch(text, -1) {
					bad = append(bad, found{word: match[1], file: path, line: at, bare: true})
				}
				if !definitions {
					bad = append(bad, unquotedTables(text, schema, path, at)...)
				}
			}
			if arg := queryArgument(call, method.Sel.Name, packages); arg != nil {
				if _, _, readable := literal(fset, arg); !readable {
					if text, ok := quoted[assembledFrom(arg)]; ok {
						examined++
						bad = append(bad, unquotedColumns(withoutSQLComments(text), columns, path,
							fset.Position(arg.Pos()).Line)...)
					}
				}
			}
			return true
		})
	}
	return bad, examined, qualified
}

// A piece is one string literal of an argument written as a concatenation,
// and where its text starts in the whole.
type piece struct {
	text  string
	pos   token.Pos
	line  int
	start int
}

// piecesOf reads a string argument as its literals, following the
// concatenations these queries are written as, and nothing when no part of it
// is a literal.
func piecesOf(fset *token.FileSet, node ast.Expr) []piece {
	var out []piece
	var visit func(ast.Expr) bool
	visit = func(node ast.Expr) bool {
		switch typed := node.(type) {
		case *ast.BasicLit:
			if typed.Kind != token.STRING {
				return false
			}
			text, err := strconv.Unquote(typed.Value)
			if err != nil {
				// A raw string with something Unquote will not take. The
				// value itself is close enough to search.
				text = typed.Value
			}
			out = append(out, piece{text: text, pos: typed.Pos(), line: fset.Position(typed.Pos()).Line})
			return true
		case *ast.BinaryExpr:
			if typed.Op != token.ADD {
				return false
			}
			left := visit(typed.X)
			right := visit(typed.Y)
			return left || right
		}
		return false
	}
	visit(node)
	at := 0
	for i := range out {
		out[i].start = at
		at += len(out[i].text)
	}
	return out
}

func joined(parts []piece) string {
	var text strings.Builder
	for _, p := range parts {
		text.WriteString(p.text)
	}
	return text.String()
}

// pieceAt is the piece a span of the joined text starts in, and whether the
// span lies wholly inside it.
func pieceAt(parts []piece, start, end int) (piece, bool) {
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i].start <= start {
			return parts[i], end <= parts[i].start+len(parts[i].text)
		}
	}
	return parts[0], false
}

// ordered sorts what was found by file, line and word, for a stable report.
func ordered(bad []found) []found {
	sort.Slice(bad, func(i, j int) bool {
		if bad[i].file != bad[j].file {
			return bad[i].file < bad[j].file
		}
		if bad[i].line != bad[j].line {
			return bad[i].line < bad[j].line
		}
		return bad[i].word < bad[j].word
	})
	return bad
}
