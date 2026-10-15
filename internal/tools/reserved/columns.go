// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// column matches a column a migration declares: a quoted name opening a line
// of a table's definition, or the name an added column is given.
//
// A definition's type is often concatenated in from the engine's own
// spelling, so the literal ends after the name and the spaces that follow it.
// Opening a line is what tells a declaration from a quoted name inside an
// index or a constraint, which follows a parenthesis or a comma.
var column = regexp.MustCompile(`(?m)(?:^\s*|\bADD\s+(?:COLUMN\s+)?)"([a-z_][a-z0-9_]*)"(?:\s|$)`)

// columnsDeclared adds the columns a migration file declares to columns.
func columnsDeclared(path string, file *ast.File, columns map[string]bool) {
	if !strings.Contains(path, "database/migrate/migrations/") || strings.HasSuffix(path, "_test.go") {
		return
	}
	ast.Inspect(file, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		for _, match := range column.FindAllStringSubmatch(withoutSQLComments(text), -1) {
			columns[match[1]] = true
		}
		return true
	})
}

// A bareColumn is a declared column written bare in a query, the name
// qualifying it where one does, and the span of the two.
type bareColumn struct {
	word, qualifier string
	start, end      int
}

// quoted is how the column is written once it is quoted, qualifier and all.
func (b bareColumn) quoted() string {
	if b.qualifier == "" {
		return strconv.Quote(b.word)
	}
	qualifier := b.qualifier
	if !strings.HasPrefix(qualifier, `"`) && !strings.HasPrefix(qualifier, "?") {
		qualifier = strconv.Quote(qualifier)
	}
	return qualifier + "." + strconv.Quote(b.word)
}

// bareColumns reports every column the schema declares that a query's text
// writes bare.
//
// The text is read as SQL by a small scanner rather than by a pattern, so that
// what is inside a quoted identifier, a string constant or a backquoted name
// is stepped over whole. A word is a column when the migrations declare a
// column of that name and it is written in lower case: every keyword here is
// written in capitals, and every declared name is lower case. A word followed
// by a parenthesis is a function, a word followed by a dot qualifies the next
// one, and a word following a placeholder mark or a cast is not a name.
func bareColumns(text string, columns map[string]bool) []bareColumn {
	var bare []bareColumn
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			i = closing(text, i)
		case isDigit(c):
			for i < len(text) && isWordByte(text[i]) {
				i++
			}
		case isWordByte(c):
			end := i
			for end < len(text) && isWordByte(text[end]) {
				end++
			}
			word := text[i:end]
			if columns[word] && word == strings.ToLower(word) && isColumnAt(text, i, end) {
				one := bareColumn{word: word, start: i, end: end}
				if i > 0 && text[i-1] == '.' {
					// A qualifier the code supplies leaves the dot where it is.
					if qualifier, at := qualifierBefore(text, i-1); qualifier != "" {
						one.qualifier, one.start = qualifier, at
					}
				}
				bare = append(bare, one)
			}
			i = end
		default:
			i++
		}
	}
	return bare
}

// isColumnAt reports whether the word at text[start:end] stands where a
// column can: not a function's name, not a qualifier, and not the word a
// placeholder mark or a cast opens.
func isColumnAt(text string, start, end int) bool {
	if end < len(text) && text[end] == '.' {
		return false
	}
	next := end
	for next < len(text) && (text[next] == ' ' || text[next] == '\t' || text[next] == '\n') {
		next++
	}
	if next < len(text) && text[next] == '(' {
		return false
	}
	if start > 0 && text[start-1] == '?' {
		return false
	}
	if start > 1 && text[start-2:start] == "::" {
		return false
	}
	return true
}

// qualifierBefore is the name qualifying a column, read back from the dot at
// text[dot], and where it starts.
func qualifierBefore(text string, dot int) (string, int) {
	start := dot
	if start > 0 && text[start-1] == '"' {
		start--
		for start > 0 && text[start-1] != '"' {
			start--
		}
		if start > 0 {
			start--
		}
		return text[start:dot], start
	}
	for start > 0 && isWordByte(text[start-1]) {
		start--
	}
	if start > 0 && text[start-1] == '?' {
		start--
	}
	return text[start:dot], start
}

// closing is the index just past the quote that closes the one at text[open].
// A doubled quote inside is the quote character itself, as SQL writes it.
func closing(text string, open int) int {
	quote := text[open]
	for i := open + 1; i < len(text); i++ {
		if text[i] != quote {
			continue
		}
		if i+1 < len(text) && text[i+1] == quote {
			i++
			continue
		}
		return i + 1
	}
	return len(text)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isWordByte(c byte) bool {
	return c == '_' || isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// quotedByBuilder is the builder's methods that quote the identifier they are
// given. A query assembled in a variable is read for columns without them.
var quotedByBuilder = map[string]bool{
	"Column": true, "ExcludeColumn": true, "Order": true, "Group": true, "Table": true,
}

// queryArgument is the argument of a writing method that holds its SQL. The
// rest are values bound into it, and a value is free to be a word the schema
// has a column of. A call on a package rather than a value — strings.Join,
// errors.Join — writes no SQL, and has none.
func queryArgument(call *ast.CallExpr, method string, packages map[string]bool) ast.Expr {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		if x, ok := selector.X.(*ast.Ident); ok && packages[x.Name] {
			return nil
		}
	}
	at := 0
	switch method {
	case "ExecContext", "QueryContext", "QueryRowContext":
		at = 1
	}
	if at >= len(call.Args) {
		return nil
	}
	return call.Args[at]
}

// importedNames is the name each import of a file binds.
func importedNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, spec := range file.Imports {
		if spec.Name != nil {
			names[spec.Name.Name] = true
			continue
		}
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		names[path[strings.LastIndex(path, "/")+1:]] = true
	}
	return names
}

// unquotedColumns reports, as findings, every declared column the text writes
// bare.
func unquotedColumns(text string, columns map[string]bool, path string, line int) []found {
	var bad []found
	for _, one := range bareColumns(text, columns) {
		bad = append(bad, found{word: one.word, file: path, line: line, bare: true, column: one.quoted()})
	}
	return bad
}
