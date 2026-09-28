// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"testing"
)

// Every kind of work declared is in the list an operator's view of what is
// waiting reads, so a new kind is not missing from it.
//
// Read from the source rather than listed here, because a list in the test is
// a second list to keep right.
func TestEveryKindDeclaredIsListed(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "kinds.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	for _, decl := range file.Decls {
		block, ok := decl.(*ast.GenDecl)
		if !ok || block.Tok != token.CONST {
			continue
		}
		for _, spec := range block.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				declared++
				literal, ok := value.Values[i].(*ast.BasicLit)
				if !ok {
					t.Errorf("%s is not written as a literal, so this cannot read it", name.Name)
					continue
				}
				kind, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(Kinds(), kind) {
					t.Errorf("%s (%q) is declared and not listed by Kinds", name.Name, kind)
				}
			}
		}
	}
	if declared == 0 {
		t.Fatal("no kind was declared in kinds.go, so this checked nothing")
	}
	if declared != len(Kinds()) {
		t.Errorf("%d kinds are declared and Kinds lists %d", declared, len(Kinds()))
	}
}
