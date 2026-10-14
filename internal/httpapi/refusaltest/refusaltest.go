// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package refusaltest checks the refusal mappers of one route package: every
// function there that takes an error and answers one, which is the shape of a
// mapper from a store's error to what a caller is told.
//
// Each route package with a mapper runs these over its own, because a mapper
// is usually unexported and only its own package can call it. The mappers are
// read from the source of the package under test, so one written later and
// missing from its table fails rather than going unchecked.
package refusaltest

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// LostAddress is the address Lost carries, which no answer may repeat.
const LostAddress = "10.0.4.7"

// Lost is a store error wrapping a failed dial, which carries the address the
// driver tried.
func Lost() error {
	return fmt.Errorf("read what is open there: %w", &net.OpError{
		Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 4, 7), Port: 5432},
		Err: errors.New("connection refused"),
	})
}

// Unclassified is an error nothing classified — neither a store's sentence nor
// anything the engine's error types recognize. An object store's answer is the
// live case: it names the endpoint and the credential it signed with.
func Unclassified() error {
	return fmt.Errorf("store the file: %w", errors.New(
		"PUT https://objects.internal.example:9000/evidence: AccessDenied for AKIAEXAMPLE"))
}

// UnclassifiedText is what Unclassified carries that no answer may repeat.
var UnclassifiedText = []string{"objects.internal", "AKIAEXAMPLE"}

// Said is a store's own sentence, wrapped the way a store wraps it.
func Said() error {
	return fmt.Errorf("record the claim: %w",
		refusal.Errorf("%q is not a recognized reason for something not applying", "because"))
}

// SaidText is the part of Said a caller is told.
const SaidText = "is not a recognized reason"

// Faults fails each answer that is not a server error, or that publishes any
// of the withheld strings.
//
// The whole body is read, the way a caller receives it, rather than its
// detail alone: a fault's text carried in the list of errors beside the detail
// is published just the same.
func Faults(t testing.TB, mapped map[string]error, withheld ...string) {
	t.Helper()
	for name, answer := range mapped {
		var status huma.StatusError
		if !errors.As(answer, &status) || status.GetStatus() != 500 {
			t.Errorf("%s answered %v, want a 500", name, answer)
			continue
		}
		body, err := json.Marshal(status)
		if err != nil {
			t.Errorf("%s answered a body that cannot be written: %v", name, err)
			continue
		}
		for _, text := range withheld {
			if strings.Contains(string(body), text) {
				t.Errorf("%s published %q: %s", name, text, body)
			}
		}
		var model *huma.ErrorModel
		if errors.As(answer, &model) && len(model.Errors) > 0 {
			t.Errorf("%s answered a fault carrying details of it: %s", name, body)
		}
	}
}

// Publishes fails each answer that is not a refusal carrying the store's
// sentence in its own words.
func Publishes(t testing.TB, answers map[string]error) {
	t.Helper()
	if len(answers) == 0 {
		t.Fatal("no mapper was asked, so this checked nothing")
		return
	}
	for name, answer := range answers {
		var status huma.StatusError
		if !errors.As(answer, &status) || status.GetStatus() >= 500 {
			t.Errorf("%s answered %v, want a refusal", name, answer)
			continue
		}
		if !strings.Contains(answer.Error(), SaidText) {
			t.Errorf("%s did not publish the store's sentence: %v", name, answer)
		}
	}
}

// MappersIn is every function in this Go source that takes an error and
// answers one.
func MappersIn(source string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "", source, 0)
	if err != nil {
		return nil, err
	}
	var found []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
			continue
		}
		if result, ok := fn.Type.Results.List[0].Type.(*ast.Ident); !ok || result.Name != "error" {
			continue
		}
		for _, param := range fn.Type.Params.List {
			if kind, ok := param.Type.(*ast.Ident); ok && kind.Name == "error" {
				found = append(found, fn.Name.Name)
				break
			}
		}
	}
	return found, nil
}

// DeclaredIn is every mapper declared in the Go source of one directory,
// leaving its tests out.
func DeclaredIn(dir fs.FS) ([]string, error) {
	sources, err := fs.Glob(dir, "*.go")
	if err != nil {
		return nil, err
	}
	var declared []string
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := fs.ReadFile(dir, name)
		if err != nil {
			return nil, err
		}
		found, err := MappersIn(string(source))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		declared = append(declared, found...)
	}
	sort.Strings(declared)
	return declared, nil
}

// CoversEveryMapper fails where a mapper declared in the source of the
// package under test is neither checked nor exempt, or where one checked is
// no longer declared.
func CoversEveryMapper(t *testing.T, mapped map[string]error, exempt map[string]string) {
	t.Helper()
	declared, err := DeclaredIn(os.DirFS("."))
	if err != nil {
		t.Fatal(err)
	}
	if len(declared) == 0 {
		t.Fatal("no refusal mapper was found in the source, so this checked nothing")
	}
	for _, name := range declared {
		if _, ok := exempt[name]; ok {
			continue
		}
		if _, ok := mapped[name]; !ok {
			t.Errorf("%s maps an error to an answer and is not passed a lost connection here", name)
		}
	}
	for name := range mapped {
		if !slices.Contains(declared, name) {
			t.Errorf("%s is checked here and no longer declared in the source", name)
		}
	}
	for name := range exempt {
		if !slices.Contains(declared, name) {
			t.Errorf("%s is exempt here and no longer declared in the source", name)
		}
	}
}
