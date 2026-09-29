// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// mappersIn is every function in this Go source that takes an error and
// answers one: the shape of a mapper from a store's error to what a caller is
// told.
func mappersIn(source string) ([]string, error) {
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

func TestTheDetectorFindsARefusalMapper(t *testing.T) {
	got, err := mappersIn(`package p
func mapped(logger any, err error, what string) error { return err }
func unrelated(what string) error { return nil }
func (s *store) method(err error) error { return err }`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "mapped" {
		t.Errorf("the mappers found were %v, want [mapped]", got)
	}
}

// TestALostConnectionIsAFaultInEveryRefusalMapper passes each mapper a store
// error wrapping a failed dial, which carries the address the driver tried,
// and asks for a server error whose words name none of it.
//
// The mappers are read from this package's source, so one written later and
// missing here fails rather than going unchecked.
func TestALostConnectionIsAFaultInEveryRefusalMapper(t *testing.T) {
	lost := fmt.Errorf("read what is open there: %w", &net.OpError{
		Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 4, 7), Port: 5432},
		Err: errors.New("connection refused"),
	})
	mapped := everyMapper(lost)
	// Reached only with an error something has already classified, so a lost
	// connection never arrives at them.
	exempt := map[string]string{
		"rejection":  "an upload refused by a rule the ingest names",
		"aboutBuild": "a refusal already answered as a status, prefixed with the build",
	}
	for name, answer := range mapped {
		var status huma.StatusError
		if !errors.As(answer, &status) || status.GetStatus() != 500 {
			t.Errorf("%s answered %v, want a 500", name, answer)
			continue
		}
		if strings.Contains(answer.Error(), "10.0.4.7") {
			t.Errorf("%s published the address: %v", name, answer)
		}
	}
	coversEveryMapper(t, mapped, exempt)
}

// An error nothing classified — neither a store's sentence nor anything the
// engine's error types recognize — is a fault in every mapper, and its text is
// withheld. An object store's answer is the live case: it names the endpoint
// and the credential it signed with.
func TestAnUnclassifiedErrorIsAFaultInEveryRefusalMapper(t *testing.T) {
	unclassified := fmt.Errorf("store the file: %w", errors.New(
		"PUT https://objects.internal.example:9000/evidence: AccessDenied for AKIAEXAMPLE"))
	mapped := everyMapper(unclassified)
	for name, answer := range mapped {
		var status huma.StatusError
		if !errors.As(answer, &status) || status.GetStatus() != 500 {
			t.Errorf("%s answered %v, want a 500", name, answer)
			continue
		}
		if strings.Contains(answer.Error(), "objects.internal") ||
			strings.Contains(answer.Error(), "AKIAEXAMPLE") {
			t.Errorf("%s published the error's text: %v", name, answer)
		}
	}
	coversEveryMapper(t, mapped, map[string]string{
		"rejection":  "an upload refused by a rule the ingest names",
		"aboutBuild": "a refusal already answered as a status, prefixed with the build",
	})
}

// A store's own sentence reaches the caller in its own words through each
// mapper that has no arm for it, however the store wrapped it.
func TestAStoresRefusalIsPublishedByTheCatchAllMappers(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	said := fmt.Errorf("record the claim: %w",
		refusal.Errorf("%q is not a recognized reason for something not applying", "because"))
	for name, answer := range map[string]error{
		"asked":              asked(quiet, said),
		"refusedDecision":    refusedDecision(quiet, said),
		"refusedNote":        refusedNote(quiet, said),
		"declineDeclaration": declineDeclaration(quiet, said),
	} {
		var status huma.StatusError
		if !errors.As(answer, &status) || status.GetStatus() >= 500 {
			t.Errorf("%s answered %v, want a refusal", name, answer)
			continue
		}
		if !strings.Contains(answer.Error(), "is not a recognized reason") {
			t.Errorf("%s did not publish the store's sentence: %v", name, answer)
		}
	}
}

// everyMapper is what each refusal mapper in this package answers err with.
func everyMapper(lost error) map[string]error {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	in := Deps{Logger: quiet}
	nowhere := func() error { return huma.Error404NotFound("nothing goes by that") }
	return map[string]error{
		"asked":              asked(quiet, lost),
		"refused":            refused(quiet, lost, "that could not be recorded"),
		"refusedDecision":    refusedDecision(quiet, lost),
		"refusedNote":        refusedNote(quiet, lost),
		"declineDeclaration": declineDeclaration(quiet, lost),
		"declineRename":      declineRename(quiet, lost),
		"vexRefused":         vexRefused(in, lost, "that could not be read"),
		"advisoryRefused":    advisoryRefused(in, lost, "that could not be read"),
		"refusedFinding":     refusedFinding(in, lost),
		"refusedReport":      refusedReport(in, lost, "that could not be read"),
		"refusedMovement":    refusedMovement(in, lost),
		"refusedRuling":      refusedRuling(in, lost, "that could not be read"),
		"refusedWindow":      refusedWindow(in, lost),
		"absent":             absent(quiet, lost, "that could not be looked up", nowhere),
		"wentWrong":          wentWrong(quiet, "that could not be read", lost),
		"notRecorded":        notRecorded(quiet, lost),
		"recording":          recording(quiet, "that could not be recorded", lost),
		"ambiguousOrMissing": ambiguousOrMissing(quiet, lost),
		"undeclared":         undeclared(quiet, lost, "that could not be looked up"),
		"oneVersion": oneVersion(lost, func(err error) error {
			return refusedFinding(in, err)
		}),
	}
}

// coversEveryMapper fails where a mapper declared in this package's source is
// neither checked nor exempt, or where one checked is no longer declared.
func coversEveryMapper(t *testing.T, mapped map[string]error, exempt map[string]string) {
	t.Helper()
	own := os.DirFS(".")
	sources, err := fs.Glob(own, "*.go")
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := fs.ReadFile(own, name)
		if err != nil {
			t.Fatal(err)
		}
		found, err := mappersIn(string(source))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		declared = append(declared, found...)
	}
	if len(declared) == 0 {
		t.Fatal("no refusal mapper was found in the source, so this checked nothing")
	}
	sort.Strings(declared)
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
}
