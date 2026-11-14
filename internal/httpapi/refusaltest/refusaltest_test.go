// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package refusaltest_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

func TestTheDetectorFindsARefusalMapper(t *testing.T) {
	got, err := refusaltest.MappersIn(`package p
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

// recorder is a test the harness reports to, so what it reports can be read.
type recorder struct {
	testing.TB
	failed []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.failed = append(r.failed, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatal(args ...any) { r.failed = append(r.failed, fmt.Sprint(args...)) }

func TestAFaultCarryingItsCauseInTheListOfErrorsIsCaught(t *testing.T) {
	cause := refusaltest.Lost()
	leaking := huma.NewError(http.StatusInternalServerError, "that could not be recorded", cause)
	r := &recorder{TB: t}
	refusaltest.Faults(r, map[string]error{"leaking": leaking}, refusaltest.LostAddress)
	if len(r.failed) == 0 {
		t.Fatal("a fault publishing the address it dialed in its list of errors passed")
	}
}

func TestAFaultInWordsOfItsOwnPasses(t *testing.T) {
	quiet := huma.Error500InternalServerError("that could not be recorded")
	r := &recorder{TB: t}
	refusaltest.Faults(r, map[string]error{"quiet": quiet}, refusaltest.LostAddress)
	if len(r.failed) != 0 {
		t.Errorf("a fault naming nothing about its cause failed: %v", r.failed)
	}
}

func TestARefusalAnsweredAsAFaultIsCaught(t *testing.T) {
	r := &recorder{TB: t}
	refusaltest.Faults(r, map[string]error{
		"refused": huma.Error422UnprocessableEntity("no"),
	})
	if len(r.failed) == 0 {
		t.Fatal("a 422 passed as a fault")
	}
}

func TestAFaultAnsweredWhereARefusalBelongsIsCaught(t *testing.T) {
	r := &recorder{TB: t}
	refusaltest.Publishes(r, map[string]error{
		"faulted":  huma.Error500InternalServerError("that could not be recorded"),
		"reworded": huma.Error422UnprocessableEntity("something else entirely"),
	})
	if len(r.failed) != 2 {
		t.Errorf("reported %v, want the fault and the reworded refusal", r.failed)
	}
}

func TestNothingAskedIsCaught(t *testing.T) {
	r := &recorder{TB: t}
	refusaltest.Publishes(r, nil)
	if len(r.failed) == 0 {
		t.Fatal("asking no mapper passed")
	}
}

func TestAFaultCheckAskingNothingIsCaught(t *testing.T) {
	r := &recorder{TB: t}
	refusaltest.Faults(r, nil, refusaltest.LostAddress)
	if len(r.failed) == 0 {
		t.Fatal("asking no mapper passed")
	}
}

func TestAMapperDeclaredAndUncheckedIsReported(t *testing.T) {
	got := refusaltest.Uncovered([]string{"checked", "unchecked"},
		map[string]error{"checked": nil}, nil)
	if len(got) != 1 || !strings.HasPrefix(got[0], "unchecked ") {
		t.Errorf("reported %v, want unchecked alone", got)
	}
}

func TestAMapperCheckedAndNoLongerDeclaredIsReported(t *testing.T) {
	got := refusaltest.Uncovered([]string{"checked"},
		map[string]error{"checked": nil, "gone": nil}, nil)
	if len(got) != 1 || !strings.HasPrefix(got[0], "gone ") {
		t.Errorf("reported %v, want gone alone", got)
	}
}

func TestAMapperExemptAndNoLongerDeclaredIsReported(t *testing.T) {
	got := refusaltest.Uncovered([]string{"checked"},
		map[string]error{"checked": nil}, map[string]string{"gone": "a reason"})
	if len(got) != 1 || !strings.HasPrefix(got[0], "gone ") {
		t.Errorf("reported %v, want gone alone", got)
	}
}

func TestEveryMapperCheckedOrExemptReportsNothing(t *testing.T) {
	got := refusaltest.Uncovered([]string{"checked", "exempt"},
		map[string]error{"checked": nil}, map[string]string{"exempt": "a reason"})
	if len(got) != 0 {
		t.Errorf("reported %v, want nothing", got)
	}
}

func TestADeclaredMapperIsReadFromSourceAndNotFromTests(t *testing.T) {
	dir := fstest.MapFS{
		"map.go":      {Data: []byte("package p\nfunc mapped(err error) error { return err }\n")},
		"map_test.go": {Data: []byte("package p\nfunc helper(err error) error { return err }\n")},
	}
	got, err := refusaltest.DeclaredIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "mapped" {
		t.Errorf("declared %v, want [mapped]", got)
	}
}
