// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/csaf"
)

// Every field the reader reads is one the shape this deployment writes
// declares, under the same name and of the same kind, walked from the two
// documents the reader starts at into every struct a field holds.
func TestTheReaderReadsOnlyNamesTheWrittenShapeDeclares(t *testing.T) {
	visited := 0
	for _, root := range []struct{ read, written any }{
		{providerMetadata{}, csaf.ProviderMetadata{}},
		{rolieFeed{}, csaf.Feed{}},
	} {
		problems := shapeDiffers(reflect.TypeOf(root.read), reflect.TypeOf(root.written), map[reflect.Type]bool{}, &visited)
		for _, problem := range problems {
			t.Error(problem)
		}
	}
	if visited == 0 {
		t.Fatal("no reader struct was compared, so this checked nothing")
	}
	t.Logf("compared %d reader structs", visited)
}

// element is the struct a field holds, through a pointer, a slice or a map,
// or nil where it holds none.
func element(kind reflect.Type) reflect.Type {
	for kind.Kind() == reflect.Pointer || kind.Kind() == reflect.Slice ||
		kind.Kind() == reflect.Array || kind.Kind() == reflect.Map {
		kind = kind.Elem()
	}
	if kind.Kind() != reflect.Struct {
		return nil
	}
	return kind
}

// shapeDiffers is every field of a reader struct, and of every struct its
// fields hold, that the written struct at the same place does not declare
// under that name or declares as another kind.
func shapeDiffers(read, written reflect.Type, seen map[reflect.Type]bool, visited *int) []string {
	if seen[read] {
		return nil
	}
	seen[read] = true
	*visited++
	fields := map[string]reflect.StructField{}
	for i := range written.NumField() {
		fields[jsonName(written.Field(i))] = written.Field(i)
	}
	if read.NumField() == 0 {
		return []string{read.Name() + " reads nothing"}
	}
	var problems []string
	for i := range read.NumField() {
		field := read.Field(i)
		declared, ok := fields[jsonName(field)]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s reads %q, which %s does not declare",
				read.Name(), jsonName(field), written.Name()))
			continue
		}
		if declared.Type.Kind() != field.Type.Kind() {
			problems = append(problems, fmt.Sprintf("%s reads %q as a %s, which %s declares as a %s",
				read.Name(), jsonName(field), field.Type.Kind(), written.Name(), declared.Type.Kind()))
			continue
		}
		readHolds, writtenHolds := element(field.Type), element(declared.Type)
		switch {
		case readHolds == nil && writtenHolds == nil:
		case readHolds == nil || writtenHolds == nil:
			problems = append(problems, fmt.Sprintf("%s reads %q holding %v, which %s declares holding %v",
				read.Name(), jsonName(field), readHolds, written.Name(), writtenHolds))
		default:
			problems = append(problems, shapeDiffers(readHolds, writtenHolds, seen, visited)...)
		}
	}
	return problems
}

func TestAReaderFieldNestedDeeperThanTheRootIsCompared(t *testing.T) {
	type writtenLeaf struct {
		Name string `json:"name"`
	}
	type written struct {
		Leaves []writtenLeaf `json:"leaves"`
	}
	type readLeaf struct {
		Other string `json:"other"`
	}
	type read struct {
		Leaves []readLeaf `json:"leaves"`
	}
	visited := 0
	if got := shapeDiffers(reflect.TypeFor[read](), reflect.TypeFor[written](), map[reflect.Type]bool{}, &visited); len(got) != 1 || visited != 2 {
		t.Errorf("reported %v over %d structs, want the nested field over 2", got, visited)
	}
	type matchingLeaf struct {
		Name string `json:"name"`
	}
	type matching struct {
		Leaves []matchingLeaf `json:"leaves"`
	}
	if got := shapeDiffers(reflect.TypeFor[matching](), reflect.TypeFor[written](), map[reflect.Type]bool{}, &visited); len(got) != 0 {
		t.Errorf("a matching shape reported %v", got)
	}
}

func jsonName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	return name
}
