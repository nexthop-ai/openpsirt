// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/csaf"
)

// Every field the reader reads is one the shape this deployment writes
// declares, under the same name and of the same kind.
func TestTheReaderReadsOnlyNamesTheWrittenShapeDeclares(t *testing.T) {
	pairs := []struct{ read, written any }{
		{providerMetadata{}, csaf.ProviderMetadata{}},
		{distribution{}, csaf.Distribution{}},
		{rolie{}, csaf.ROLIE{}},
		{feedDescription{}, csaf.FeedDescription{}},
		{rolieFeed{}, csaf.Feed{}},
		{feedBody{}, csaf.FeedBody{}},
		{feedEntry{}, csaf.Entry{}},
		{link{}, csaf.Link{}},
		{content{}, csaf.Content{}},
	}
	for _, pair := range pairs {
		written := map[string]reflect.Kind{}
		w := reflect.TypeOf(pair.written)
		for i := range w.NumField() {
			written[jsonName(w.Field(i))] = w.Field(i).Type.Kind()
		}
		r := reflect.TypeOf(pair.read)
		if r.NumField() == 0 {
			t.Fatalf("%s reads nothing, so this checked nothing", r.Name())
		}
		for i := range r.NumField() {
			field := r.Field(i)
			kind, ok := written[jsonName(field)]
			if !ok {
				t.Errorf("%s reads %q, which %s does not declare", r.Name(), jsonName(field), w.Name())
				continue
			}
			if kind != field.Type.Kind() {
				t.Errorf("%s reads %q as a %s, which %s declares as a %s",
					r.Name(), jsonName(field), field.Type.Kind(), w.Name(), kind)
			}
		}
	}
}

func jsonName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	return name
}
