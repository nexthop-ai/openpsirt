// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"maps"
	"reflect"
	"strings"
	"sync"

	"github.com/danielgtaylor/huma/v2"
)

// schemaPrefix is where a schema reference points, the framework's default.
const schemaPrefix = "#/components/schemas/"

// derived holds every schema worked out from a Go type, once per process.
//
// Working a schema out walks every field of every type an operation takes or
// returns, and it is half of what building the API costs: 8.4 ms of 17.8 ms
// a build. Every API this process builds registers the same operations, so the
// schemas are the same each time and are worked out by whichever build reaches
// a type first.
//
// The framework's registry is not safe for concurrent use, so every question
// is asked holding one lock. Builds in one process run one after another, so
// the lock is never waited on.
var derived = struct {
	sync.Mutex
	registry huma.Registry
}{
	registry: huma.NewMapRegistry(schemaPrefix, huma.DefaultSchemaNamer),
}

// schemas is one API's view of the shared registry.
//
// Registering an operation adds a property naming the JSON Schema to the
// top-level schema of each body it sends, and it does so only where the
// property is absent. Shared, the second API to register would find it present
// and leave its responses without the link. So an API holds its own copy of
// each top-level schema, with its own property map, and everything beneath
// those is shared, because nothing writes to it.
//
// The copy is written while operations register, which is one goroutine, and
// complete is called before the API serves; after that it is only read.
type schemas struct {
	own map[string]*huma.Schema
}

var _ huma.Registry = (*schemas)(nil)

func newSchemas() *schemas {
	return &schemas{own: map[string]*huma.Schema{}}
}

// Schema works out the schema for a type, or returns the one already worked
// out. With allowRef a struct comes back as a reference, fresh on every call;
// without it, the shared schema itself, which nothing here asks for.
func (s *schemas) Schema(t reflect.Type, allowRef bool, hint string) *huma.Schema {
	derived.Lock()
	defer derived.Unlock()
	return derived.registry.Schema(t, allowRef, hint)
}

// SchemaFromRef returns this API's copy of a top-level schema, copying it from
// the shared registry the first time it is asked for.
func (s *schemas) SchemaFromRef(ref string) *huma.Schema {
	name, ok := strings.CutPrefix(ref, schemaPrefix)
	if !ok {
		return nil
	}
	if have, ok := s.own[name]; ok {
		return have
	}
	derived.Lock()
	defer derived.Unlock()
	return s.copy(name, derived.registry.Map()[name])
}

// copy records this API's copy of one shared schema. The caller holds the
// lock.
func (s *schemas) copy(name string, shared *huma.Schema) *huma.Schema {
	if shared == nil {
		return nil
	}
	mine := *shared
	mine.Properties = maps.Clone(shared.Properties)
	s.own[name] = &mine
	return &mine
}

// complete copies every schema the shared registry holds that this API has not
// asked for yet, so that answering a request never writes here.
func (s *schemas) complete() {
	derived.Lock()
	defer derived.Unlock()
	for name, shared := range derived.registry.Map() {
		if _, ok := s.own[name]; !ok {
			s.copy(name, shared)
		}
	}
}

// TypeFromRef returns the Go type a reference was worked out from.
func (s *schemas) TypeFromRef(ref string) reflect.Type {
	derived.Lock()
	defer derived.Unlock()
	return derived.registry.TypeFromRef(ref)
}

// Map returns this API's top-level schemas.
func (s *schemas) Map() map[string]*huma.Schema {
	s.complete()
	return s.own
}

// RegisterTypeAlias is refused: an alias would change the schema of a type for
// every API in the process, and no operation here declares one.
func (s *schemas) RegisterTypeAlias(reflect.Type, reflect.Type) {
	panic("httpapi: a type alias would change every API in the process")
}

// MarshalJSON writes the top-level schemas, as the document's components. The
// document's YAML is converted from its JSON.
func (s *schemas) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Map())
}
