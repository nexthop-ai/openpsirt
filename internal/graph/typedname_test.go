// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A component name somebody types is matched without regard to capitals. Two
// components whose names differ only in capitals are both what the name
// means, so a name typed in neither spelling answers with the choices, and a
// name typed in the producer's own spelling, as every link carries it,
// reaches the one spelled that way.
func TestATypedComponentNameIsMatchedWithoutRegardToCapitals(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		shouted := graph.Described{Purl: "pkg:generic/OpenSSL@3.0", Name: "OpenSSL", Version: "3.0"}
		quiet := graph.Described{Purl: "pkg:generic/openssl@1.1", Name: "openssl", Version: "1.1"}
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{zlib, shouted, quiet},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: zlib}, {Parent: root, Child: shouted},
				{Parent: root, Child: quiet},
			},
		}); err != nil {
			t.Fatal(err)
		}

		// One component, typed with other capitals.
		want, err := f.store.ComponentAs(ctx, f.targetID, zlib.Name, graph.Choice{})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.store.ComponentAs(ctx, f.targetID, "ZLib", graph.Choice{}); err != nil || got != want {
			t.Errorf("zlib typed as ZLib resolved %d (%v), want %d", got, err, want)
		}

		// Two that differ only in capitals, typed in neither spelling.
		_, err = f.store.ComponentAs(ctx, f.targetID, "OPENSSL", graph.Choice{})
		var several *graph.Ambiguous
		if !errors.As(err, &several) || len(several.Choices) != 2 {
			t.Fatalf("a name two components answer to answered %v, want the two choices", err)
		}
		for _, choice := range several.Choices {
			if _, err := f.store.ComponentAs(ctx, f.targetID, "OPENSSL", choice); err != nil {
				t.Errorf("the choice %+v did not resolve: %v", choice, err)
			}
		}

		// The producer's own spelling reaches the one spelled that way.
		for _, each := range []graph.Described{shouted, quiet} {
			id, err := f.store.ComponentAs(ctx, f.targetID, each.Name, graph.Choice{})
			if err != nil {
				t.Errorf("%s in its own spelling answered %v", each.Name, err)
				continue
			}
			version, err := f.store.ComponentAs(ctx, f.targetID, "OPENSSL",
				graph.Choice{Version: each.Version})
			if err != nil || version != id {
				t.Errorf("%s resolved %d, and its version resolves %d (%v)", each.Name, id, version, err)
			}
		}
	})
}
