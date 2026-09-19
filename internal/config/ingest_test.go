package config_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func TestTheIngestBoundsAreReachableFromTheEnvironment(t *testing.T) {
	// the ingest bounds says all of them are configurable. None of them
	// was: the process handed the reader an empty set, the reader filled
	// every field from its own defaults, and there was no environment
	// variable for any of them — so a deployment that wanted a smaller
	// ceiling than 256 MB could not have one, and the whole surface
	// existed with nothing able to reach it.
	t.Setenv("OPENPSIRT_INGEST_MAX_BYTES", "1048576")
	t.Setenv("OPENPSIRT_INGEST_MAX_COMPONENTS", "500")
	t.Setenv("OPENPSIRT_INGEST_MAX_DEPTH", "8")

	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	bounds := loaded.Limits().OrDefault()
	if bounds.MaxBytes != 1<<20 {
		t.Errorf("the size ceiling is %d, want what was set", bounds.MaxBytes)
	}
	if bounds.MaxComponents != 500 {
		t.Errorf("the component ceiling is %d, want what was set", bounds.MaxComponents)
	}
	if bounds.MaxDepth != 8 {
		t.Errorf("the depth ceiling is %d, want what was set", bounds.MaxDepth)
	}
	// Anything not set keeps the reader's own default rather than becoming
	// zero, which is what lets a deployment change one bound without restating
	// the rest.
	if bounds.MaxEdges != sbom.DefaultLimits().MaxEdges {
		t.Errorf("an unset ceiling became %d rather than the default", bounds.MaxEdges)
	}
}
