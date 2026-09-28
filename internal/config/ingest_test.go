// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

// Every ingest bound is configurable, each reaching the field it names. The
// values are distinct, so two settings wired to one field, or one field left
// out, reads as the wrong number.
func TestTheIngestBoundsAreReachableFromTheEnvironment(t *testing.T) {
	t.Setenv("OPENPSIRT_INGEST_MAX_BYTES", "1048576")
	t.Setenv("OPENPSIRT_INGEST_MAX_COMPONENTS", "500")
	t.Setenv("OPENPSIRT_INGEST_MAX_EDGES", "501")
	t.Setenv("OPENPSIRT_INGEST_MAX_FILES", "502")
	t.Setenv("OPENPSIRT_INGEST_MAX_STATEMENTS", "503")
	t.Setenv("OPENPSIRT_INGEST_MAX_DEPTH", "8")
	t.Setenv("OPENPSIRT_INGEST_MAX_DOCUMENTS", "9")

	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.Limits().OrDefault()
	want := sbom.Limits{
		MaxBytes:      1 << 20,
		MaxComponents: 500,
		MaxEdges:      501,
		MaxFiles:      502,
		MaxStatements: 503,
		MaxDepth:      8,
		MaxDocuments:  9,
	}
	if got != want {
		t.Errorf("the ingest bounds read as %+v, want %+v", got, want)
	}
}

// Anything not set keeps the reader's own default rather than becoming zero,
// which is what lets a deployment change one bound without restating the rest.
func TestAnUnsetIngestBoundKeepsItsDefault(t *testing.T) {
	t.Setenv("OPENPSIRT_INGEST_MAX_DEPTH", "8")
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Limits().OrDefault().MaxEdges; got != sbom.DefaultLimits().MaxEdges {
		t.Errorf("an unset ceiling became %d rather than the default", got)
	}
}

// Every scanner bound is configurable, each reaching the field it names, with
// distinct values for the reason the ingest bounds above have them.
func TestTheScannerBoundsAreReachableFromTheEnvironment(t *testing.T) {
	t.Setenv("OPENPSIRT_SCANNER_MAX_OUTPUT", "1048577")
	t.Setenv("OPENPSIRT_SCANNER_MAX_COMPLAINT", "4097")
	t.Setenv("OPENPSIRT_SCANNER_MAX_MATCHES", "303")
	t.Setenv("OPENPSIRT_SCANNER_MAX_REFERENCES", "17")

	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.ScannerLimits().OrDefault()
	want := scanner.Limits{
		MaxOutput:     1048577,
		MaxComplaint:  4097,
		MaxMatches:    303,
		MaxReferences: 17,
	}
	if got != want {
		t.Errorf("the scanner bounds read as %+v, want %+v", got, want)
	}
}
