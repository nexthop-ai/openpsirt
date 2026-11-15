// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

func TestADocumentUploadIsRecordedInTheWordsItsStatusIsSaidIn(t *testing.T) {
	// The lists hand the record on as the status, unmapped.
	for recorded, said := range map[string]ingest.UploadStatus{
		finding.UploadTaken:      ingest.UploadCompleted,
		finding.UploadTurnedAway: ingest.UploadRefused,
	} {
		if recorded != string(said) {
			t.Errorf("a document is recorded as %q and its status is said as %q", recorded, said)
		}
	}
}

func TestEveryProgressAndRunStatusIsAnUploadStatus(t *testing.T) {
	// The lists answer one vocabulary for every kind, so a state of either
	// kind's own maps to a status in it, and the one that is still working
	// reads as in progress.
	want := map[ingest.Progress]ingest.UploadStatus{
		ingest.Reading: ingest.UploadInProgress, ingest.Scanning: ingest.UploadInProgress,
		ingest.Scanned: ingest.UploadCompleted, ingest.Refused: ingest.UploadFailed,
	}
	if len(ingest.Progresses()) == 0 || len(series.Statuses()) == 0 {
		t.Fatal("no states were listed, so this checked nothing")
	}
	for _, p := range ingest.Progresses() {
		if got := p.Upload(); got != want[p] {
			t.Errorf("an upload %s reads as %q, want %q", p, got, want[p])
		}
	}
	for _, s := range series.Statuses() {
		if got := ingest.RunUpload(s); !slices.Contains(ingest.UploadStatuses(), got) {
			t.Errorf("a run %s reads as %q, outside the upload statuses", s, got)
		}
	}
	if got := ingest.RunUpload(series.Waiting); got != ingest.UploadInProgress {
		t.Errorf("a waiting run reads as %q, want in progress", got)
	}
	if got := ingest.RunUpload(series.Superseded); got != ingest.UploadCompleted {
		t.Errorf("a superseded run reads as %q, want completed", got)
	}
}
