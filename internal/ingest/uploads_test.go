// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
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
