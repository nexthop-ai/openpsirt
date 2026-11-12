// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"fmt"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

func TestFoldsAreReadInBatchesNoLongerThanAnEngineTakes(t *testing.T) {
	folds := make([]string, 2*database.BatchSize+1)
	for i := range folds {
		folds[i] = fmt.Sprint("fold-", i)
	}
	var read []string
	batches := 0
	if err := inFoldBatches(folds, func(batch []string) error {
		batches++
		if len(batch) > database.BatchSize {
			t.Errorf("a batch held %d folds, over %d", len(batch), database.BatchSize)
		}
		read = append(read, batch...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if batches != 3 {
		t.Errorf("%d batches were read, want 3", batches)
	}
	if !slices.Equal(read, folds) {
		t.Errorf("the batches covered %d folds, want each of the %d once", len(read), len(folds))
	}
	if err := inFoldBatches(nil, func([]string) error {
		t.Error("an empty list was read")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
