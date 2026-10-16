// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"strconv"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestAnAttachmentSizeStoredPastTheCeilingIsReadAsTheCeiling(t *testing.T) {
	// An upgraded deployment can hold a value past the ceiling, and scratch
	// space is sized for the ceiling.
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		over := strconv.Itoa(2 * setting.MostAttachmentMaxSize)
		if _, _, err := setting.NewStore(db.DB).Change(ctx, setting.AttachmentMaxSize, over); err != nil {
			t.Fatal(err)
		}
		size, _, _, err := attachmentLimits(ctx, core.Deps{DB: db})
		if err != nil {
			t.Fatal(err)
		}
		if size != setting.MostAttachmentMaxSize {
			t.Errorf("a stored %s is read as %d, want the ceiling %d", over, size, setting.MostAttachmentMaxSize)
		}
	})
}
