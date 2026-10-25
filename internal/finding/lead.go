// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// LeadAt is the finding a lead is on one build, where the subject may read
// it: the open one, or the newest where none is open. A lead nobody may read
// here and a lead that is not here are both ErrNoOpenFinding.
func (s *Store) LeadAt(ctx context.Context, subject access.Subject, targetID int64, placeIdentity string) (*Finding, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	visible, err := access.Readable(subject, productID)
	if err != nil {
		return nil, ErrNoOpenFinding
	}
	kinds, kindArgs := kind.Evidence.Where(`"f"."kind"`)
	var lead Finding
	err = s.db.NewSelect().Model(&lead).
		Where(`"f"."target_id" = ?`, targetID).
		Where(`"f"."place_identity" = ?`, placeIdentity).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(kinds, kindArgs...).
		OrderExpr(`CASE WHEN "f"."closed_at" IS NULL THEN 0 ELSE 1 END ASC, "f"."id" DESC`).
		Limit(1).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNoOpenFinding
	case err != nil:
		return nil, fmt.Errorf("read the lead at that place: %w", err)
	}
	return &lead, nil
}
