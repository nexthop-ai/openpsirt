// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

// mostReason bounds what a refusal records of what the sender was told.
const mostReason = 2000

// Refusal is the last upload of a series to a build that was turned away
// once its sender was admitted to the build.
type Refusal struct {
	bun.BaseModel `bun:"table:series_refusal,alias:sx"`

	ID           int64     `bun:"id,pk,autoincrement"`
	TargetID     int64     `bun:"target_id,notnull"`
	Series       string    `bun:"series,notnull"`
	SeriesFolded string    `bun:"series_folded,notnull"`
	Kind         kind.Kind `bun:"kind,notnull"`
	At           time.Time `bun:"at,notnull"`
	Reason       string    `bun:"reason,notnull"`
	Credential   *string   `bun:"credential"`
}

// Refused records that an upload of a series to a build was turned away,
// replacing the last refusal of that series there.
//
// A note about something that already failed. The caller logs what comes back
// and answers the sender either way, so failing to write it never turns a
// refusal the sender needs to read into a fault.
func (s *Store) Refused(ctx context.Context, r Refusal) error {
	r.Series = strings.TrimSpace(r.Series)
	// A name too long to be a series is one reason the upload was refused,
	// and the note keeps what fits.
	if runes := []rune(r.Series); len(runes) > database.NameWidth {
		r.Series = string(runes[:database.NameWidth])
	}
	r.SeriesFolded = typedname.Matching(r.Series)
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	// Cut where a character starts, since an engine checking the encoding
	// refuses a split one.
	r.Reason = bound.Head(r.Reason, mostReason)
	// An update and then an insert, for the reason a scan refusal is written
	// so: no portable upsert, and a series refused once is usually refused
	// again.
	res, err := s.db.NewUpdate().Model((*Refusal)(nil)).
		Set(`"series" = ?`, r.Series).
		Set(`"at" = ?`, r.At).
		Set(`"reason" = ?`, r.Reason).
		Set(`"credential" = ?`, r.Credential).
		Where(`"target_id" = ?`, r.TargetID).
		Where(`"kind" = ?`, r.Kind).
		Where(`"series_folded" = ?`, r.SeriesFolded).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("record that an upload was refused: %w", err)
	}
	changed, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("record that an upload was refused: %w", err)
	}
	if changed > 0 {
		return nil
	}
	if _, err := s.db.NewInsert().Model(&r).Exec(ctx); err != nil {
		// Two refusals arriving together: one inserted, and this one is
		// the same note.
		if database.IsDuplicate(err) {
			return nil
		}
		return fmt.Errorf("record that an upload was refused: %w", err)
	}
	return nil
}

// RefusalsOf is the refusals of a kind recorded against a build, newest
// first. The caller has already decided the subject reads the build's runs.
func (s *Store) RefusalsOf(ctx context.Context, targetID int64, k kind.Kind) ([]Refusal, error) {
	var out []Refusal
	if err := s.db.NewSelect().Model(&out).
		Where(`"sx"."target_id" = ?`, targetID).
		Where(`"sx"."kind" = ?`, k).
		OrderExpr(`"sx"."at" DESC, "sx"."id" DESC`).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the uploads turned away: %w", err)
	}
	return out, nil
}
