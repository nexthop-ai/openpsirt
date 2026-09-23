// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

// suppliersSilent is the condition that a configured supplier has not been
// read successfully in longer than this deployment allows.
//
// A supplier that stopped answering and one that has published nothing look
// the same from every screen but its own panel, so the silence is looked for
// rather than waited for. Measured from the last successful read, or from when
// the supplier was configured where none has succeeded: never having answered
// is the same silence.
//
// Never shorter in effect than two scan intervals, since a supplier is read
// once each. A deployment scanning fortnightly would otherwise hear every week
// that each supplier is silent, which is an alert nobody can clear (REQ-49).
//
// One per supplier, told to administrators, who are the ones who configure
// suppliers. It clears when a read succeeds, the supplier is withdrawn or its
// product is retired.
func (w *Watch) suppliersSilent(ctx context.Context) ([]Holds, error) {
	settings := setting.NewStore(w.db)
	after, err := settings.Duration(ctx, setting.SupplierSilentAfter,
		setting.DefaultSupplierSilentAfter)
	if err != nil {
		return nil, fmt.Errorf("read how long a supplier may go unread: %w", err)
	}
	every, err := settings.Duration(ctx, setting.ScanEvery, setting.DefaultScanEvery)
	if err != nil {
		return nil, fmt.Errorf("read how often suppliers are read: %w", err)
	}
	after = max(after, 2*every)

	var sources []struct {
		supplier.Source `bun:"extend"`

		Product string `bun:"product"`
	}
	err = w.db.NewSelect().
		Model((*supplier.Source)(nil)).
		ColumnExpr("sp.*").
		ColumnExpr(`p.display_name AS "product"`).
		Join(`JOIN "product" AS "p" ON p.id = sp.product_id`).
		Where("sp.retired_at IS NULL").
		// A retired product's suppliers are never read again, and retiring
		// the product does not withdraw them, so their silence is nobody's
		// to clear.
		Where("p.retired_at IS NULL").
		Scan(ctx, &sources)
	if err != nil {
		return nil, fmt.Errorf("read which suppliers are configured: %w", err)
	}
	now := time.Now().UTC()
	var out []Holds
	for _, one := range sources {
		since := one.CreatedAt
		if one.ReachedAt != nil {
			since = *one.ReachedAt
		}
		if now.Sub(since) < after {
			continue
		}
		body := fmt.Sprintf("The supplier %s for %s has not been read successfully since %s.",
			one.Display, one.Product, since.Format("2006-01-02"))
		if one.ReachedAt == nil {
			body = fmt.Sprintf("The supplier %s for %s has not been read successfully since "+
				"it was configured on %s.", one.Display, one.Product, since.Format("2006-01-02"))
		}
		if one.Failed != "" {
			body += " The last attempt stopped at: " + one.Failed
		}
		productID := one.ProductID
		out = append(out, Holds{
			// Keyed on the supplier alone, so a reason that changes between
			// attempts stays one condition rather than a new one each pass.
			About:     identify(fmt.Sprintf("supplier-silent %d", one.ID)),
			Body:      body,
			Link:      "/settings",
			ProductID: &productID,
		})
	}
	return out, nil
}
