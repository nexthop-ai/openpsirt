// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// upstreamsFailing is the condition that the upstream a product trusts cannot
// be read, and what to say when one that was failing is read again.
//
// Raised once the last attempt failed and nothing has been read for longer
// than two read intervals, so one failed read that the next one answers raises
// nothing. Measured from the last read that worked, or from when the upstream
// was trusted where none has. One per upstream, to administrators, who are
// the ones who trust upstreams. It clears when a read succeeds or the
// upstream stops being trusted; the first of those says so, once.
func (w *Watch) upstreamsFailing(ctx context.Context) ([]Holds, map[string]Holds, error) {
	every, err := setting.NewStore(w.db).Duration(ctx, setting.UpstreamEvery, setting.DefaultUpstreamEvery)
	if err != nil {
		return nil, nil, fmt.Errorf("read how often upstreams are read: %w", err)
	}
	var trusted []struct {
		upstream.Upstream `bun:"extend"`

		Product string `bun:"product"`
	}
	err = w.db.NewSelect().
		Model((*upstream.Upstream)(nil)).
		ColumnExpr("up.*").
		ColumnExpr(catalog.ShownExpr("p")+` AS "product"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "up"."product_id"`).
		Where(`"p"."retired_at" IS NULL`).
		Scan(ctx, &trusted)
	if err != nil {
		return nil, nil, fmt.Errorf("read which upstreams are trusted: %w", err)
	}
	now := time.Now().UTC()
	var failing []Holds
	recovered := map[string]Holds{}
	for _, one := range trusted {
		about := identify("upstream-failing " + strconv.FormatInt(one.ID, 10))
		productID := one.ProductID
		since := one.TrustedAt
		if one.ReachedAt != nil {
			since = *one.ReachedAt
		}
		if one.Failed == "" {
			recovered[about] = Holds{
				About: about, Link: weblink.Products(), ProductID: &productID,
				Body: fmt.Sprintf("The upstream of %s, %s, is read again.", one.Product, one.URL),
			}
			continue
		}
		if now.Sub(since) < 2*every {
			continue
		}
		last := "it has never been read"
		if one.ReachedAt != nil {
			last = "it was last read " + minute(*one.ReachedAt)
		}
		failing = append(failing, Holds{
			// Keyed on the upstream alone, so an error that changes between
			// attempts stays one condition rather than a new one each pass.
			About: about, Link: weblink.Products(), ProductID: &productID,
			Body: fmt.Sprintf("The upstream of %s, %s, cannot be read, and %s. The last attempt stopped at: %s",
				one.Product, one.URL, last, one.Failed),
		})
	}
	return failing, recovered, nil
}
