// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/csaf"
)

// listings writes the three files that say what the directory holds and the
// one that says what the directory is.
func (w *Writer) listings(ctx context.Context, published []entry) error {
	listed := make([]csaf.Listed, 0, len(published))
	for _, one := range published {
		listed = append(listed, one.Listed)
	}
	// The newest moment any of them was released, which is what the feed and
	// the provider description date themselves from. Taken from the documents
	// rather than from the clock, so that a pass over an unchanged directory
	// writes the bytes it wrote last time: dated now, every file would move
	// every hour and every reader would fetch the lot again.
	newest := csaf.Newest(listed)

	if err := w.put(ctx, indexFile, csaf.Index(listed), "text/plain; charset=utf-8"); err != nil {
		return err
	}
	if err := w.put(ctx, changesFile, csaf.Changes(listed), "text/csv; charset=utf-8"); err != nil {
		return err
	}
	feed, err := json.MarshalIndent(w.feed(listed), "", "  ")
	if err != nil {
		return fmt.Errorf("write the advisory feed: %w", err)
	}
	if err := w.put(ctx, feedFile, append(feed, '\n'), "application/json"); err != nil {
		return err
	}
	described, err := json.MarshalIndent(w.described(newest), "", "  ")
	if err != nil {
		return fmt.Errorf("write the provider description: %w", err)
	}
	return w.put(ctx, metadataFile, append(described, '\n'), "application/json")
}

// feed is the directory as a ROLIE feed.
//
// One feed, because the directory carries one label. The standard asks that
// every document of a label be in a single feed, and a second feed here would
// be a second label this deployment does not serve. The hash beside each
// document is named in its entry, which the standard requires wherever one
// exists.
func (w *Writer) feed(listed []csaf.Listed) csaf.Feed {
	return csaf.FeedOf(csaf.FeedName(w.who.Prefix), csaf.FeedTitle(w.who.Name, travels),
		w.who.At(feedFile), w.who.At, []csaf.Beside{{Rel: "hash", Suffix: hashSuffix}}, listed)
}

// described is the provider's description of itself. Nothing here is
// signed, so it names no key and claims the provider role alone.
func (w *Writer) described(newest time.Time) csaf.ProviderMetadata {
	return csaf.Describe(csaf.Description{
		Metadata: w.who.At(metadataFile), Directory: w.who.Published, Feed: w.who.At(feedFile),
		Name: w.who.Name, TLP: travels,
		// The publisher every document it lists names, built the same way.
		Publisher: advisory.IssuerOf(w.who),
		Listed:    w.settings.List, Mirrored: w.settings.Mirror, Newest: newest,
	})
}
