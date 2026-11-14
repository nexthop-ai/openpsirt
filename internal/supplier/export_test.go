// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier

import (
	"context"
	"errors"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// FetchForTest points the pass at a fetcher that answers without a network.
//
// Here rather than beside Pass, so it is not in the binary: the real fetcher
// reaches a publisher's own service, whose contents change, so the pass cannot
// be exercised end to end any other way — and a seam for that is not something
// a running deployment has a use for.
func FetchForTest(p *Pass, fetch *Fetcher) { p.fetch = fetch }

// At fixes the clock, for a test that asks what happens at a given moment.
func (s *Store) At(now func() time.Time) *Store { return &Store{db: s.db, now: now} }

// FromForTest reads one supplier as a pass does, recording how it went.
func FromForTest(ctx context.Context, p *Pass, feed Feed) (Taken, error) { return p.from(ctx, feed) }

// RecordForTest records an advisory naming publisher and identifier as fetched
// from address, past the checks a fetched document meets first.
func RecordForTest(ctx context.Context, f *Fetcher, by access.Subject, feed Feed,
	address, publisher, identifier string) error {

	_, err := f.record(ctx, by, feed, entry{address: address}, []byte("{}"), read{whole: true},
		sbom.Advisory{Publisher: publisher, Identifier: identifier}, map[string]bool{})
	return err
}

// SteppedOver says whether a pass steps over the document err is about.
func SteppedOver(err error) bool {
	var u unreadable
	return errors.As(err, &u)
}
