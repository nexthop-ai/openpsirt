// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"log/slog"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
)

// Warning is how long before the signing key expires the deployment starts
// saying so. A key past its expiry signs nothing dated after it, and a
// deployment holding one refuses to start.
const Warning = 30 * 24 * time.Hour

// betweenChecks is how often the key's expiry is asked about.
const betweenChecks = 24 * time.Hour

// Watch says, at start and once a day after, when the signing key expires
// within Warning or has expired.
type Watch struct {
	signer *Signer
	logger *slog.Logger
	now    func() time.Time
}

// NewWatch watches the signer's key, or answers nil where there is no key or
// it never expires.
func NewWatch(signer *Signer, logger *slog.Logger) *Watch {
	if signer == nil || !signer.expires {
		return nil
	}
	return &Watch{signer: signer, logger: logger, now: time.Now}
}

// Run checks the key until the context ends.
func (w *Watch) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenChecks, func(ctx context.Context) { w.Check(ctx) })
}

// Check logs a warning where the key expires within Warning, or an error where
// it has expired, and answers whether it said anything.
func (w *Watch) Check(ctx context.Context) bool {
	now := w.now().UTC()
	until := w.signer.until
	switch {
	case !now.Before(until):
		w.logger.ErrorContext(ctx, "the key published documents are signed with has expired: "+
			"a document dated after its expiry cannot be signed, and the next start is refused",
			"fingerprint", w.signer.fingerprint, "expired", until.UTC().Format(time.RFC3339))
	case until.Sub(now) <= Warning:
		w.logger.WarnContext(ctx, "the key published documents are signed with expires soon: "+
			"extend it or configure another before then",
			"fingerprint", w.signer.fingerprint, "expires", until.UTC().Format(time.RFC3339))
	default:
		return false
	}
	return true
}
