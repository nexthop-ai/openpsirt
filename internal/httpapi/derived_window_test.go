// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// TestTheDerivedGrantWindowIsNeverNone holds the line that the bound on a grant
// a group derived resolves the way a sign-in's does, through the wiring the
// process actually uses.
//
// A window of zero reads as "nothing is ever stale", so a group somebody left
// would go on granting roles through their token. The environment variable is
// zero unless somebody exports it, so it cannot be the only source.
func TestTheDerivedGrantWindowIsNeverNone(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		settings := setting.NewStore(db.DB)

		for _, c := range []struct {
			what       string
			settings   *setting.Store
			configured time.Duration
			want       time.Duration
		}{
			// The stock install: nothing exported, nothing set. The built-in
			// has to be what arrives, because none would mean never stale.
			{"a stock install", nil, 0, access.DefaultSessionLifetime},
			{"started with one", nil, 4 * time.Hour, 4 * time.Hour},
			{"nothing set, reading the database", settings, 0, access.DefaultSessionLifetime},
		} {
			if got := httpapi.DerivedWindow(c.settings, c.configured)(ctx); got != c.want {
				t.Errorf("%s bounds a derived grant at %v, want %v", c.what, got, c.want)
			}
		}

		// A read that fails answers the window configured, or the built-in,
		// and never none: a database that cannot answer must not leave a
		// derived grant that never goes stale.
		failing, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := settings.Get(failing, setting.SessionLifetime); err == nil {
			t.Fatal("a read on a cancelled context succeeded, so nothing here fails")
		}
		if got := httpapi.DerivedWindow(settings, 4*time.Hour)(failing); got != 4*time.Hour {
			t.Errorf("a failed read started with 4h bounds a derived grant at %v", got)
		}
		if got := httpapi.DerivedWindow(settings, 0)(failing); got != access.DefaultSessionLifetime {
			t.Errorf("a failed read on a stock install bounds a derived grant at %v", got)
		}

		// And the administrator's setting decides, per request rather than at
		// startup: somebody shortening it to cut off a departed employee's
		// tokens gets the shorter window without restarting anything.
		window := httpapi.DerivedWindow(settings, 12*time.Hour)
		if _, _, err := settings.Change(ctx, setting.SessionLifetime, "2h"); err != nil {
			t.Fatal(err)
		}
		if got := window(ctx); got != 2*time.Hour {
			t.Errorf("after the setting was shortened the bound is %v, want 2h", got)
		}
	})
}
