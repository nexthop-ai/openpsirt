// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
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
// The window was taken from the environment variable alone, once, at startup.
// That is zero unless somebody exports it, and zero reads as "nothing is ever
// stale" — so on a stock install the bound was inert and a group somebody left
// went on granting roles through their token exactly as before. The test that
// covered the bound built its own window and never went through this, so the
// suite stayed green.
func TestTheDerivedGrantWindowIsNeverNone(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
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

		// And the administrator's setting decides, per request rather than at
		// startup: somebody shortening it to cut off a departed employee's
		// tokens gets the shorter window without restarting anything.
		window := httpapi.DerivedWindow(settings, 12*time.Hour)
		if err := settings.Set(ctx, setting.SessionLifetime, "2h"); err != nil {
			t.Fatal(err)
		}
		if got := window(ctx); got != 2*time.Hour {
			t.Errorf("after the setting was shortened the bound is %v, want 2h", got)
		}
	})
}
