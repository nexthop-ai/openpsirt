// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// started is a configuration a start would accept, with somebody named to
// administer it, so that each case below changes the one thing it is about.
func started() config.Config {
	queueing := queue.DefaultOptions()
	return config.Config{
		BootstrapAdmins:   []string{"root"},
		QueueMaxAttempts:  queueing.MaxAttempts,
		QueueClaimTimeout: queueing.ClaimTimeout,
		QueueHeartbeat:    queueing.Heartbeat,
		QueueMaxHold:      queueing.MaxHold,
		QueueBackoff:      queueing.Backoff,
		ScannerTimeout:    time.Minute,
	}
}

func TestAStartThatWouldLeaveNobodyAdministeringIsRefused(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		cfg := started()
		cfg.BootstrapAdmins = nil
		cfg.GroupRoles = []access.Mapping{{Group: "platform", Grants: string(access.PublicRead)}}
		if _, _, err := prepare(t.Context(), cfg, discard(), db); err == nil ||
			!strings.Contains(err.Error(), "OPENPSIRT_GROUP_ROLES maps no group to admin") {
			t.Errorf("group mappings granting nobody administration started: %v", err)
		}
	})
}

func TestAScannerAllowedToOutlastItsHoldIsRefused(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		cfg := started()
		cfg.QueueMaxHold = time.Hour
		cfg.ScannerTimeout = time.Hour
		if _, _, err := prepare(t.Context(), cfg, discard(), db); err == nil ||
			!strings.Contains(err.Error(), "OPENPSIRT_SCANNER_TIMEOUT") {
			t.Errorf("a scanner timeout at the hold's ceiling started: %v", err)
		}
		cfg.ScannerTimeout = 30 * time.Minute
		if _, _, err := prepare(t.Context(), cfg, discard(), db); err != nil {
			t.Errorf("a configuration that should start was refused: %v", err)
		}
	})
}

// issuing is a provider that only says who issues its identifiers, which is
// all a start asks of one.
type issuing struct{ issuer string }

func (p issuing) Name() string   { return "ours" }
func (p issuing) Issuer() string { return p.issuer }
func (p issuing) Begin(context.Context, string) (string, signin.Pending, error) {
	return "", signin.Pending{}, nil
}
func (p issuing) Complete(context.Context, string, signin.Pending, string) (*signin.Identity, error) {
	return nil, nil
}

func TestAProviderOtherThanTheOneIdentifiersWereBoundUnderIsRefused(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		person, err := rights.Ensure(ctx, "alice", "Alice", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.Claim(ctx, person.ID, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := rights.MatchProvider(ctx, "https://a.example", "00u1", "alice"); err != nil {
			t.Fatal(err)
		}
		if err := onlyTheBoundProvider(ctx, rights,
			map[string]signin.Provider{"ours": issuing{"https://b.example"}}); err == nil {
			t.Error("a provider with another issuer started over identifiers bound under the first")
		}
		if err := onlyTheBoundProvider(ctx, rights,
			map[string]signin.Provider{"ours": issuing{"https://a.example"}}); err != nil {
			t.Errorf("the provider the identifiers were bound under was refused: %v", err)
		}
	})
}

func TestAProviderWithNoAddressToReturnToIsRefused(t *testing.T) {
	providers := map[string]signin.Provider{"ours": issuing{"https://a.example"}}
	if err := returnsTo(providers, ""); err == nil {
		t.Error("a provider with no address to send people back to was accepted")
	}
	if err := returnsTo(providers, "https://psirt.example"); err != nil {
		t.Errorf("a provider with an address was refused: %v", err)
	}
	if err := returnsTo(nil, ""); err != nil {
		t.Errorf("no provider and no address was refused: %v", err)
	}
}
