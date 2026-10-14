// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
)

func TestOnlyAPersonReachesAnAttachment(t *testing.T) {
	// A pipeline's key may be scoped to the product, and is still not somebody
	// who reads what a file hangs off: every read and write refuses it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		row := f.upload(t, f.who(t, access.PublicTriage), "evidence.txt", []byte("the request"))
		key := access.NewPipeline(9, "nightly", access.Scope{ProductID: f.product})

		if _, err := f.store.Find(ctx, key, row.Token); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a key found a file: %v", err)
		}
		if _, err := f.store.ForIssue(ctx, key, f.product, f.issue); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a key listed an issue's files: %v", err)
		}
		report := f.aReport(t, f.who(t, access.PublicTriage), nil)
		if _, err := f.store.ForReport(ctx, key, f.product, report); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a key listed a report's files: %v", err)
		}
		if _, err := f.store.Upload(ctx, key, attach.Against{ProductID: f.product, VulnerabilityID: f.issue},
			"more.txt", strings.NewReader("x"), 1, roomy, plenty, plenty, false); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a key put a file against an issue: %v", err)
		}
		// A token nothing was ever stored under answers as one somebody may
		// not reach, so redacting cannot be used to ask which tokens exist.
		if err := f.store.Redact(ctx, f.admin(t), strings.Repeat("0", 32),
			"A credential was attached."); !errors.Is(err, access.ErrDenied) {
			t.Errorf("redacting a token nothing holds answered %v", err)
		}
	})
}
