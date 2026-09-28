// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/uptrace/bun"
)

// An issue's files are listed to whoever may read the issue, at the visibility
// its places carry, and to nobody else. An upload waiting for text that has not
// been saved is not on the list.
//
// Verified by deleting the mayReach call in ForIssue, which lists the
// undisclosed issue's file to a public reader, and by deleting its
// `attached_at IS NOT NULL` condition, which lists the waiting upload.
func TestAnIssuesFilesAreListedOnlyToWhoeverMayReadIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		undisclosed := f.anIssue(t, "CVE-2026-9001", access.Private)
		reader := f.who(t, access.PublicRead)
		trusted := f.who(t, access.PublicTriage, access.PrivateTriage)

		// Evidence on the issue is held by the issue the moment it arrives;
		// an upload for a draft waits for the text that will point at it.
		shown, err := f.store.Upload(ctx, trusted,
			attach.Against{ProductID: f.product, VulnerabilityID: f.issue}, "shown.log",
			strings.NewReader("open knowledge"), 14, roomy, plenty, plenty, true)
		if err != nil {
			t.Fatalf("upload evidence: %v", err)
		}
		f.upload(t, trusted, "draft.log", []byte("draft"))
		if _, err := f.store.Upload(ctx, trusted,
			attach.Against{ProductID: f.product, VulnerabilityID: undisclosed}, "hidden.log",
			strings.NewReader("not announced"), 13, roomy, plenty, plenty, true); err != nil {
			t.Fatalf("upload against an undisclosed issue: %v", err)
		}

		listed, err := f.store.ForIssue(ctx, reader, f.product, f.issue)
		if err != nil {
			t.Fatalf("a reader listing a public issue's files: %v", err)
		}
		if len(listed) != 1 || listed[0].Token != shown.Token {
			t.Errorf("a public issue lists %+v, want the one attached file", listed)
		}

		if rows, err := f.store.ForIssue(ctx, reader, f.product, undisclosed); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a public reader listing an undisclosed issue's files got %d rows and %v, want a refusal",
				len(rows), err)
		}
		rows, err := f.store.ForIssue(ctx, trusted, f.product, undisclosed)
		if err != nil || len(rows) != 1 {
			t.Errorf("somebody who may see undisclosed work listed %d rows: %v", len(rows), err)
		}
	})
}

// A product somebody cannot see answers exactly as a product that is not
// declared, and the identifier they named is never looked up: resolving it
// first would make the refusal a directory of what exists.
//
// Verified by deleting the `subject.Kind != access.Person ||
// !subject.Sees(named.ID)` arm in Issue: the answer stays the same, because
// the reach check after the lookup refuses too, and the statement against the
// vulnerability table is what fails the test.
func TestAnUnseenProductIsRefusedBeforeTheIssueIsLookedUp(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		elsewhere := access.NewPerson(9999, "elsewhere@example.com", false,
			map[int64][]access.Role{f.product + 1000: {access.PublicRead}}, 0)
		pipeline := access.NewPipeline(1, "build", access.Scope{ProductID: f.product})

		asked := &issueLookups{}
		f.db.AddQueryHook(asked)

		for name, subject := range map[string]access.Subject{
			"somebody holding nothing on it": elsewhere,
			"a pipeline credential":          pipeline,
		} {
			asked.reset()
			_, _, err := f.store.Issue(ctx, subject, world.ProductName, identity)
			if !errors.Is(err, attach.ErrNoSuchIssue) {
				t.Errorf("%s got %v, want the answer an undeclared product gets", name, err)
			}
			if n := asked.count(); n != 0 {
				t.Errorf("for %s the identifier was looked up %d times before the refusal", name, n)
			}
		}
		if _, _, err := f.store.Issue(ctx, elsewhere, "nonesuch", identity); !errors.Is(err, attach.ErrNoSuchIssue) {
			t.Errorf("an undeclared product got %v", err)
		}
	})
}

// issueLookups counts the statements that read the vulnerability table.
type issueLookups struct {
	mu sync.Mutex
	n  int
}

func (c *issueLookups) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	if strings.Contains(event.Query, `"vulnerability"`) {
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
	}
	return ctx
}

func (c *issueLookups) AfterQuery(context.Context, *bun.QueryEvent) {}

func (c *issueLookups) reset() {
	c.mu.Lock()
	c.n = 0
	c.mu.Unlock()
}

func (c *issueLookups) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
