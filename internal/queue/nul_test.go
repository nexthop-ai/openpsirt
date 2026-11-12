// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A failure quoting a program's output with a NUL in it is recorded without
// the NUL, rather than leaving the job running because the record of its
// failure could not be written.
func TestAFailureQuotingANULIsRecorded(t *testing.T) {
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if _, err := q.Add(ctx, "ingest", "x"); err != nil {
			t.Fatal(err)
		}
		job, err := q.Claim(ctx, "worker", "ingest")
		if err != nil || job == nil {
			t.Fatalf("claim: %v %+v", err, job)
		}
		if err := q.Fail(ctx, job.ID, "worker", errors.New("grype said \x00 and stopped")); err != nil {
			t.Fatalf("a failure quoting a NUL was not recorded: %v", err)
		}
		var stored queue.Job
		if err := db.DB.NewSelect().Model(&stored).Where(`"id" = ?`, job.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if stored.LastError == nil || !strings.Contains(*stored.LastError, "grype said  and stopped") {
			t.Errorf("the failure was recorded as %v", stored.LastError)
		}
	})
}

// A postponement quoting a NUL or bytes that are not UTF-8 is recorded
// cleaned, as a failure is, rather than leaving the job claimed.
func TestAPostponementQuotingANULIsRecorded(t *testing.T) {
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if _, err := q.Add(ctx, "ingest", "x"); err != nil {
			t.Fatal(err)
		}
		job, err := q.Claim(ctx, "worker", "ingest")
		if err != nil || job == nil {
			t.Fatalf("claim: %v %+v", err, job)
		}
		if err := q.Postpone(ctx, job.ID, "worker", time.Minute, "no snapshot at /srv/\xff\x00records"); err != nil {
			t.Fatalf("a postponement quoting a NUL was not recorded: %v", err)
		}
		var stored queue.Job
		if err := db.DB.NewSelect().Model(&stored).Where(`"id" = ?`, job.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if stored.State != queue.Pending || stored.LastError == nil ||
			!strings.Contains(*stored.LastError, "no snapshot at /srv/") {
			t.Errorf("the postponement was recorded as %s %v", stored.State, stored.LastError)
		}
	})
}
