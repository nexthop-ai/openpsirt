// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// fillingAfterTheCheck is the handler's handle with another sender's job of
// the kind landing right after the door counts the waiting work: the backlog
// fills between the door's check and the queueing.
func fillingAfterTheCheck(kind string) func(t *testing.T, db *database.DB) *database.DB {
	return func(t *testing.T, db *database.DB) *database.DB {
		hooked, _ := dbtest.RivalAfterSelect(t, db, "job", 5*time.Second, func() error {
			_, err := queue.New(db, queue.DefaultOptions()).Add(t.Context(), kind, "somebody else's")
			return err
		})
		served := *db
		served.DB = hooked
		return &served
	}
}

// A backlog filling after the door let a scan in still answers 503 with when
// to send again, as the door's own refusal does.
func TestAScanQueuedIntoABacklogThatFilledIsToldWhenToRetry(t *testing.T) {
	opts := queue.DefaultOptions()
	opts.MaxBacklog = 1
	httpapitest.IngestThrough(t, dbtest.Two, opts, fillingAfterTheCheck(queue.Parse),
		func(t *testing.T, f *httpapitest.IngestFixture) {
			rec := httptest.NewRecorder()
			f.Handler.ServeHTTP(rec, f.Sending(httpapitest.Upload(t, f.Path,
				httpapitest.Inventory(httpapitest.Nowish(), "libc6"))))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("a scan queued into a full backlog answered %d: %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("a scan queued into a full backlog is not told when to send again")
			}
		})
}

// The same for an analyzer run.
func TestAnAnalyzerRunQueuedIntoABacklogThatFilledIsToldWhenToRetry(t *testing.T) {
	opts := queue.DefaultOptions()
	opts.MaxBacklog = 1
	httpapitest.IngestThrough(t, dbtest.Two, opts, fillingAfterTheCheck(queue.Analyze),
		func(t *testing.T, f *httpapitest.IngestFixture) {
			body, kind := httpapitest.Form(t,
				httpapitest.Part{Field: "sarif", Filename: "run.sarif", Content: clangRun},
				httpapitest.Part{Field: "series", Content: "nightly"})
			req := httptest.NewRequest(http.MethodPost, analyses(f), body)
			req.Header.Set("Content-Type", kind)
			rec := httptest.NewRecorder()
			f.Handler.ServeHTTP(rec, f.Sending(req))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("an analyzer run queued into a full backlog answered %d: %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("an analyzer run queued into a full backlog is not told when to send again")
			}
		})
}
