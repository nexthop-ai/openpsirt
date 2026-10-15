// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// AfterPage runs fn between the collection pass reading its page and acting on
// it.
//
// The window the pass's guard exists for: text naming an attachment is saved
// after the transaction that wrote it, so a comment landing in that gap is the
// ordinary case rather than a contrived one. Waiting for it to happen by
// itself is a test that passes by never racing.
func AfterPage(s *Store, fn func()) { s.afterPage = fn }

// MintToken is the identifier an attachment is given, for the check that text
// can refer to one.
func MintToken() (string, error) { return mintToken() }

// BeforeRecord runs fn inside an upload's transaction, between the room being
// checked and the row being written.
func BeforeRecord(s *Store, fn func()) { s.beforeRecord = fn }

// ObjectStore is a bucket on a stand-in object store on a loopback address,
// holding what it is sent in memory, and the address it answers on. It is
// closed when the test ends.
func ObjectStore(t *testing.T) (*Bucket, string) {
	t.Helper()
	held := map[string][]byte{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			held[r.URL.Path] = body
		case http.MethodGet:
			body, ok := held[r.URL.Path]
			if !ok {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
				return
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			delete(held, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)
	bucket, err := NewBucket(context.Background(), BucketConfig{
		Endpoint: server.URL, Bucket: "attachments", Region: "us-east-1",
		Key: "key", Secret: "secret", PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bucket, server.URL
}
