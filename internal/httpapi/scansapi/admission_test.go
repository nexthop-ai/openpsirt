// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// counted is a request body that records how much of it was read.
type counted struct {
	r    io.Reader
	read atomic.Int64
}

func (c *counted) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func (c *counted) Close() error { return nil }

// unread sends req with its body counted, and answers what came back and how
// many bytes of the body the server read.
func unread(f *httpapitest.IngestFixture, req *http.Request) (*httptest.ResponseRecorder, int64) {
	body := &counted{r: req.Body}
	req.Body = body
	rec := httptest.NewRecorder()
	f.Handler.ServeHTTP(rec, f.Sending(req))
	return rec, body.read.Load()
}

func TestAnUploadToAProductTheKeyDoesNotCoverIsRefusedUnread(t *testing.T) {
	limitedIngest(t, sbom.Limits{}, func(t *testing.T, f *httpapitest.IngestFixture) {
		ctx := t.Context()
		names := catalog.NewStore(f.DB.DB)
		other, err := names.DeclareProduct(ctx, "elsewhere", "Elsewhere")
		if err != nil {
			t.Fatal(err)
		}
		branch, err := names.DeclareStream(ctx, other.ID, fixture.BranchName, catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := names.DeclareVariant(ctx, other.ID, fixture.CustomerVariant, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := names.TargetFor(ctx, branch.ID, variant.ID); err != nil {
			t.Fatal(err)
		}

		inventory := httpapitest.Inventory(httpapitest.Nowish(), "libc6")
		path := func(product string) string {
			return strings.Replace(f.Path, "/"+fixture.ProductName+"/", "/"+product+"/", 1)
		}
		covered, coveredRead := unread(f, httpapitest.Upload(t, path("elsewhere"), inventory))
		nobody, nobodyRead := unread(f, httpapitest.Upload(t, path("no-such-product"), inventory))

		if covered.Code != http.StatusNotFound {
			t.Fatalf("an upload to a product the key does not cover returned %d: %s",
				covered.Code, covered.Body.String())
		}
		if coveredRead != 0 || nobodyRead != 0 {
			t.Errorf("a refused upload had %d and %d bytes of its body read", coveredRead, nobodyRead)
		}
		// The same answer as a product nobody declared, so the refusal says
		// nothing about which products exist. Each spells back the name it
		// was sent.
		spelled := bytes.ReplaceAll(covered.Body.Bytes(), []byte("elsewhere"), []byte("no-such-product"))
		if covered.Code != nobody.Code || !bytes.Equal(spelled, nobody.Body.Bytes()) {
			t.Errorf("a product the key does not cover answered %d %s, and one nobody declared %d %s",
				covered.Code, covered.Body.String(), nobody.Code, nobody.Body.String())
		}
	})
}

func TestADeclaredLengthPastTheLimitIsRefusedUnread(t *testing.T) {
	limitedIngest(t, sbom.Limits{MaxBytes: 4096}, func(t *testing.T, f *httpapitest.IngestFixture) {
		req := httpapitest.Upload(t, f.Path, httpapitest.Inventory(httpapitest.Nowish(), "libc6"))
		req.ContentLength = 2*4096 + 1
		rec, read := unread(f, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("a request declaring more than the limit returned %d: %s", rec.Code, rec.Body.String())
		}
		if read != 0 {
			t.Errorf("%d bytes of a request declaring more than the limit were read", read)
		}
	})
}

func TestUploadsPastTheSimultaneousLimitAreAskedToSendAgain(t *testing.T) {
	limitedIngest(t, sbom.Limits{}, func(t *testing.T, f *httpapitest.IngestFixture) {
		if err := setting.NewStore(f.DB.DB).Set(t.Context(), setting.UploadsAtOnce, "1"); err != nil {
			t.Fatal(err)
		}
		inventory := httpapitest.Inventory(httpapitest.Nowish(), "libc6")

		// The first upload is held part way through its body, so it holds
		// its place while the second arrives.
		whole := httpapitest.Upload(t, f.Path, inventory)
		content, err := io.ReadAll(whole.Body)
		if err != nil {
			t.Fatal(err)
		}
		pr, pw := io.Pipe()
		first := httptest.NewRequest(http.MethodPost, f.Path, pr)
		first.Header.Set("Content-Type", whole.Header.Get("Content-Type"))
		done := make(chan int)
		go func() {
			rec := httptest.NewRecorder()
			f.Handler.ServeHTTP(rec, f.Sending(first))
			done <- rec.Code
		}()
		// A write returns once the server has read it, so the place is held.
		if _, err := pw.Write(content[:64]); err != nil {
			t.Fatal(err)
		}

		second := httptest.NewRecorder()
		f.Handler.ServeHTTP(second, f.Sending(httpapitest.Upload(t, f.Path, inventory)))
		if second.Code != http.StatusServiceUnavailable {
			t.Errorf("an upload past the limit returned %d: %s", second.Code, second.Body.String())
		}
		if second.Header().Get("Retry-After") == "" {
			t.Error("an upload past the limit was not told when to send again")
		}

		if _, err := pw.Write(content[64:]); err != nil {
			t.Fatal(err)
		}
		_ = pw.Close()
		if code := <-done; code != http.StatusAccepted {
			t.Fatalf("the upload holding the place returned %d", code)
		}

		// The place is given back once an upload is answered.
		if code, _ := f.Send(t, httpapitest.Upload(t, f.Path, inventory)); code == http.StatusServiceUnavailable {
			t.Error("the place an answered upload held was not given back")
		}
	})
}
