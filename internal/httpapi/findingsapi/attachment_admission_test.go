// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// countedBody is a request body that records how much of it was read.
type countedBody struct {
	r    io.Reader
	read atomic.Int64
}

func (c *countedBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func (c *countedBody) Close() error { return nil }

// attaching sends a file of size bytes as who, and answers what came back
// and how many bytes of the request the server read.
func attaching(t *testing.T, r *httpapitest.Reach, who, path string, size int) (*httptest.ResponseRecorder, int64) {
	t.Helper()
	body := &bytes.Buffer{}
	form := multipart.NewWriter(body)
	part, err := form.CreateFormFile("file", "evidence.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(bytes.Repeat([]byte("a"), size)); err != nil {
		t.Fatal(err)
	}
	if err := form.WriteField("evidence", "true"); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	length := int64(body.Len())
	counted := &countedBody{r: body}
	req := httptest.NewRequest(http.MethodPost, path, counted)
	req.ContentLength = length
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(httpapitest.TestHeader, who)
	httpapitest.FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec, counted.read.Load()
}

func TestAnAttachmentNobodyMayMakeIsRefusedUnread(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		const here = "/v1/products/mine/issues/CVE-2026-9999/attachments"

		// Somebody who reads the product and may not attach to it.
		reader, read := attaching(t, r, "reader", here, 4096)
		httpapitest.RefusedWith(t, reader, http.StatusForbidden)
		if read != 0 {
			t.Errorf("%d bytes of an attachment a reader may not make were read", read)
		}

		// An issue nobody filed, and a product the person holds nothing in,
		// answer alike and read nothing.
		absent, absentRead := attaching(t, r, "triager",
			"/v1/products/mine/issues/OPENPSIRT-2026-000001/attachments", 4096)
		elsewhere, elsewhereRead := attaching(t, r, "triager",
			"/v1/products/theirs/issues/CVE-2026-9999/attachments", 4096)
		if absent.Code != http.StatusNotFound {
			t.Fatalf("an issue nobody filed answered %d: %s", absent.Code, absent.Body.String())
		}
		if absentRead != 0 || elsewhereRead != 0 {
			t.Errorf("refused attachments had %d and %d bytes read", absentRead, elsewhereRead)
		}
		if absent.Code != elsewhere.Code || !bytes.Equal(absent.Body.Bytes(), elsewhere.Body.Bytes()) {
			t.Errorf("a product the person holds nothing in answered %d %s, and an issue nobody "+
				"filed %d %s", elsewhere.Code, elsewhere.Body.String(), absent.Code, absent.Body.String())
		}
	})
}

func TestAnAttachmentOfExactlyTheSizeAcceptedIsTaken(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		const most = 4096
		if err := setting.NewStore(r.DB.DB).Set(t.Context(), setting.AttachmentMaxSize,
			strconv.Itoa(most)); err != nil {
			t.Fatal(err)
		}
		const here = "/v1/products/mine/issues/CVE-2026-9999/attachments"

		if got, _ := attaching(t, r, "triager", here, most); got.Code != http.StatusCreated {
			t.Fatalf("a file of exactly the size accepted answered %d: %s", got.Code, got.Body.String())
		}
		if got, _ := attaching(t, r, "triager", here, most+1); got.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("a file one byte larger answered %d: %s", got.Code, got.Body.String())
		}

		// A request past the setting and the form around it is refused
		// before it is read.
		got, read := attaching(t, r, "triager", here, 2<<20)
		if got.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("a request far past the size accepted answered %d: %s", got.Code, got.Body.String())
		}
		if read != 0 {
			t.Errorf("%d bytes of a request far past the size accepted were read", read)
		}
	})
}

func TestAnAttachmentToAReportNobodyMayWorkIsRefusedUnread(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
			`{"summary":"They say the management socket lets anybody in."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording a claim answered %d: %s", got.Code, got.Body.String())
		}
		var recorded httpapitest.ReportRead
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		at := "/v1/products/mine/reports/" + recorded.Reference + "/attachments"

		// A reader of unannounced work opens the report and may not work it,
		// and somebody short of that may not open it at all.
		for _, c := range []struct {
			who  string
			want int
		}{{"private", http.StatusForbidden}, {"triager", http.StatusNotFound}} {
			who := c.who
			rec, read := attaching(t, r, who, at, 4096)
			httpapitest.RefusedWith(t, rec, c.want)
			if read != 0 {
				t.Errorf("%d bytes of an attachment %q may not make were read", read, who)
			}
		}
		if rec, _ := attaching(t, r, "private-triage", at, 4096); rec.Code != http.StatusCreated {
			t.Errorf("attaching to a report answered %d: %s", rec.Code, rec.Body.String())
		}
	})
}
