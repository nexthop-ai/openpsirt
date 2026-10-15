// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package directory_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

// The directory this deployment publishes is one this deployment's own
// supplier reader follows: from the provider description, through the feed,
// to the document and the digest beside it.
func TestThisDeploymentsDirectoryIsReadByItsOwnSupplierReader(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.issued(t, "A flaw in the recovery console")
		f.write(t)

		at, err := url.Parse(served)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(http.StripPrefix(at.Path,
			http.FileServer(http.Dir(f.where))))
		t.Cleanup(server.Close)
		reached, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		admin := access.Subject{Kind: access.Person, ID: f.who.ID, Identity: f.who.Identity,
			Admin: true}
		source, err := supplier.NewStore(f.db).Add(ctx, admin, f.product, "Ourselves",
			served+"provider-metadata.json")
		if err != nil {
			t.Fatal(err)
		}
		// Wound back, so the document issued a moment ago is past the mark.
		long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		source.CaughtUpTo, source.CaughtUpMark, source.CreatedAt = &long, "", long

		fetch := supplier.NewFetcher(f.db, sbom.Limits{}, outward.Excluded{})
		// The addresses the directory names are its published ones, answered
		// here by the test server.
		fetch.Client = &http.Client{Transport: hosted{at: reached.Host,
			inner: server.Client().Transport}}
		fetch.Pause = 0
		took, err := fetch.From(ctx, admin, *source)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 || took.Checked != 1 || took.Refused != 0 || took.Skipped != 0 {
			t.Errorf("reading this deployment's own directory took %+v, want the one "+
				"advisory, checked against its digest", took)
		}
	})
}

// The publisher the provider description names is the one every document it
// lists names, field for field.
func TestTheProviderDescriptionNamesThePublisherTheDocumentsDo(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		named := f.issued(t, "A flaw in the recovery console")
		f.write(t)

		var described struct {
			Publisher json.RawMessage `json:"publisher"`
		}
		if err := json.Unmarshal(f.read(t, "provider-metadata.json"), &described); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Document struct {
				Publisher json.RawMessage `json:"publisher"`
			} `json:"document"`
		}
		if err := json.Unmarshal(f.read(t, f.pathOf(t, named)), &doc); err != nil {
			t.Fatal(err)
		}
		var one, other bytes.Buffer
		if err := json.Compact(&one, described.Publisher); err != nil {
			t.Fatal(err)
		}
		if err := json.Compact(&other, doc.Document.Publisher); err != nil {
			t.Fatal(err)
		}
		if one.String() != other.String() {
			t.Errorf("the description names %s and the document %s", one.String(), other.String())
		}
	})
}

// hosted sends every request to the test server, whatever host it names.
type hosted struct {
	at    string
	inner http.RoundTripper
}

func (h hosted) RoundTrip(req *http.Request) (*http.Response, error) {
	sent := req.Clone(req.Context())
	sent.URL.Host = h.at
	return h.inner.RoundTrip(sent)
}
