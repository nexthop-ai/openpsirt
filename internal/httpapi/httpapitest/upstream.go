// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// UpstreamAt serves an upstream over TLS: a CSAF provider description naming
// its publisher, no key, and a feed listing nothing. It answers the address of
// the description and the authorities the server is trusted by.
func UpstreamAt(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/csaf/provider-metadata.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"canonical_url":"`+base+`/.well-known/csaf/provider-metadata.json",`+
			`"publisher":{"category":"vendor","name":"Example Upstream","namespace":"https://upstream.example.test"},`+
			`"distributions":[{"rolie":{"feeds":[{"tlp_label":"WHITE","url":"`+base+`/.well-known/csaf/white/feed.json"}]}}],`+
			`"role":"csaf_provider","metadata_version":"2.0"}`)
	})
	mux.HandleFunc("/.well-known/csaf/white/feed.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"feed":{"id":"feed","title":"feed","entry":[]}}`)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	base = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return base + "/.well-known/csaf/provider-metadata.json", roots
}

// Rebuilt is the reach over the same deployment with its dependencies
// adjusted, for a test that needs one more thing wired.
func (r *Reach) Rebuilt(adjust func(*core.Deps)) *Reach {
	deps := r.Deps
	adjust(&deps)
	handler, api := httpapi.New(slog.New(slog.DiscardHandler), nil, deps)
	again := *r
	again.Handler, again.API, again.Deps = handler, api, deps
	return &again
}

// UpstreamStatement records, once, an upstream's statement about mine: zlib
// at 1.2.11 is not affected by CVE-2026-0001, for anybody shipping it. It
// answers the statement's identifier, the same one every time it is asked.
func (r *Reach) UpstreamStatement(t *testing.T) int64 {
	t.Helper()
	ctx := t.Context()
	product, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := r.Rights.ByIdentity(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	said := []finding.Statement{{
		Vulnerability: "CVE-2026-0001", Purl: "pkg:generic/zlib@1.2.11", Component: "zlib",
		About: "1.2.11", Status: "not_affected", Justification: "vulnerable_code_not_present",
		Placement: finding.PlacedAnybody,
	}}
	if _, _, err := finding.NewStore(r.DB.DB).RecordStatements(ctx,
		access.Subject{Kind: access.Person, ID: admin.ID}, product.ID, finding.Supplied{
			Source: finding.FromUpstream, Identifier: "VEX-upstream-CVE-2026-0001",
			Publisher: "Example Upstream", Document: "https://upstream.example.test/vex.json",
			Digest: strings.Repeat("a", 64),
		}, said); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := r.DB.DB.NewSelect().Model((*finding.Statement)(nil)).Column("id").
		Where(`"product_id" = ?`, product.ID).Where(`"source" = ?`, finding.FromUpstream).
		Where(`"superseded_at" IS NULL`).Scan(ctx, &id); err != nil {
		t.Fatal(err)
	}
	return id
}
