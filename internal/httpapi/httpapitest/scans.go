// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/scansapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// Inventory is an inventory as a build would send one, built around a time so
// a test can place one scan before another.
func Inventory(builtAt time.Time, component string) string {
	return fmt.Sprintf(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "serialNumber": "urn:uuid:%x",
	  "metadata": {
	    "timestamp": %q,
	    "component": {"bom-ref": "root", "name": "sonic-broadcom.bin", "version": "1.0"}
	  },
	  "components": [{"bom-ref": "a", "name": %q, "version": "2.41", "purl": "pkg:deb/debian/%s@2.41"}],
	  "dependencies": [{"ref": "root", "dependsOn": ["a"]}]
	}`, builtAt.UnixNano(), builtAt.UTC().Format(time.RFC3339), component, component)
}

// Nowish is a build time a moment ago, which every arrival check accepts.
func Nowish() time.Time { return time.Now().UTC().Add(-time.Hour) }

// Upload builds the multipart request a build sends.
func Upload(t *testing.T, path, inventory string, suppressions ...string) *http.Request {
	t.Helper()
	parts := []Part{{Field: "inventory", Filename: "sonic.cdx.json", Content: inventory}}
	for i, s := range suppressions {
		parts = append(parts, Part{Field: "suppressions", Filename: fmt.Sprintf("vex-%d.json", i), Content: s})
	}
	body, kind := Form(t, parts...)
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", kind)
	return req
}

// IngestFixture is a migrated database with one declared target and a server
// in front of it.
type IngestFixture struct {
	Handler http.Handler
	DB      *database.DB
	Queue   *queue.Queue
	Path    string
	// Key is a pipeline's credential for the declared target, which is how a
	// build actually sends.
	Key string
}

// Sending presents the pipeline's credential, the way a build would.
func (f *IngestFixture) Sending(req *http.Request) *http.Request {
	req.Header.Set("Authorization", "Bearer "+f.Key)
	return req
}

func (f *IngestFixture) Send(t *testing.T, req *http.Request) (int, scansapi.UploadResult) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.Handler.ServeHTTP(rec, f.Sending(req))
	var result scansapi.UploadResult
	if rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode response: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, result
}

// The four-engine form and the two-engine form of the same fixture. Which
// one a test uses is decided by the rule at dbtest.Two: a test that pins what
// a query does — what a list contains, what a filter hides, what a conflict
// looks like, what text comes back — runs on every engine, and a test that
// pins routing, who may reach what, or the shape of a response runs on two.
func EachIngest(t *testing.T, opts queue.Options, fn func(t *testing.T, f *IngestFixture)) {
	t.Helper()
	IngestOn(t, dbtest.Each, opts, fn)
}

func IngestOn(t *testing.T, on Engines, opts queue.Options, fn func(t *testing.T, f *IngestFixture)) {
	t.Helper()
	on(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		product := fixture.New(t, db).Product

		// A key scoped to the product, which is the common case: a key cannot
		// imply which release an upload is for, so the upload states it.
		rights := access.NewStore(db.DB)
		_, secret, err := rights.NewKey(ctx, "nightly", access.Scope{ProductID: product.ID})
		if err != nil {
			t.Fatal(err)
		}

		q := queue.New(db, opts)
		handler, _ := httpapi.New(quiet, nil, core.Deps{
			DB: db, Queue: q,
			Access: access.NewResolver(rights, access.Trust{}),
			// Small enough that a test can write a document past it. Every
			// other bound is the default, which OrDefault fills in.
			Limits: sbom.Limits{MaxBytes: 4096},
		})
		fn(t, &IngestFixture{
			Handler: handler, DB: db, Queue: q, Key: secret,
			Path: "/v1/products/" + fixture.ProductName + "/streams/" + fixture.BranchName +
				"/variants/" + fixture.CustomerVariant + "/scans",
		})
	})
}

// Receipts asks what became of what was filed, as whoever holds secret.
func Receipts(t *testing.T, f *IngestFixture, secret, path string) (int, scansapi.ReceiptsOutput) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	f.Handler.ServeHTTP(rec, req)

	var out scansapi.ReceiptsOutput
	if rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.Body); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

// Carrying is an inventory of however many components, each hung off the
// root, so one upload can be compared against another.
func Carrying(builtAt time.Time, components map[string]string) string {
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]string, 0, len(names))
	refs := make([]string, 0, len(names))
	for _, name := range names {
		version := components[name]
		rows = append(rows, fmt.Sprintf(
			`{"bom-ref": %q, "name": %q, "version": %q, "purl": "pkg:deb/debian/%s@%s"}`,
			name, name, version, name, version))
		refs = append(refs, strconv.Quote(name))
	}
	return fmt.Sprintf(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "serialNumber": "urn:uuid:%x",
	  "metadata": {"timestamp": %q,
	    "component": {"bom-ref": "root", "name": "sonic-broadcom.bin", "version": "1.0"}},
	  "components": [%s],
	  "dependencies": [{"ref": "root", "dependsOn": [%s]}]
	}`, builtAt.UnixNano(), builtAt.UTC().Format(time.RFC3339),
		strings.Join(rows, ","), strings.Join(refs, ","))
}

// ProductHere is the product the ingest fixture declared.
func ProductHere(t *testing.T, f *IngestFixture) int64 {
	t.Helper()
	product, err := catalog.NewStore(f.DB.DB).ProductByName(t.Context(), fixture.ProductName)
	if err != nil {
		t.Fatal(err)
	}
	return product.ID
}

// InventoryOf gives the build's newest upload the inventory it was read from,
// and finishes the run so it is one somebody could have read.
func (r *Reach) InventoryOf(t *testing.T, contents string) int64 {
	t.Helper()
	ctx := t.Context()
	target := r.TargetOf(t, SeededBuild)
	scan, err := ingest.NewStore(r.DB.DB).Newest(ctx, target)
	if err != nil || scan == nil {
		t.Fatalf("the build has no upload to hang an inventory on: %v", err)
	}
	document, err := ingest.NewDocuments(r.DB.DB).Write(ctx, scan.ID, ingest.InventoryKind, 0,
		strings.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	var runID int64
	if err := r.DB.DB.NewSelect().Table("scan_run").ColumnExpr(`"id"`).
		Where(`"target_id" = ?`, target).Order("id DESC").Limit(1).
		Scan(ctx, &runID); err != nil {
		t.Fatal(err)
	}
	if err := finding.NewStore(r.DB.DB).Finish(ctx, runID, "0.112.0", "2026-08-28",
		"", nil); err != nil {
		t.Fatal(err)
	}
	return document.ID
}

// Which names any two builds of a product differ on: two releases, two
// platforms of one release, or a tag and the branch it was cut from.

// Inventoried reads an inventory of these names at these versions for one
// build of mine, declaring the variant where it is new.
func (r *Reach) Inventoried(t *testing.T, variant, hash string, held map[string]string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	mine, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.VariantByName(ctx, mine.ID, variant); err != nil {
		if _, err := names.DeclareVariant(ctx, mine.ID, variant, true); err != nil {
			t.Fatal(err)
		}
	}
	top := graph.Described{Purl: "pkg:generic/mine-" + variant + "@1.0", Name: "mine-" + variant, Version: "1.0"}
	snap := graph.Snapshot{Root: top}
	for name, version := range held {
		component := graph.Described{
			Purl: "pkg:deb/debian/" + name + "@" + version, Name: name, Version: version,
		}
		snap.Components = append(snap.Components, component)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: top, Child: component})
	}
	r.Shipped(t, Build{"mine", "master", variant}, hash, snap)
}

// TwoPlatforms is one release built for two platforms that differ by one name
// each way and one version.
func (r *Reach) TwoPlatforms(t *testing.T) {
	t.Helper()
	r.Inventoried(t, "broadcom", "broadcom", map[string]string{
		"libc6": "2.41", "zlib1g": "1.3", "openssl": "3.0.11",
	})
	r.Inventoried(t, "mellanox", "mellanox", map[string]string{
		"libc6": "2.42", "curl": "8.4.0", "openssl": "3.0.11",
	})
}
