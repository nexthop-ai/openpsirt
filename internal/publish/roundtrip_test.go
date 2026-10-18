// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

// What this deployment publishes is read back by this deployment's own
// readers: the supplier pass follows the provider description through the
// feed to every document and the digest beside it, takes the advisory and
// sets the VEX documents aside as it does any publisher's; and the VEX
// reader takes each VEX document, CSAF and OpenVEX alike, back into the
// statements it was written from, telling a statement about the component
// alone from one about the component inside the build.
func TestWhatThisDeploymentPublishesIsReadBackByItsOwnReaders(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		w, _ := publishedWorld(t, f)
		s := surfaceOver(w, 100000, nil)
		server := httptest.NewTLSServer(s.h)
		t.Cleanup(server.Close)
		reached, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		admin := access.Subject{Kind: access.Person, ID: w.Person.ID, Identity: w.Person.Identity,
			Admin: true}
		source, err := supplier.NewStore(w.DB.DB).Add(ctx, admin, w.Product.ID, "Ourselves",
			base+publish.MetadataPath)
		if err != nil {
			t.Fatal(err)
		}
		long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		source.CaughtUpTo, source.CaughtUpMark, source.CreatedAt = &long, "", long
		fetch := supplier.NewFetcher(w.DB.DB, sbom.Limits{}, outward.Excluded{})
		fetch.Client = &http.Client{Transport: hosted{at: reached.Host, inner: server.Client().Transport}}
		fetch.Pause = 0
		took, err := fetch.From(ctx, admin, *source)
		if err != nil {
			t.Fatal(err)
		}
		vexDocuments := 0
		for _, path := range strings.Fields(string(s.body(publish.IndexPath))) {
			if strings.HasPrefix(path[strings.LastIndex(path, "/")+1:], "vex-") {
				vexDocuments++
			}
		}
		if took.Documents != 1 || took.Skipped != vexDocuments || took.Refused != 0 ||
			took.Checked != 1 || took.Mismatched != 0 {
			t.Errorf("reading this deployment's own provider took %+v, want the advisory read and "+
				"checked against its digest, and %d VEX documents set aside", took, vexDocuments)
		}

		// The statements back, from the CSAF document about each issue.
		portable := statementsOf(t, s.body(pathOf(t, s, "CVE-2026-1001")))
		if len(portable) != 1 || portable[0].Status != sbom.NotAffected ||
			portable[0].Justification != "vulnerable_code_not_present" ||
			len(portable[0].Targets) != 1 || portable[0].Targets[0].Purl != openssl.Purl ||
			portable[0].Targets[0].Within != nil {
			t.Errorf("read back %+v, want openssl alone not affected", portable)
		}
		ours := statementsOf(t, s.body(pathOf(t, s, "CVE-2026-1002")))
		if len(ours) != 1 || ours[0].Status != sbom.NotAffected ||
			ours[0].Justification != "vulnerable_code_not_in_execute_path" ||
			len(ours[0].Targets) != 1 || ours[0].Targets[0].Purl != libnl.Purl ||
			ours[0].Targets[0].Within == nil ||
			ours[0].Targets[0].Within.Purl != sonicRoot.Purl {
			t.Errorf("read back %+v, want libnl inside the build not affected", ours)
		}

		// And from the OpenVEX document about the branch.
		openvex := statementsOf(t, s.body(publish.OpenVEXPath+w.Product.Name+"/"+w.Branch.Name+".json"))
		seen := 0
		for _, one := range openvex {
			switch one.Vulnerability {
			case "CVE-2026-1001":
				seen++
				if one.Targets[0].Purl != openssl.Purl || one.Targets[0].Within != nil {
					t.Errorf("OpenVEX read back %+v for CVE-2026-1001, want openssl alone", one.Targets)
				}
			case "CVE-2026-1002":
				seen++
				if one.Targets[0].Purl != libnl.Purl || one.Targets[0].Within == nil ||
					one.Targets[0].Within.Purl != sonicRoot.Purl {
					t.Errorf("OpenVEX read back %+v for CVE-2026-1002, want libnl inside the build",
						one.Targets)
				}
			}
		}
		if seen != 2 {
			t.Errorf("OpenVEX read back %d of the two statements: %+v", seen, openvex)
		}
	})
}

// pathOf is the path the CSAF VEX document about an issue is served at.
func pathOf(t *testing.T, s *surface, issue string) string {
	t.Helper()
	for _, path := range strings.Fields(string(s.body(publish.IndexPath))) {
		if strings.HasSuffix(path, "-"+strings.ToLower(issue)+".json") {
			return publish.DirectoryPath + path
		}
	}
	t.Fatalf("no document about %s is listed", issue)
	return ""
}

// statementsOf is what the VEX reader takes from a document.
func statementsOf(t *testing.T, document []byte) []sbom.Suppression {
	t.Helper()
	read, err := sbom.ReadSuppressions(bytes.NewReader(document), sbom.Limits{})
	if err != nil {
		t.Fatalf("the VEX reader refused a published document: %v\n%s", err, document)
	}
	return read
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
