// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// A NUL anywhere in a document is dropped as it is read: every string a
// document carries may reach the database, and the query builder refuses one
// on two of the engines.
func TestANULInADocumentIsDroppedAsItIsRead(t *testing.T) {
	const body = `{"bomFormat":"CycloneDX","specVersion":"1.6",
	 "serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79\u0000",
	 "metadata":{"component":{"type":"application","name":"sonic","version":"1.0","bom-ref":"root"}},
	 "components":[{"type":"library","name":"libc6","version":"2.36","bom-ref":"libc",
	   "purl":"pkg:deb/debian/libc6@2.36","supplier":{"name":"Debian\u0000 Project"},
	   "licenses":[{"license":{"name":"LGPL\u0000-2.1"}}]}],
	 "dependencies":[{"ref":"root","dependsOn":["libc"]}]}`
	doc, err := sbom.Read(strings.NewReader(body), sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", doc), "\x00") {
		t.Errorf("the document was read with a NUL in it: %+v", doc)
	}
	if !strings.Contains(fmt.Sprintf("%+v", doc), "Debian Project") {
		t.Errorf("the text around the NUL was lost: %+v", doc)
	}
}
