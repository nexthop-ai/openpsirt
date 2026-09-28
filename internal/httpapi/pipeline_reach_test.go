// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// A pipeline's key reads back what it sent and nothing else, on every read
// this deployment serves. The reads are taken from the registered operations
// rather than a list, so a route added later is held to the rule the day it
// is added.
//
// A narrowed operation admits every credential at the route and decides in
// the handler; reading() is what refuses a key there, and the walk is what
// reaches it.
//
// Verified by deleting the refusal in reading(): the reads that rely on it
// then answer a key 404, the answer for a name it may not see, where they
// refused it.
func TestAPipelineReadsNothingButWhatItSent(t *testing.T) {
	// What a sender may read, and what each answers here: its receipts, what
	// one upload changed, and a document it sent. The fixture's scan was not
	// sent by the key, so its document is not the key's to read.
	const build = "/v1/products/{product}/streams/{stream}/variants/{variant}"
	sent := map[string]int{
		build + "/scans":                             http.StatusOK,
		build + "/scans/{scan}/changes":              http.StatusOK,
		build + "/scans/{scan}/documents/{document}": http.StatusNotFound,
	}
	parameter := regexp.MustCompile(`\{[^}]+\}`)
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		checked, allowed := 0, 0
		for path, item := range r.api.OpenAPI().Paths {
			if item.Get == nil {
				continue
			}
			if asks, stated := item.Get.Extensions["x-openpsirt-requires"]; stated &&
				declaredScope(t, asks) == "none" {
				continue
			}
			at := parameter.ReplaceAllStringFunc(filled(path), func(name string) string {
				switch name {
				case "{vulnerability}", "{issue}":
					return "CVE-2026-9999"
				case "{component}":
					return "libnl-3-200"
				default:
					return "1"
				}
			})
			// A required query parameter is given a value, so that what
			// answers is the rule about the credential rather than a
			// complaint about the request.
			var asked []string
			for _, p := range item.Get.Parameters {
				if p.In == "query" && p.Required {
					asked = append(asked, p.Name+"=master")
				}
			}
			if len(asked) > 0 {
				at += "?" + strings.Join(asked, "&")
			}
			got := r.asKey(t, http.MethodGet, at)
			if want, ok := sent[path]; ok {
				allowed++
				if got != want {
					t.Errorf("a pipeline reading back what it sent at %s answered %d, want %d",
						at, got, want)
				}
				continue
			}
			checked++
			if got != http.StatusForbidden {
				t.Errorf("a pipeline reading %s answered %d, want 403", at, got)
			}
		}
		if checked == 0 || allowed != len(sent) {
			t.Fatalf("%d reads were refused and %d of %d sender reads were found, so this checked "+
				"less than it names", checked, allowed, len(sent))
		}
	})
}
