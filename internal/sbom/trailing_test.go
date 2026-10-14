// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"io"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/bound/boundtest"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func fixtureText(t *testing.T, name string) string {
	t.Helper()
	raw, err := io.ReadAll(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestADocumentContinuingAfterItsTopLevelValueIsRefused(t *testing.T) {
	vex := fixtureText(t, "suppression-from-patch.openvex.json")
	advisory := fixtureText(t, "advisory-named-products.csaf.json")
	readers := []struct {
		name string
		body string
		read func(string) error
	}{
		{"inventory", minimal, func(body string) error {
			_, err := sbom.Read(strings.NewReader(body), sbom.DefaultLimits())
			return err
		}},
		{"inventory header", minimal, func(body string) error {
			_, err := sbom.ReadHeader(strings.NewReader(body), sbom.DefaultLimits())
			return err
		}},
		{"suppressions", vex, func(body string) error {
			_, err := sbom.ReadSuppressions(strings.NewReader(body), sbom.DefaultLimits())
			return err
		}},
		{"advisory", advisory, func(body string) error {
			_, err := sbom.ReadAdvisory(strings.NewReader(body), sbom.DefaultLimits())
			return err
		}},
	}
	for _, each := range readers {
		t.Run(each.name, func(t *testing.T) {
			if err := each.read(each.body + "\n\t \n"); err != nil {
				t.Fatalf("trailing whitespace was refused: %v", err)
			}
			for _, tail := range []string{each.body, "{}", "garbage", "]"} {
				err := each.read(each.body + "\n" + tail)
				if err == nil {
					t.Fatalf("a document followed by %.20q was read", tail)
				}
				if !refusal.In(err) || !strings.Contains(err.Error(), "continues after") {
					t.Fatalf("refused for another reason: %v", err)
				}
			}
		})
	}
}

func TestADocumentOfExactlyTheByteLimitIsRead(t *testing.T) {
	const limit = 4096
	feed := func(n int) error {
		body := minimal + strings.Repeat(" ", n-len(minimal))
		_, err := sbom.Read(strings.NewReader(body), sbom.Limits{MaxBytes: limit}.OrDefault())
		return err
	}
	boundtest.Edges(t, limit, feed, func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "larger than")
	})
}
