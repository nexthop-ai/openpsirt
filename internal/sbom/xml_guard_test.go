// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"io"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// A declaration ends where the decoder ends it: a bracket inside its quotes
// does not end it, and a quote or bracket inside a comment within it is
// neither. Ended earlier, the guard reads what follows as a comment
// the decoder never saw, and counts no tag after it.
func TestATagAfterADeclarationIsStillBounded(t *testing.T) {
	long := "<a " + strings.Repeat("b", 200) + ">"
	for name, declaration := range map[string]string{
		"a bracket in quotes":          `<!DOCTYPE a "x><!--">`,
		"a quote in a comment":         `<!DOCTYPE x [<!-- ' -->]>`,
		"a bracket in a comment":       `<!DOCTYPE x [<!-- < -->]>`,
		"a nested bracket, no comment": `<!DOCTYPE x [<!ENTITY a "b">]>`,
		"a quote straight after <!":    `<!"x>`,
	} {
		t.Run(name, func(t *testing.T) {
			guard := &tagGuard{r: strings.NewReader(declaration + long), most: 64}
			if _, err := io.ReadAll(guard); !refusal.In(err) {
				t.Errorf("a tag past the bound after %s answered %v", name, err)
			}
		})
	}
}
