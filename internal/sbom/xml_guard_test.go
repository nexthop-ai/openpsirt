// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"io"
	"strings"
	"testing"
)

// A declaration ends what the guard reads. The reader refuses the document
// when the decoder returns the declaration, so the refusal names it whatever
// follows, an over-long tag included, and the guard never answers first.
func TestTheGuardLeavesADeclarationToTheReader(t *testing.T) {
	long := "<a " + strings.Repeat("b", 200) + ">"
	for name, declaration := range map[string]string{
		"a bracket in quotes":       `<!DOCTYPE a "x><!--">`,
		"a comment inside it":       `<!DOCTYPE x [<!-- ' -->]>`,
		"a nested bracket":          `<!DOCTYPE x [<!ENTITY a "b">]>`,
		"a quote straight after <!": `<!"x>`,
	} {
		t.Run(name, func(t *testing.T) {
			guard := &tagGuard{r: strings.NewReader(declaration + long), most: 64}
			if _, err := io.ReadAll(guard); err != nil {
				t.Errorf("the guard answered %v after %s, which the reader refuses", err, name)
			}
		})
	}
}
