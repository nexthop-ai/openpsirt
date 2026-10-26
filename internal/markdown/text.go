// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown

import (
	"strings"

	"github.com/yuin/goldmark/ast"
	extast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
)

// Text is markdown reduced to the words it shows: emphasis, headings, lists
// and quotes without their markers, a link and an image as the words they
// show, code as written, and raw HTML left out. Blocks are separated by a
// line feed.
//
// It is for markdown somebody else wrote that is kept as text, such as an
// analyzer's message, which is shown encoded and never rendered.
func Text(source string) string {
	src := []byte(source)
	doc := parser.Parser().Parse(text.NewReader(src))
	var b strings.Builder
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		switch node := n.(type) {
		case *ast.RawHTML, *ast.HTMLBlock:
			return ast.WalkSkipChildren, nil
		case *ast.Text:
			if entering {
				b.Write(node.Segment.Value(src))
				if node.SoftLineBreak() || node.HardLineBreak() {
					b.WriteByte(' ')
				}
			}
		case *ast.String:
			if entering {
				b.Write(node.Value)
			}
		case *ast.AutoLink:
			if entering {
				b.Write(node.Label(src))
			}
		case *ast.CodeBlock, *ast.FencedCodeBlock:
			if entering {
				lines := n.Lines()
				for i := range lines.Len() {
					line := lines.At(i)
					b.Write(line.Value(src))
				}
			}
		case *extast.TableCell:
			if !entering {
				b.WriteByte(' ')
			}
		}
		if !entering && n.Type() == ast.TypeBlock && n.Kind() != ast.KindDocument {
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
				b.WriteByte('\n')
			}
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(collapse(b.String()))
}

// collapse writes each line with its own surrounding space removed and the
// empty lines between blocks left out.
func collapse(s string) string {
	lines := strings.Split(s, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
