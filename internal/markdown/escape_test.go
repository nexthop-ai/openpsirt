// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown_test

import (
	"strings"
	"testing"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// hostile is what a third party can put in a name, a version or a
// description: every construct a renderer would act on.
var hostile = []string{
	"[Download the fix](https://evil.example/p)",
	"![x](https://evil.example/t)",
	"<img src=https://evil.example/t.gif>",
	"<https://evil.example/p>",
	"<script>alert(1)</script>",
	"https://evil.example/p",
	"HTTPS://evil.example/p",
	"www.evil.example/p",
	"security@evil.example",
	"[x]: https://evil.example/p",
	"[x][y]",
	"# Heading",
	"## Heading",
	"- a list item",
	"+ a list item",
	"1. a numbered item",
	"1) a numbered item",
	"> a quotation",
	"---",
	"***",
	"___",
	"`code`",
	"*emphasis* and **strong** and _this_",
	"~~struck~~",
	"| a | b |",
	"&lt;script&gt; and &#60;",
	"trailing backslash \\",
	"\\[escaped already\\](https://evil.example/p)",
	"line one\n\n## Fixed upstream\n- [nothing](https://evil.example/p)",
	"carriage\r\n<https://evil.example/p>",
	"a tab\there",
	"@channel and @here",
}

// rendered is what a renderer with the common extensions makes of a document.
func rendered(t *testing.T, document string) ast.Node {
	t.Helper()
	md := goldmark.New(goldmark.WithExtensions(extension.GFM))
	return md.Parser().Parse(text.NewReader([]byte(document)))
}

func TestAnEscapedStringIsTextToARenderer(t *testing.T) {
	examined := 0
	for _, raw := range hostile {
		// Written where the documents write one: as a list item's content,
		// which begins a line as far as a block opener is concerned.
		document := "- " + markdown.Literal(raw) + "\n"
		root := rendered(t, document)
		var got strings.Builder
		items := 0
		_ = ast.Walk(root, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
			if !entering {
				return ast.WalkContinue, nil
			}
			switch typed := node.(type) {
			case *ast.ListItem:
				// The one the document wrote, and no list the string opened
				// inside it.
				if items++; items > 1 {
					t.Errorf("%q opened a list of its own:\n%s", raw, document)
				}
			case *ast.Document, *ast.List, *ast.TextBlock, *ast.Paragraph:
			case *ast.Text:
				got.Write(typed.Value([]byte(document)))
			case *ast.String:
				got.Write(typed.Value)
			default:
				t.Errorf("%q became %s:\n%s", raw, node.Kind(), document)
			}
			return ast.WalkContinue, nil
		})
		// And it reads as what was written, a line break aside.
		want := strings.Join(strings.Fields(raw), " ")
		if read := strings.Join(strings.Fields(shown(got.String())), " "); read != want {
			t.Errorf("%q reads as %q", raw, read)
		}
		examined++
	}
	if examined == 0 {
		t.Fatal("nothing was examined")
	}
}

// shown is text as a renderer displays it. The parser keeps a backslash
// escape in the text it holds, and the renderer drops the backslash.
func shown(held string) string {
	var out strings.Builder
	for i := 0; i < len(held); i++ {
		if held[i] == '\\' && i+1 < len(held) && strings.IndexByte(punctuation, held[i+1]) >= 0 {
			i++
		}
		out.WriteByte(held[i])
	}
	return out.String()
}

// punctuation is what CommonMark lets a backslash escape.
const punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

func TestOrdinaryNamesAreWrittenAsTheyAre(t *testing.T) {
	// A release note is read as source too, where a backslash before every
	// dot of every version would be noise in a document going to a customer.
	for _, name := range []string{
		"libnl-3-200", "6.12.41-1", "1:2.36-9", "grype 0.100.0", "python_dateutil",
		"2026-08-28", "CVE-2026-1234", "GHSA-xxxx-yyyy-zzzz", "linux-image (6.12)",
		"pkg:deb/debian/openssl?arch=amd64", "v1.0 broadcom", "-rc1", "1.x",
	} {
		if got := markdown.Literal(name); got != name {
			t.Errorf("%q was written as %q", name, got)
		}
	}
}
