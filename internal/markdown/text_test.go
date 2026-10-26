// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown

import "testing"

func TestMarkdownIsReducedToTheWordsItShows(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain words", "plain words"},
		{"**Null** pointer _dereference_ of `p`", "Null pointer dereference of p"},
		{"See [the rule](https://example.com/rule) here", "See the rule here"},
		{"![a picture](https://example.com/x.png)", "a picture"},
		{"<https://example.com/a>", "https://example.com/a"},
		{"# Heading\n\n- one\n- two\n\n> quoted", "Heading\none\ntwo\nquoted"},
		{"before <b>bold</b> after", "before bold after"},
		{"<div>\nblock\n</div>\n\nafter", "after"},
		{"```\nint *p = 0;\n```", "int *p = 0;"},
		{"line one\nline two", "line one line two"},
		{"a \\_b\\_ &lt; c &#38; d", "a _b_ < c & d"},
		{"`a \\_b &lt; c`", "a \\_b &lt; c"},
	} {
		if got := Text(c.in); got != c.want {
			t.Errorf("Text(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
