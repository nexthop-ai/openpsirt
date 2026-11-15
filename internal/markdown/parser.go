// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown

import (
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

// parser is configured once, and is a parser only.
//
// Raw HTML is refused at submission by `inspect`, which names the line it is
// on. goldmark's parser produces RawHTML and HTMLBlock nodes whatever it is
// configured with, so no parser option stops markup.
//
// Refusing beats escaping here. An allowlist of permitted tags is a thing that
// can be wrong, and every interesting attack lives in the gap between what such
// a list permits and what a browser does; nothing anybody needs for triage
// requires markup, so the category is removed rather than bounded. And a
// person told at submission can fix it, where a tag silently escaped is a
// person who typed something and got something else.
//
// Nothing here renders. The submission policy walks what this parser produced
// and stores the source; every renderer is somebody else's — the interface for
// a browser, an integrator for their own application — and the API's only
// representation is the source. This package holds only what the submission
// check needs.
var parser = goldmark.New(goldmark.WithExtensions(extension.GFM))
