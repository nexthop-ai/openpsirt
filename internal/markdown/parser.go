package markdown

import (
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

// parser is configured once. Raw HTML is off **at the parser** rather than
// stripped afterwards: an allowlist of permitted tags is a thing that can be
// wrong, and every interesting attack lives in the gap between what such a
// list permits and what a browser actually does. Turning the feature off
// removes the category, and nothing anybody needs for triage requires it.
var parser = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(
		// Not WithUnsafe, and not WithXHTML. The default is to escape raw
		// HTML, which is the behavior being relied on.
		html.WithHardWraps(),
	),
)

// Nothing here renders. The submission policy walks what this parser produced
// and stores the source; every renderer is somebody else's — the interface for
// a browser, an integrator for their own application — and the API's only
// representation is the source.
//
// A sanitizer, its policy, its language allowlist and a render entry point
// lived here and were reached by nothing that runs. A rule improved in them
// next year would have changed nothing for anybody, while `DESIGN-text.md`
// said sanitizing happened on every render — which is the shape somebody
// ticks a checklist against. The document says what happens now, and this
// file holds only what the submission check needs.
