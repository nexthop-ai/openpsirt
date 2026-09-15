package markdown

import (
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

// parser is configured once, and is a parser only.
//
// **Raw HTML is refused at submission, not turned off here.** goldmark's
// parser produces RawHTML and HTMLBlock nodes whatever this is configured
// with; what read as "off at the parser" was a *renderer* option on an object
// whose renderer is never obtained. So the sentence described a mechanism that
// did not run, on the file a reviewer opens to tick the item — and the thing
// that actually stops markup is `inspect`, which refuses the submission
// naming the line it is on.
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
// representation is the source.
//
// A sanitizer, its policy, its language allowlist and a render entry point
// lived here and were reached by nothing that runs. A rule improved in them
// next year would have changed nothing for anybody, while `DESIGN-text.md`
// said sanitizing happened on every render — which is the shape somebody
// ticks a checklist against. The document says what happens now, and this
// file holds only what the submission check needs.
var parser = goldmark.New(goldmark.WithExtensions(extension.GFM))
