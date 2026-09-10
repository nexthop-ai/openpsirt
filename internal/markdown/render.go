package markdown

import (
	"bytes"
	"context"
	"fmt"
	stdhtml "html"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

// renderTimeout bounds how long a caller waits for markup.
//
// Rendering is work somebody else asked us to do, and a pathological input
// should fail one request rather than hold one open indefinitely.
//
// **It bounds the wait, not the work.** A parse cannot be interrupted, so the
// goroutine doing it runs to completion with nobody reading the result. What
// this buys is that the request answers and its resources are released; what
// it does not buy is a cap on CPU. The cap on CPU is MaxBytes, applied before
// any of this starts — which is the control that actually bounds the work, and
// the reason a length limit is not merely tidiness.
const renderTimeout = 2 * time.Second

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

// sanitizer runs over the markup on the way out.
//
// Belt and braces, deliberately. The parser already refuses raw HTML and the
// policy already refused the text at submission — but stored text predates
// rules written since, and a control that only ran when the text arrived
// protects nothing written before it existed.
var sanitizer = policy()

func policy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()

	p.AllowElements("a", "p", "br", "hr", "blockquote",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"ul", "ol", "li", "dl", "dt", "dd",
		"strong", "em", "del", "code", "pre",
		"table", "thead", "tbody", "tr", "th", "td",
		"input") // task list checkboxes, which the extension emits disabled

	p.AllowAttrs("class").Matching(languageClass).OnElements("code")
	p.AllowAttrs("type", "checked", "disabled").OnElements("input")
	p.AllowAttrs("align").OnElements("th", "td")

	// Links, restricted to the schemes that cannot become a page or a script.
	//
	// `attachment` is among them because the submission check accepts it and
	// this is the same rule read from the other end: left out, the sanitizer
	// deleted the anchor and left the text, so a reference accepted when it
	// was written stopped being one when anybody read it — the disagreement
	// this file already carries a paragraph about for relative links. It
	// cannot become a page or a script either: no browser resolves it, and
	// what turns it into a path is the interface, against a file this
	// deployment holds.
	p.AllowAttrs("href").OnElements("a")
	p.AllowURLSchemes("http", "https", "mailto", Attachment, Issue)

	// A link to somewhere in this deployment is ordinary — one finding
	// referring to another — and the submission check says so and accepts it.
	// Without this the sanitizer then deleted the whole anchor and left the
	// text behind, so a link accepted when it was written silently stopped
	// being a link when anybody read it. Requiring the destination to parse is
	// what keeps "relative" from becoming "anything that is not a scheme we
	// recognize".
	p.AllowRelativeURLs(true)
	p.RequireParseableURLs(true)

	p.RequireNoFollowOnLinks(true)
	// Both halves. Opening in a new tab hands the opened page a reference back
	// to ours unless it is refused, and the address of the page somebody is
	// reading is itself worth not sending: a link in a comment on an
	// undisclosed finding would otherwise carry our internal address to
	// whoever runs the site at the other end.
	p.RequireNoReferrerOnFullyQualifiedLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)

	// Nothing is fetched. No image element is permitted at all, which is the
	// category rather than a rule about which addresses are acceptable: an
	// image fires from the browser of every reader, from inside the network,
	// and on an undisclosed finding that is a disclosure channel.
	return p
}

// languageClass is the only class a code block may carry, and only for a
// language that was allowlisted. Anything else keeps the block and loses the
// label.
//
// This is the single place the allowlist is applied. A second check on the way
// in looked like defense in depth and was really two spellings of one rule —
// which diverge, and then the tag a submission accepted is not the tag the
// sanitizer keeps.
var languageClass = languagePattern()

// Render turns stored source into markup.
//
// Called on the way out, every time, for every destination. What is stored is
// the source, so a rule written next year applies to text written last year.
func Render(ctx context.Context, source string) (string, error) {
	if len(source) > MaxBytes {
		return "", ErrTooLong
	}

	ctx, cancel := context.WithTimeout(ctx, renderTimeout)
	defer cancel()

	done := make(chan struct{})
	var (
		buffer bytes.Buffer
		err    error
	)
	go func() {
		defer close(done)
		err = parser.Convert([]byte(source), &buffer)
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("that took too long to render")
	case <-done:
	}
	if err != nil {
		return "", fmt.Errorf("render: %w", err)
	}

	return sanitizer.Sanitize(buffer.String()), nil
}

// Escaped is how text that came from a scan file is shown.
//
// Never rendered, whatever it looks like. Once a renderer exists, pointing it
// at a component description is the obvious next step — and that hands
// whoever wrote the scan file a formatting language aimed at the browsers of
// the people who hold the most access here.
func Escaped(text string) string { return stdhtml.EscapeString(text) }

// languagePattern builds the expression a code block's class must match.
//
// Built from the allowlist rather than written out, so adding a language is
// one edit and cannot drift from what the policy permits.
func languagePattern() *regexp.Regexp {
	names := make([]string, 0, len(Languages))
	for name := range Languages {
		names = append(names, regexp.QuoteMeta(name))
	}
	sort.Strings(names)
	return regexp.MustCompile(`^language-(` + strings.Join(names, "|") + `)$`)
}
