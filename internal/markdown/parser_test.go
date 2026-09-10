package markdown

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func TestRawMarkupIsRefusedByTheParserAndNotOnlyTheSanitizer(t *testing.T) {
	// Two layers stop raw markup, and this is the one that has to be checked
	// separately because the other hides it: with the sanitizer in front,
	// turning the parser's guard off changes nothing observable.
	//
	// The order matters. An allowlist of permitted tags is a thing that can be
	// wrong, and every interesting attack lives in the gap between what such a
	// list permits and what a browser does. Refusing the feature at the parser
	// removes the category rather than enumerating it.
	for _, raw := range []string{
		`<script>alert(1)</script>`,
		`before <img src=x onerror=alert(1)> after`,
		`<div onclick="alert(1)">x</div>`,
	} {
		var out bytes.Buffer
		if err := parser.Convert([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		// What the parser does with it — dropping the block outright, or
		// escaping it inline — differs by where it appeared, and either is
		// correct. What must not happen is it arriving as markup.
		for _, live := range tagsIn(out.String()) {
			for _, forbidden := range []string{"<script", "<img", "onerror", "onclick"} {
				if strings.Contains(strings.ToLower(live), forbidden) {
					t.Errorf("the parser emitted %q as live markup, before anything sanitized it: %q",
						forbidden, out.String())
				}
			}
		}
	}
}

// tagsIn returns the live markup in rendered output. Text that was escaped is
// not markup and cannot do anything.
func tagsIn(rendered string) []string {
	return regexp.MustCompile(`<[^>]*>`).FindAllString(rendered, -1)
}
