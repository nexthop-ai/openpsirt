package markdown

import (
	"bytes"
	"fmt"
	stdhtml "html"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// Schemes are the only ones a link may use.
//
// `javascript:` in a link is the oldest attack there is, and a `data:` address
// lets a link become a page we appear to have served. Everything else is
// refused rather than argued about, autolinked text included.
//
// `attachment:` is a file held here, referred to by an opaque identifier and
// never by an address. It resolves through a path that asks who is looking,
// which is what makes it the one scheme an image may also use.
var Schemes = map[string]bool{
	"http": true, "https": true, "mailto": true, Attachment: true, Issue: true,
}

// Attachment is the scheme a file held here is referred to by.
const Attachment = "attachment"

// Issue is the scheme one vulnerability is referred to by, wherever this
// deployment has it.
//
// An identifier and never an address, for the reason an attachment is: what a
// finding's address is — a product, a build, a component — is not what somebody
// writing "the same root cause as CVE-2026-1234" means. They mean the issue,
// and the address that answers that is the issue's own.
//
// Written rather than detected. A bare identifier in a sentence is text
// somebody wrote, and rewriting it into a link would make the tool edit
// prose — including inside a quotation, or a list of identifiers somebody is
// explaining rather than citing.
const Issue = "issue"

// inspect reports what is wrong with submitted text.
//
// **The document is parsed and its structure examined, not scanned as lines.**
// The first version of this matched regular expressions against each line, and
// that is a different question from the one that matters: what the renderer
// will make of it. The two came apart in every direction —
//
//   - A destination is entity-decoded before it becomes a link, so
//     `&#106;avascript:` reads as nothing dangerous to a pattern and as
//     `javascript:` to the renderer.
//   - A reference definition puts the destination on a line of its own, far
//     from the text that uses it, so a pattern looking for `](…)` finds
//     nothing at all.
//   - A link may be written across several lines, which a line-by-line reader
//     cannot see as one thing.
//   - And `<https://example.com>` — the standard way to write a bare link —
//     looks exactly like a markup tag to a pattern, so honest text was refused.
//
// Asking the parser removes the whole class. What is checked here is what will
// be rendered, because it is the same parse.
func inspect(source string) []Fault {
	document := parser.Parser().Parse(text.NewReader([]byte(source)))
	lines := lineIndexFor(source)

	var faults []Fault
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch typed := node.(type) {
		case *ast.Image:
			// An image may come from a file held here and from nowhere else.
			// The rule that nothing is fetched from a third party is
			// unchanged, and it is the whole rule: an image loaded from
			// somewhere else fires from the browser of everybody who reads
			// the text, from inside the network, telling whoever wrote it who
			// is looking and when. On an undisclosed finding that is a
			// disclosure channel rather than a picture.
			destination := string(typed.Destination)
			if scheme, _ := schemeOf(destination); scheme != Attachment {
				faults = append(faults, Fault{
					Line:      lines.of(destination, lines.at(node)),
					Offending: destination,
					Reason: "an image has to be a file attached here, because one loaded from " +
						"anywhere else is fetched by the browser of everybody who reads this — " +
						"from inside the network, telling whoever wrote it who is looking and " +
						"when. Attach the file and refer to it",
				})
			} else if fault, bad := attachmentFault(
				lines.of(destination, lines.at(node)), destination); bad {
				faults = append(faults, fault)
			}
		case *ast.Link:
			destination := string(typed.Destination)
			if fault, bad := destinationFault(lines.of(destination, lines.at(node)), destination); bad {
				faults = append(faults, fault)
			}
		case *ast.AutoLink:
			destination := string(typed.URL([]byte(source)))
			if fault, bad := destinationFault(lines.of(destination, lines.at(node)), destination); bad {
				faults = append(faults, fault)
			}
		case *ast.RawHTML, *ast.HTMLBlock:
			faults = append(faults, Fault{
				Line: lines.at(node),
				Reason: "markup is not interpreted here and will be shown as written. " +
					"Use markdown, or a fenced block if you meant to show the tag itself",
			})
		}
		return ast.WalkContinue, nil
	})
	return faults
}

// destinationFault judges where a link goes.
func destinationFault(line int, destination string) (Fault, bool) {
	scheme, ok := schemeOf(destination)
	if !ok {
		return Fault{
			Line: line, Offending: destination,
			Reason: fmt.Sprintf(
				"a link may use http, https, mailto, attachment or issue, and this uses %q",
				scheme),
		}, true
	}
	if scheme == Attachment {
		return attachmentFault(line, destination)
	}
	if scheme == Issue {
		return issueFault(line, destination)
	}
	return Fault{}, false
}

// issueFault judges what an issue reference names.
//
// Judged at submission for the reason an attachment reference is: the half
// that lists what a text refers to recognizes only an identifier, so a
// destination the scheme accepted and that half ignores is a dead link nothing
// reports — accepted when it was written and pointing at nothing when anybody
// read it.
//
// It does not ask whether we have that issue. Somebody writing about a flaw we
// have not seen yet is writing something true, and refusing it would make the
// text argue with the scan schedule.
func issueFault(line int, destination string) (Fault, bool) {
	value := strings.TrimPrefix(destination, Issue+":")
	if namedIssue(value) {
		return Fault{}, false
	}
	return Fault{
		Line: line, Offending: destination,
		Reason: "an issue is referred to by its identifier — issue:CVE-2026-1234 — and this " +
			"is not one. Whether we have it does not matter here; the shape does",
	}, true
}

// attachmentFault judges what an attachment reference names.
//
// The scheme was accepted and what followed it was not looked at, while
// References — the half that decides which files a piece of text actually
// pulls in — recognizes only a minted identifier. So `attachment:../../secret`
// was accepted when it was written and referred to nothing when it was read: a
// dead link nothing reported, and the same two-halves-of-one-rule disagreement
// the sanitizer had over relative links. Judged here instead, at the moment
// somebody can still fix it.
func attachmentFault(line int, destination string) (Fault, bool) {
	if mintedToken(strings.TrimPrefix(destination, Attachment+":")) {
		return Fault{}, false
	}
	return Fault{
		Line: line, Offending: destination,
		Reason: "an attachment is referred to by the identifier this deployment " +
			"minted for it — 32 hexadecimal characters — and nothing else " +
			"resolves to a file. Attach the file and use the reference it gives you",
	}, true
}

// schemeOf reads where a destination goes, and whether it is somewhere a link
// may go.
//
// The destination arrives already decoded by the parser, which is the point:
// what is judged is where the link will actually point rather than how it was
// spelled.
//
// A destination with no scheme is relative. Those stay inside this deployment
// and are allowed — a link from one finding to another is ordinary.
func schemeOf(destination string) (string, bool) {
	// Decoded first, and this is the whole point. A destination is kept as it
	// was written and resolved when it is rendered, so `&#106;avascript:`
	// reads as harmless here and as `javascript:` in a browser. Judging the
	// spelling rather than the meaning is how a check gets walked past.
	destination = strings.TrimSpace(stdhtml.UnescapeString(destination))
	if destination == "" {
		return "", true
	}
	// **A destination beginning with two separators is not relative**, whatever
	// the absence of a colon suggests. `//evil.example/x` is an address on
	// another host that inherits whatever scheme the page was served over, and
	// `/\evil.example/x` is the same thing to a browser — so read as relative,
	// both were accepted at submission and rendered as an anchor with neither
	// the referrer rule nor the new-tab rule applied, because neither applies
	// to something with no scheme. A reader clicking it navigated in the same
	// tab to a third party, handing over this deployment's own address — which
	// names the product, the build and the finding — as the referrer. A
	// relative link inside this deployment never starts with two separators.
	//
	// Asked as "two separators" rather than as a list of the two spellings
	// somebody thought of: a browser reads all four the same way, and the list
	// held `//` and `/\` while `\\` and `\/` went past it as relative.
	if len(destination) > 1 &&
		strings.ContainsAny(destination[:1], `/\`) &&
		strings.ContainsAny(destination[1:2], `/\`) {
		return "", false
	}
	// Anything before a path separator, a query or a fragment is not a scheme.
	head := destination
	if cut := strings.IndexAny(head, "/?#"); cut >= 0 {
		head = head[:cut]
	}
	scheme, found := strings.CutSuffix(head, ":")
	if !found {
		// No colon before the first separator, so nothing is claiming to be a
		// scheme: this is relative.
		if !strings.Contains(head, ":") {
			return "", true
		}
		scheme, _, _ = strings.Cut(head, ":")
	}
	// Whitespace and control characters inside a scheme are how one gets past
	// a check that trusts the text: browsers strip them and act on what is
	// left.
	scheme = strings.Map(func(r rune) rune {
		if r <= ' ' {
			return -1
		}
		return r
	}, scheme)
	if scheme == "" {
		return "", true
	}

	lowered := strings.ToLower(scheme)
	return lowered, Schemes[lowered]
}

// lineIndex maps a position in the source to the line it is on.
type lineIndex struct {
	source []byte
	starts []int
}

func newLineIndex(source string) lineIndex {
	starts := []int{0}
	for offset, r := range []byte(source) {
		if r == '\n' {
			starts = append(starts, offset+1)
		}
	}
	return lineIndex{source: []byte(source), starts: starts}
}

// of returns the 1-indexed line the given text appears on.
//
// Used in preference to the enclosing block's position, because a paragraph
// may run for twenty lines and pointing at its first one sends somebody to the
// wrong place. What a person will do is search for the offending text, so this
// does the same.
func (l lineIndex) of(offending string, fallback int) int {
	if offending == "" {
		return fallback
	}
	at := bytes.Index(l.source, []byte(offending))
	if at < 0 {
		// The destination was decoded by the parser and does not appear
		// literally — an entity-encoded scheme, say. The block is then the
		// most precise honest answer.
		return fallback
	}
	for number := len(l.starts) - 1; number >= 0; number-- {
		if at >= l.starts[number] {
			return number + 1
		}
	}
	return fallback
}

// at returns the 1-indexed line a node begins on, or 0 where it cannot be
// placed. A fault that cannot say where it is still reports what is wrong.
func (l lineIndex) at(node ast.Node) int {
	// Only a block knows where it is. Asking an inline node is not merely
	// unanswerable — it panics — so the walk goes up to the block containing
	// it, which is the paragraph or list item a person would look at anyway.
	for node != nil && node.Type() != ast.TypeBlock && node.Type() != ast.TypeDocument {
		node = node.Parent()
	}
	if node == nil {
		return 0
	}

	offset := -1
	if lines := node.Lines(); lines != nil && lines.Len() > 0 {
		offset = lines.At(0).Start
	}
	if offset < 0 {
		return 0
	}
	for number := len(l.starts) - 1; number >= 0; number-- {
		if offset >= l.starts[number] {
			return number + 1
		}
	}
	return 0
}

// lineIndexFor builds the map inspect uses.
func lineIndexFor(source string) lineIndex { return newLineIndex(source) }

// References lists the attachments a piece of text refers to, in the order it
// refers to them and without repeats.
//
// Read from the parsed document rather than by searching the source, so that a
// reference inside a fenced block or an inline code span — where it is being
// shown rather than made — is not counted. Somebody explaining how to write
// one of these should not thereby attach a file to their justification.
func References(source string) []string {
	return referenced(source, Attachment, mintedToken)
}

// Issues lists the vulnerabilities a piece of text refers to, in the order it
// refers to them and without repeats.
//
// Read from the parsed document for the reason attachment references are: an
// identifier inside a fenced block or a code span is being shown rather than
// cited, and somebody explaining how to write one of these should not thereby
// cite it.
//
// **Nothing is checked against the database here.** Whether we have that issue
// is a question with a subject attached, and this package holds no subject and
// reaches no rows. What it answers is what the text refers to; what that
// resolves to travels beside the text (REQ-65).
func Issues(source string) []string {
	return referenced(source, Issue, namedIssue)
}

// referenced is the walk both reference lists do, differing only in the scheme
// they are about and what shape a destination has to be.
func referenced(source, scheme string, shaped func(string) bool) []string {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	document := parser.Parser().Parse(text.NewReader([]byte(source)))
	var found []string
	seen := map[string]bool{}
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var destination string
		switch typed := node.(type) {
		case *ast.Image:
			destination = string(typed.Destination)
		case *ast.Link:
			destination = string(typed.Destination)
		default:
			return ast.WalkContinue, nil
		}
		if had, _ := schemeOf(destination); had != scheme {
			return ast.WalkContinue, nil
		}
		value := strings.TrimPrefix(destination, scheme+":")
		// Only what a reference of this kind looks like. Anything else is a
		// broken link in a document rather than something to go looking for,
		// and matching loosely would let text name rows by pattern.
		if !shaped(value) || seen[value] {
			return ast.WalkContinue, nil
		}
		seen[value] = true
		found = append(found, value)
		return ast.WalkContinue, nil
	})
	return found
}

// namedIssue reports whether a reference is shaped like an identifier a report
// gives a vulnerability: a letter, then letters, digits and separators.
//
// Deliberately a shape rather than a list of prefixes. CVE, GHSA and every
// vendor identifier a scan file carries — SONIC-2026-245447 among them — are
// all of this shape, and a list of the ones we have heard of would refuse a
// reference to an issue this deployment already holds.
//
// What it exists to refuse is a destination that is not an identifier at all:
// a path, an authority, anything carrying a slash or a colon. Bounded, because
// an identifier is a name rather than a document.
func namedIssue(value string) bool {
	if len(value) < 3 || len(value) > 64 {
		return false
	}
	if !isLetter(value[0]) {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !isLetter(c) && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// mintedToken reports whether a reference is shaped like one this deployment
// makes: 32 hexadecimal characters, lower case.
func mintedToken(token string) bool {
	if len(token) != 32 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// mention is a name written after an @, as the editor writes one.
//
// **A colon is part of a name here.** A sign-in through a trusted header mints
// identities like `proxy:dev`, and the editor writes whatever the identity is —
// so a class that stopped at the colon read `@proxy:dev` as a mention of
// "proxy", which is nobody, and the person named was never told. That is the
// ordinary shape of an identity in a self-hosted deployment rather than an
// unusual one.
//
// Otherwise narrow: it must follow something that is not a word character, so
// an email address in the middle of a sentence is not read as a mention of
// whatever follows the @.
var mention = regexp.MustCompile(`(^|[^\w@.:-])@([A-Za-z0-9][A-Za-z0-9._:@-]{0,190})`)

// Mentions lists the identities a piece of text names, without repeats.
//
// Read from the parsed document like References, so that a name inside a
// fenced block or an inline code span — where it is being shown rather than
// written — is not one. Somebody pasting a log line that happens to contain an
// @ has not called for anybody.
//
// **What comes back is what was typed, not who it is.** Whether a name is
// somebody, and whether the reader may know that, is a question for the data
// layer; this only says what the text says.
func Mentions(source string) []string {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	document := parser.Parser().Parse(text.NewReader([]byte(source)))
	var found []string
	seen := map[string]bool{}
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		// Only prose. A code span and a fenced block are both showing text
		// rather than saying it, and the walk does not descend into either
		// for the same reason References does not.
		if _, code := node.(*ast.CodeSpan); code {
			return ast.WalkSkipChildren, nil
		}
		if _, fenced := node.(*ast.FencedCodeBlock); fenced {
			return ast.WalkSkipChildren, nil
		}
		if _, block := node.(*ast.CodeBlock); block {
			return ast.WalkSkipChildren, nil
		}
		words, ok := node.(*ast.Text)
		if !ok {
			return ast.WalkContinue, nil
		}
		for _, match := range mention.FindAllStringSubmatch(string(words.Value([]byte(source))), -1) {
			// Punctuation at the end is the sentence rather than the name:
			// "thanks @ana." and "@ana: yes" both name ana.
			name := strings.TrimRight(match[2], ".-_:")
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			found = append(found, name)
		}
		return ast.WalkContinue, nil
	})
	return found
}
