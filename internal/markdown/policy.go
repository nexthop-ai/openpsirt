// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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

// allowedScheme reports whether a link may use this scheme. These are the only
// ones.
//
// `javascript:` in a link is the oldest attack there is, and a `data:` address
// lets a link become a page we appear to have served. Everything else is
// refused rather than argued about, autolinked text included.
//
// `attachment:` is a file held here, referred to by an opaque identifier and
// never by an address. It resolves through a path that asks who is looking,
// which is what makes it the one scheme an image may also use.
//
// Not a map anybody can widen. An exported map is a value every importer
// shares and any of them may write to at init, so one line in an unrelated
// package could add a scheme to the link policy for the whole process, with
// nothing in this file changed and no test here failing. Asked as a function
// over a closed list instead, which is a policy rather than a variable.
func allowedScheme(scheme string) bool {
	switch scheme {
	case "http", "https", "mailto", Attachment, Issue:
		return true
	}
	return false
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
// The document is parsed and its structure examined, not scanned as lines.
// Matching regular expressions against each line asks a different question
// from the one that matters: what the renderer will make of it. The two come
// apart in every direction —
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
//     looks exactly like a markup tag to a pattern, so honest text is refused.
//
// Asking the parser removes the whole class. The check here is over what will
// be rendered, because it is the same parse.
func inspect(source string) []Fault {
	document := parser.Parser().Parse(text.NewReader([]byte(source)))
	lines := newLineIndex(source)

	var faults []Fault
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch typed := node.(type) {
		case *ast.Image:
			// An image may come from a file held here and from nowhere else.
			// An image loaded from somewhere else fires from the browser of
			// everybody who reads the text, from inside the network, telling
			// whoever wrote it who is looking and when. On an undisclosed
			// finding that is a disclosure channel rather than a picture.
			destination := string(typed.Destination)
			line := lines.of(destination, node)
			if target, _ := schemeOf(destination); target.scheme != Attachment {
				faults = append(faults, Fault{
					Line:      line,
					Offending: destination,
					Reason: "an image has to be a file attached here, because one loaded from " +
						"anywhere else is fetched by the browser of everybody who reads this — " +
						"from inside the network, telling whoever wrote it who is looking and " +
						"when. Attach the file and refer to it",
				})
			} else if fault, bad := attachmentFault(line, destination, target); bad {
				faults = append(faults, fault)
			}
		case *ast.Link:
			destination := string(typed.Destination)
			if fault, bad := destinationFault(lines.of(destination, node), destination); bad {
				faults = append(faults, fault)
			}
		case *ast.AutoLink:
			destination := string(typed.URL([]byte(source)))
			if fault, bad := destinationFault(lines.of(destination, node), destination); bad {
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
	target, ok := schemeOf(destination)
	if !ok {
		// An address on another host has no scheme to name: what is wrong is
		// the two separators rather than a word, so it has a sentence of its
		// own.
		if target.scheme == "" {
			return Fault{
				Line: line, Offending: destination,
				Reason: "a link starting with two separators goes to another host, whatever " +
					"scheme the page was served over. Write the address in full, or make it " +
					"relative to this deployment",
			}, true
		}
		return Fault{
			Line: line, Offending: destination,
			Reason: fmt.Sprintf(
				"a link may use http, https, mailto, attachment or issue, and this uses %q",
				target.scheme),
		}, true
	}
	switch target.scheme {
	case Attachment:
		return attachmentFault(line, destination, target)
	case Issue:
		return issueFault(line, destination, target)
	}
	return Fault{}, false
}

// spellingFault refuses a reference scheme spelled any way but its own.
//
// A renderer resolves `attachment:` and `issue:` as written, so a reference in
// capitals, or with a control character in its scheme, is a link to nothing.
// Refused on its own, ahead of the identifier, because the identifier may be
// well formed.
func spellingFault(line int, destination string, target destinationTarget) (Fault, bool) {
	if target.written == target.scheme {
		return Fault{}, false
	}
	return Fault{
		Line: line, Offending: destination,
		Reason: fmt.Sprintf("a reference is written %s: exactly, in lower case, "+
			"because that is the spelling a reader's page resolves. This is written %q",
			target.scheme, target.written+":"),
	}, true
}

// issueFault judges what an issue reference names.
//
// Judged at submission for the reason an attachment reference is: a
// destination the scheme accepts and no identifier can address is a dead link
// from the moment it is typed, and the writer is here to be told.
//
// It does not ask whether we have that issue. Somebody writing about a flaw we
// have not seen yet is writing something true, and refusing it would make the
// text argue with the scan schedule.
func issueFault(line int, destination string, target destinationTarget) (Fault, bool) {
	if fault, bad := spellingFault(line, destination, target); bad {
		return fault, true
	}
	if namedIssue(target.rest) {
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
// References, the half that decides which files a piece of text keeps,
// recognizes only a minted identifier. A reference this accepts is one
// References counts, so a destination like `attachment:../../secret` is
// refused here, at the moment somebody can still fix it.
func attachmentFault(line int, destination string, target destinationTarget) (Fault, bool) {
	if fault, bad := spellingFault(line, destination, target); bad {
		return fault, true
	}
	if mintedToken(target.rest) {
		return Fault{}, false
	}
	return Fault{
		Line: line, Offending: destination,
		Reason: "an attachment is referred to by the identifier this deployment " +
			"minted for it — 32 hexadecimal characters — and nothing else " +
			"resolves to a file. Attach the file and use the reference it gives you",
	}, true
}

// destinationTarget is a destination read the way a browser reads it.
type destinationTarget struct {
	// scheme is in lower case, and empty for a relative destination or one
	// on another host.
	scheme string
	// written is the scheme as the destination spells it.
	written string
	// rest is what follows the scheme's colon.
	rest string
}

// schemeOf reads where a destination goes, and whether it is somewhere a link
// may go.
//
// What is judged is where the link will actually point rather than how it was
// spelled, so the destination is decoded and then normalized the way a
// browser's address parser normalizes it before anything is read from it.
//
// A destination with no scheme is relative. Those stay inside this deployment
// and are allowed — a link from one finding to another is ordinary.
func schemeOf(destination string) (destinationTarget, bool) {
	// A destination is kept as it was written and resolved when it is
	// rendered, so `&#106;avascript:` reads as harmless before decoding and
	// as `javascript:` in a browser.
	literal := strings.TrimSpace(stdhtml.UnescapeString(destination))
	destination = browserNormalized(literal)
	if destination == "" {
		return destinationTarget{}, true
	}
	// A destination beginning with two separators is an address on another
	// host that inherits whatever scheme the page was served over. A browser
	// reads `/` and `\` alike here, so all four spellings are one rule. A
	// relative link inside this deployment never starts with two separators,
	// and the referrer and new-tab rules a renderer applies to an absolute
	// link do not apply to a relative one.
	if len(destination) > 1 &&
		strings.ContainsAny(destination[:1], `/\`) &&
		strings.ContainsAny(destination[1:2], `/\`) {
		return destinationTarget{}, false
	}
	// Anything after a path separator, a query or a fragment is not a scheme,
	// and a browser takes the scheme up to the first colon.
	head := destination
	if cut := strings.IndexAny(head, "/?#"); cut >= 0 {
		head = head[:cut]
	}
	if !strings.Contains(head, ":") {
		return destinationTarget{}, true
	}
	scheme, _, _ := strings.Cut(destination, ":")
	// A control character inside a scheme is how one gets past a check that
	// trusts the text, so none is read as part of it.
	scheme = strings.Map(func(r rune) rune {
		if r <= ' ' {
			return -1
		}
		return r
	}, scheme)
	if scheme == "" {
		return destinationTarget{}, true
	}
	scheme = strings.ToLower(scheme)

	// The spelling and the remainder are read from the destination before
	// normalizing. A renderer matches a reference as written, so a tab or a
	// capital the browser would forgive is still a reference to nothing.
	written, rest, _ := strings.Cut(literal, ":")
	return destinationTarget{scheme: scheme, written: written, rest: rest}, allowedScheme(scheme)
}

// browserNormalized is an address as a browser's parser reads it: leading and
// trailing control characters and spaces removed, and every tab and newline
// removed wherever it sits.
func browserNormalized(address string) string {
	address = strings.TrimFunc(address, func(r rune) bool { return r <= ' ' })
	return strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\r':
			return -1
		}
		return r
	}, address)
}

// lineIndex maps a position in the source to the line it is on.
type lineIndex struct {
	source []byte
	starts []int
	// next is where the next search for each offending text begins, so a
	// destination written twice is found twice.
	next map[string]int
}

func newLineIndex(source string) lineIndex {
	starts := []int{0}
	for offset, r := range []byte(source) {
		if r == '\n' {
			starts = append(starts, offset+1)
		}
	}
	return lineIndex{source: []byte(source), starts: starts, next: map[string]int{}}
}

// of returns the 1-indexed line the given text appears on, for a node.
//
// Used in preference to the enclosing block's position, because a paragraph
// may run for twenty lines and pointing at its first one sends somebody to the
// wrong place. The search starts at the link's own text, or past the last
// place the same text was found, so a copy shown earlier in a fenced block or
// earlier in the same paragraph is not the one named. A link with no text
// starts at its block. A destination a reference definition supplies is
// written wherever the definition is, which may be above the block, so the
// whole source is searched after that.
func (l lineIndex) of(offending string, node ast.Node) int {
	fallback := l.at(node)
	if offending == "" {
		return fallback
	}
	start := textStart(node)
	if start < 0 {
		start = l.offset(node)
	}
	from := max(start, l.next[offending], 0)
	at := -1
	if from <= len(l.source) {
		if found := bytes.Index(l.source[from:], []byte(offending)); found >= 0 {
			at = from + found
		}
	}
	if at < 0 {
		at = bytes.Index(l.source, []byte(offending))
	}
	if at < 0 {
		// The destination was decoded by the parser and does not appear
		// literally — an entity-encoded scheme, say. The block is then the
		// most precise honest answer.
		return fallback
	}
	l.next[offending] = at + len(offending)
	return l.line(at)
}

// textStart returns where the first text inside a node begins in the source,
// or -1 where it holds none.
func textStart(node ast.Node) int {
	start := -1
	_ = ast.Walk(node, func(child ast.Node, entering bool) (ast.WalkStatus, error) {
		if typed, ok := child.(*ast.Text); ok && entering {
			start = typed.Segment.Start
			return ast.WalkStop, nil
		}
		return ast.WalkContinue, nil
	})
	return start
}

// at returns the 1-indexed line a node begins on, or 0 where it cannot be
// placed. A fault that cannot say where it is still reports what is wrong.
func (l lineIndex) at(node ast.Node) int {
	offset := l.offset(node)
	if offset < 0 {
		return 0
	}
	return l.line(offset)
}

// offset returns where the block holding a node begins in the source, or -1.
func (l lineIndex) offset(node ast.Node) int {
	// Only a block knows where it is. Asking an inline node panics, so the
	// walk goes up to the block containing it, which is the paragraph or list
	// item a person would look at anyway.
	for node != nil && node.Type() != ast.TypeBlock && node.Type() != ast.TypeDocument {
		node = node.Parent()
	}
	if node == nil {
		return -1
	}
	if lines := node.Lines(); lines != nil && lines.Len() > 0 {
		return lines.At(0).Start
	}
	return -1
}

// line returns the 1-indexed line an offset is on.
func (l lineIndex) line(offset int) int {
	for number := len(l.starts) - 1; number >= 0; number-- {
		if offset >= l.starts[number] {
			return number + 1
		}
	}
	return 0
}

// References lists the attachments a piece of text refers to, in the order it
// refers to them and without repeats.
//
// Read from the parsed document rather than by searching the source, so that a
// reference inside a fenced block or an inline code span — where it is being
// shown rather than made — is not counted. Somebody explaining how to write
// one of these should not thereby attach a file to their justification.
//
// Every node inspect judges a destination on is a node this reads one from.
// A reference Check accepts and this does not count is a file the sweep
// deletes while stored text still links to it.
func References(source string) []string {
	return referenced(source, Attachment, mintedToken)
}

// referenced is the walk a reference list does: a scheme, and what a
// destination has to look like to count as one.
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
		case *ast.AutoLink:
			destination = string(typed.URL([]byte(source)))
		default:
			return ast.WalkContinue, nil
		}
		target, _ := schemeOf(destination)
		if target.written != scheme {
			return ast.WalkContinue, nil
		}
		// Only what a reference of this kind looks like. Anything else is a
		// broken link in a document rather than something to go looking for,
		// and matching loosely would let text name rows by pattern.
		if !shaped(target.rest) || seen[target.rest] {
			return ast.WalkContinue, nil
		}
		seen[target.rest] = true
		found = append(found, target.rest)
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
// It exists to refuse a destination that is not an identifier at all:
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

// TokenBytes is how many random bytes an attachment's identifier carries. It
// is written as twice as many hexadecimal characters, lower case, which is the
// shape a reference to one has to take.
const TokenBytes = 16

// mintedToken reports whether a reference is shaped like one this deployment
// makes: TokenBytes written in hexadecimal, lower case.
func mintedToken(token string) bool {
	if len(token) != 2*TokenBytes {
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
// A colon is part of a name here. A sign-in through a trusted header mints
// identities like `proxy:dev`, and the editor writes whatever the identity is.
// A class stopping at the colon reads `@proxy:dev` as a mention of "proxy",
// which is nobody, and the person named is never told. That is the ordinary
// shape of an identity in a self-hosted deployment rather than an unusual one.
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
// It answers with what was typed, not with who it is. Whether a name is
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
		// Only prose, and a code span is the only thing that has to be
		// skipped to get that.
		//
		// A fenced or indented block keeps its content in Lines() with no
		// child text node, so the walk never descends into one. That is why a
		// pasted log line names nobody: it is goldmark's node layout, and the
		// rows in the test are what would catch an upgrade that changes it.
		// A code span is the case that differs:
		// parseCodeSpan appends text segments as children, so without this
		// the `@ana` in `look at @ana` would be read as a mention.
		if _, code := node.(*ast.CodeSpan); code {
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
