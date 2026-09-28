// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

const token = "0f9a1b2c3d4e5f60718293a4b5c6d7e8"

// tokenShape is how a refusal describes a reference, at the width the store
// mints.
var tokenShape = fmt.Sprintf("%d hexadecimal characters", 2*markdown.TokenBytes)

func TestAnImageMayComeFromAnAttachmentAndNowhereElse(t *testing.T) {
	// An image loaded from a third party reports who read a finding and when,
	// which on an undisclosed one is a disclosure channel. A file held here is
	// fetched through a path that asks who is looking.
	for _, c := range []struct {
		what    string
		source  string
		refused bool
	}{
		{"a file held here", "![a screenshot](attachment:" + token + ")", false},
		{"somebody else's server", "![a screenshot](https://example.org/s.png)", true},
		{"a data address", "![a screenshot](data:image/png;base64,AAAA)", true},
		{"a relative address", "![a screenshot](/static/s.png)", true},
		{"a link to a file held here", "[the log](attachment:" + token + ")", false},
	} {
		t.Run(c.what, func(t *testing.T) {
			err := markdown.Check(c.source)
			if c.refused && err == nil {
				t.Errorf("an image from %s was accepted", c.what)
			}
			if !c.refused && err != nil {
				t.Errorf("an image from %s was refused: %v", c.what, err)
			}
		})
	}
}

func TestARefusedImageSaysToAttachTheFile(t *testing.T) {
	// The refusal has to name the thing to do instead. Somebody told only that
	// their image is not allowed writes no image and no explanation either.
	err := markdown.Check("![shot](https://example.org/s.png)")
	if err == nil {
		t.Fatal("a remote image was accepted")
	}
	if !strings.Contains(err.Error(), "Attach the file") {
		t.Errorf("the refusal does not say what to do instead: %v", err)
	}
}

func TestReferencesFindsWhatTheTextActuallyPointsAt(t *testing.T) {
	other := "1122334455667788990011223344556677"[:32]
	source := "Evidence: ![shot](attachment:" + token + ")\n\n" +
		"And again ![same](attachment:" + token + ") and [a log](attachment:" + other + ")\n"
	got := markdown.References(source)
	if len(got) != 2 || got[0] != token || got[1] != other {
		t.Errorf("references are %v, want each one once in the order they appear", got)
	}
}

func TestTextShowingAReferenceDoesNotMakeOne(t *testing.T) {
	// Somebody explaining how to write one of these has not attached a file,
	// and counting it would keep an upload alive that nothing points at.
	for _, source := range []string{
		"Write it as `![shot](attachment:" + token + ")`\n",
		"```\n![shot](attachment:" + token + ")\n```\n",
	} {
		if got := markdown.References(source); len(got) != 0 {
			t.Errorf("a reference being shown was counted as one made: %v", got)
		}
	}
}

func TestOnlyAMintedIdentifierCounts(t *testing.T) {
	// A reference to something shaped differently is a broken link in a
	// document, not a row to go looking for.
	for _, bad := range []string{"attachment:short", "attachment:" + strings.ToUpper(token),
		"attachment:../../etc/passwd", "attachment:"} {
		if got := markdown.References("[x](" + bad + ")"); len(got) != 0 {
			t.Errorf("%q resolved to %v", bad, got)
		}
	}
}

func TestMentionsAreReadFromProseAndNotFromCode(t *testing.T) {
	// a mention notifying at once tells whoever was named, so what counts
	// as naming somebody has to be narrow: a log line pasted into a
	// justification has not called for anybody, and being told you were
	// mentioned when you were not is how people learn to ignore the thing.
	for _, c := range []struct {
		what   string
		source string
		want   []string
	}{
		{"a plain mention", "Asking @ana about this.", []string{"ana"}},
		{"two, once each", "@ana and @ben and @ana again", []string{"ana", "ben"}},
		{"one at the start", "@ana asked.", []string{"ana"}},
		{"inside a code span", "Write it as `@ana` to call somebody", nil},
		{"inside a fenced block", "```\nfrom @ana to @ben\n```\n", nil},
		{"inside a fenced block with a language", "```log\nfrom @ana\n```\n", nil},
		// The shape a pasted stack trace actually takes. What keeps these out
		// is that goldmark holds a block's content in Lines() with no child
		// text node, so the walk never reaches it — these rows are what would
		// catch an upgrade that changes that.
		{"inside an indented block", "A log:\n\n    from @ana to @ben\n", nil},
		{"an email address", "Mail ops@example.com about it", nil},
		{"trailing punctuation is not part of the name", "Thanks @ana.", []string{"ana"}},
		// A sign-in through a trusted header mints identities like this, and
		// the editor writes whatever the identity is. Read as a mention of
		// "proxy", the person named is never told.
		{"an identity with a colon in it", "Asking @proxy:dev to look.", []string{"proxy:dev"}},
		{"a colon that ends the sentence", "@ana: could you?", []string{"ana"}},
	} {
		t.Run(c.what, func(t *testing.T) {
			got := markdown.Mentions(c.source)
			if len(got) != len(c.want) {
				t.Fatalf("read %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("read %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestAReferenceIsRefusedUnlessItNamesAFileThisDeploymentMinted(t *testing.T) {
	// References — the half that decides which files a piece of text actually
	// pulls in — recognizes only a minted identifier. Accepting any of these
	// would store a dead link nothing reports.
	for _, c := range []struct {
		what   string
		source string
	}{
		{"a path", "[the log](attachment:../../etc/passwd)"},
		{"a name", "[the log](attachment:report.pdf)"},
		{"nothing at all", "[the log](attachment:)"},
		{"a token one character short", "[the log](attachment:" + token[1:] + ")"},
		{"a token in capitals", "[the log](attachment:" + strings.ToUpper(token) + ")"},
		{"an image of a path", "![a screenshot](attachment:../secret)"},
	} {
		t.Run(c.what, func(t *testing.T) {
			err := markdown.Check(c.source)
			if err == nil {
				t.Fatalf("%s was accepted as an attachment reference", c.what)
			}
			// And it says what to write instead, because the person reading
			// this typed it and can fix it.
			if !strings.Contains(err.Error(), tokenShape) {
				t.Errorf("the refusal does not say what a reference looks like: %v", err)
			}
			// The proof it referred to nothing: the half that resolves them
			// never saw it either.
			if got := markdown.References(c.source); len(got) != 0 {
				t.Errorf("%s resolves to %v, so the two halves still disagree", c.what, got)
			}
		})
	}
}

func TestAReferenceSchemeInCapitalsIsRefusedForItsSpelling(t *testing.T) {
	// A renderer resolves `attachment:` and `issue:` as written in lower
	// case, so a reference in any other case is a dead link. The refusal
	// names the spelling, which is what is wrong, and never the identifier,
	// which is well formed.
	for _, c := range []struct {
		what   string
		source string
		wrong  string
	}{
		{"an attachment", "[the log](Attachment:" + token + ")", tokenShape},
		{"an attachment image", "![shot](ATTACHMENT:" + token + ")", tokenShape},
		{"an issue", "[the flaw](Issue:CVE-2026-1234)", "is not one"},
	} {
		t.Run(c.what, func(t *testing.T) {
			err := markdown.Check(c.source)
			if err == nil {
				t.Fatalf("%s with its scheme in capitals was accepted", c.what)
			}
			if !strings.Contains(err.Error(), "lower case") {
				t.Errorf("the refusal does not name the spelling: %v", err)
			}
			if strings.Contains(err.Error(), c.wrong) {
				t.Errorf("the refusal blames a well-formed identifier: %v", err)
			}
			if got := markdown.References(c.source); len(got) != 0 {
				t.Errorf("a refused reference resolves to %v", got)
			}
		})
	}
}

func TestEveryAttachmentReferenceCheckAcceptsIsOneReferencesCounts(t *testing.T) {
	// Check decides what may be stored and References decides which files the
	// stored text keeps. A reference one accepts and the other does not count
	// is a file the sweep deletes while the text still links to it.
	for _, c := range []struct {
		what   string
		source string
	}{
		{"a link", "[the log](attachment:" + token + ")"},
		{"an image", "![a screenshot](attachment:" + token + ")"},
		{"an autolink", "See <attachment:" + token + "> for the log"},
		{"a reference definition", "See [the log].\n\n[the log]: attachment:" + token + "\n"},
	} {
		t.Run(c.what, func(t *testing.T) {
			if err := markdown.Check(c.source); err != nil {
				t.Fatalf("%s was refused: %v", c.what, err)
			}
			if got := markdown.References(c.source); len(got) != 1 || got[0] != token {
				t.Errorf("%s was accepted and resolves to %v, so the file it names is swept", c.what, got)
			}
		})
	}
}
