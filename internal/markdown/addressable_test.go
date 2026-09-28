// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package markdown_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// An address stored on its own goes through the judgment a link inside text
// goes through, all of it rather than the scheme alone — on the field a
// triager types and an approver reads.

func TestAnAddressStoredOnItsOwnIsJudgedLikeALink(t *testing.T) {
	for _, c := range []struct {
		what    string
		address string
		refused bool
	}{
		{"nowhere to point", "", false},
		{"an ordinary address", "https://example.test/issue/1", false},
		{"one without encryption, which is the author's choice", "http://example.test/x", false},
		{"somebody to write to", "mailto:security@example.test", false},
		{"a link inside this deployment", "/v1/findings/12", false},
		{"an attachment this deployment minted", "attachment:" + strings.Repeat("a", 32), false},
		{"an issue by its identifier", "issue:CVE-2026-1234", false},

		// A browser refuses this one and the page's policy refuses it again.
		{"a script", "javascript:alert(1)", true},
		// This is the class the restriction exists for: an installed handler
		// nobody here has heard of, handed a privileged person's click.
		{"an application scheme", "ms-msdt:calc", true},
		{"another one", "search-ms:query=x", true},
		// Two separators is another host, whatever it looks like.
		{"a protocol-relative address", "//evil.example/x", true},
		{"the backslash spelling of it", `/\evil.example/x`, true},
		// A browser strips a leading control character and removes a tab or
		// a newline anywhere, and then reads two separators.
		{"two separators with a tab between them", "/\t/evil.example/x", true},
		{"two separators with a newline between them", "/\n/evil.example/x", true},
		{"two separators after a control character", "\x01//evil.example/x", true},
		{"a script after a control character", "\x01javascript:alert(1)", true},
		{"a script with a tab in its scheme", "java\tscript:alert(1)", true},

		// What follows the scheme, judged as it is inside a link.
		{"an attachment reference that traverses", "attachment:../../etc/passwd", true},
		{"an attachment reference of the wrong length", "attachment:" + strings.Repeat("a", 31), true},
		{"an attachment reference that is not hexadecimal", "attachment:" + strings.Repeat("z", 32), true},
		{"an attachment reference naming nothing", "attachment:", true},
		{"an issue reference that traverses", "issue:../../secret", true},
		{"an issue reference that is not an identifier", "issue:!!!", true},
		{"an issue reference naming nothing", "issue:", true},
	} {
		err := markdown.Addressable(c.address)
		if (err != nil) != c.refused {
			t.Errorf("%s (%q): refused = %v, want %v (%v)",
				c.what, c.address, err != nil, c.refused, err)
		}
	}
}

func TestARefusedAddressSaysWhatIsWrongWithoutNamingALine(t *testing.T) {
	// There is no text for it to be on a line of, and "line 0" reads as a
	// position in something.
	err := markdown.Addressable("ms-msdt:calc")
	if err == nil {
		t.Fatal("an application scheme was accepted")
	}
	if strings.Contains(err.Error(), "line 0") {
		t.Errorf("a stored address is refused by line number: %q", err)
	}

	// And the message names what is wrong with it rather than an empty scheme:
	// the protocol-relative case has no scheme at all.
	err = markdown.Addressable("//evil.example/x")
	if err == nil {
		t.Fatal("an address on another host was accepted")
	}
	if strings.Contains(err.Error(), `""`) {
		t.Errorf("the refusal names an empty scheme rather than the address: %q", err)
	}
}

func TestTextPastTheBoundIsMatchableAsWhatItIs(t *testing.T) {
	// ErrTooLong is exported, which says a caller may match it, so the
	// refusal carries it through both Fault and Faults.
	err := markdown.Check(strings.Repeat("a", markdown.MaxBytes+1))
	if err == nil {
		t.Fatal("text past the bound was accepted")
	}
	if !errors.Is(err, markdown.ErrTooLong) {
		t.Errorf("text past the bound does not match ErrTooLong: %v", err)
	}
	// And it still reads as a sentence, with the size in it: the sentinel is
	// for a caller and the reason is for a person.
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal does not say what the limit is: %q", err)
	}

	// The other direction. A refusal for something else must not match it, or
	// a caller acting on the match acts on the wrong thing.
	other := markdown.Check("[x](javascript:alert(1))")
	if other == nil {
		t.Fatal("a script link was accepted")
	}
	if errors.Is(other, markdown.ErrTooLong) {
		t.Errorf("a script link matched ErrTooLong: %v", other)
	}
}

func TestOnlyAnAbsoluteAddressIsWrittenInsideAngleBrackets(t *testing.T) {
	// Inside <> anything but an absolute address is read as markup.
	for _, address := range []string{"style", "script", "findings/1", "issue:CVE-2026-1", "ftp://example.com/x"} {
		if markdown.Autolinkable(address) == nil {
			t.Errorf("%q is written into a document as <%s>", address, address)
		}
	}
	for _, address := range []string{"https://example.com/a", "http://example.com/a", "mailto:psirt@example.com"} {
		if err := markdown.Autolinkable(address); err != nil {
			t.Errorf("%q is refused: %v", address, err)
		}
	}
}
