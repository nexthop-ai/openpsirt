// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWhatAScannerComplainedIsStillStorableOnceItIsBounded(t *testing.T) {
	// The scanner's complaints quote package names from the inventory, which
	// is somebody else's text, and the cut keeps the end — so the partial
	// character lands at the front of what is stored. It is written to the
	// run's caution and to the job's last error, where half a character is
	// stored as a replacement character.
	//
	// Swept over a length, because where the cut falls depends on how long the
	// whole complaint is: one fixed string is as likely as not to land on a
	// boundary and pass whatever the code does.
	for extra := range 4 {
		said := strings.Repeat("€", 400+extra)
		bounded := tail(said)
		if !utf8.ValidString(bounded) {
			t.Fatalf("at %d characters what the scanner said is not valid UTF-8: %q",
				400+extra, bounded)
		}
		if !strings.HasPrefix(bounded, "…") {
			t.Errorf("at %d characters a bounded complaint does not say that it was cut",
				400+extra)
		}
	}
}

func TestWhatIsKeptOfAChattyScannerIsStorable(t *testing.T) {
	// The bound is applied where the excess is dropped, and what survives is
	// written to the run's caution, where half a character is stored as a
	// replacement character. The trim beside it keeps the end, so a
	// partial character left at the tail of what was kept survives into the
	// stored value.
	//
	// Swept over a length because where the cut falls depends on how much
	// arrives before the ceiling: one fixed string is as likely as not to
	// land on a boundary and pass whatever the code does.
	for extra := range 4 {
		b := bounded{most: int64(1024 + extra)}
		said := strings.Repeat("€", 2048)
		if _, err := b.Write([]byte(said)); err != nil {
			t.Fatal(err)
		}
		if !b.over {
			t.Fatalf("at %d bytes the ceiling was not reached", 1024+extra)
		}
		if !utf8.ValidString(b.String()) {
			t.Errorf("at %d bytes what was kept is not valid UTF-8, so three engines "+
				"of four refuse the write recording it", 1024+extra)
		}
		if int64(len(b.String())) > b.most {
			t.Errorf("at %d bytes it kept %d", 1024+extra, len(b.String()))
		}
	}
}

// The end-keeping bound is stored too, so it cuts on a character boundary, and
// it keeps the end whatever size the writes arrive in.
func TestWhatIsKeptOfTheEndOfAChattyScannerIsStorable(t *testing.T) {
	for extra := range 4 {
		kept := trailing{most: int64(1024 + extra)}
		for range 64 {
			if _, err := kept.Write([]byte(strings.Repeat("€", 97))); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := kept.Write([]byte("the end")); err != nil {
			t.Fatal(err)
		}
		said := kept.String()
		if !kept.over {
			t.Fatalf("at %d bytes nothing was dropped", 1024+extra)
		}
		if !utf8.ValidString(said) {
			t.Errorf("at %d bytes what was kept is not valid UTF-8", 1024+extra)
		}
		if int64(len(said)) > kept.most {
			t.Errorf("at %d bytes it kept %d", 1024+extra, len(said))
		}
		if !strings.HasSuffix(said, "the end") {
			t.Errorf("at %d bytes the end was not kept", 1024+extra)
		}
		if int64(kept.kept.Len()) > 2*kept.most {
			t.Errorf("at %d bytes it held %d between trims", 1024+extra, kept.kept.Len())
		}
	}
}
