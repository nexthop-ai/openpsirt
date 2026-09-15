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
	// run's caution and to the job's last error on four engines: PostgreSQL
	// refuses invalid UTF-8 outright and MySQL and MariaDB refuse it in
	// strict mode.
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
