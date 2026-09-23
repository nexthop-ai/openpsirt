package supplier_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"testing"
)

// sha256Of and sha512Of are a digest file as the usual checksum tools write
// one: the digest, two spaces, and the file's name.
func sha256Of(body, name string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func sha512Of(body string) string {
	sum := sha512.Sum512([]byte(body))
	return hex.EncodeToString(sum[:])
}

func TestADocumentMatchingTheDigestBesideItIsRecorded(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		body := advisory("EL-2026-0101", "libnl-3-200", "3.7.1", "CVE-2026-1101")
		p.publishes("/2026/EL-101.json", "2026-09-20T00:00:00Z", body)
		p.documents["/2026/EL-101.json.sha256"] = sha256Of(body, "EL-101.json")

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 || took.Recorded != 1 || took.Checked != 1 {
			t.Errorf("a document matching its digest was taken as %+v", took)
		}
	})
}

func TestADocumentThatDoesNotMatchItsDigestIsSteppedOver(t *testing.T) {
	// What was fetched is not what the publisher says they published.
	// Recorded, it would stand as their judgment.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		body := advisory("EL-2026-0102", "libnl-3-200", "3.7.1", "CVE-2026-1102")
		p.publishes("/2026/EL-102.json", "2026-09-20T00:00:00Z", body)
		p.documents["/2026/EL-102.json.sha256"] = sha256Of(body+" ", "EL-102.json")

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Refused != 1 || took.Documents != 0 || took.Recorded != 0 {
			t.Errorf("a document not matching its digest was taken as %+v", took)
		}
		// Stepped over rather than held: the same bytes fail the same way on
		// every pass.
		if took.Mark == "" {
			t.Error("the mark did not move past a document refused for its digest")
		}
	})
}

func TestAPageInPlaceOfADigestIsReadAsNoDigest(t *testing.T) {
	// Some servers answer an address they do not hold with a page of their
	// own and a 200. Refused, every document such a publisher issues would be
	// stepped over.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		body := advisory("EL-2026-0103", "libnl-3-200", "3.7.1", "CVE-2026-1103")
		p.publishes("/2026/EL-103.json", "2026-09-20T00:00:00Z", body)
		p.documents["/2026/EL-103.json.sha256"] = "<html>not here</html>"
		p.documents["/2026/EL-103.json.sha512"] = ""

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Recorded != 1 || took.Checked != 0 {
			t.Errorf("a document beside a page that holds no digest was taken as %+v", took)
		}
	})
}

func TestTheDigestAFeedEntryNamesIsTheOneCompared(t *testing.T) {
	// A feed entry says where its digest is, and a SHA-512 file is what
	// several publishers serve in place of a SHA-256 one.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		body := advisory("EL-2026-0104", "libnl-3-200", "3.7.1", "CVE-2026-1104")
		p.publishes("/2026/EL-104.json", "2026-09-20T00:00:00Z", body)
		p.linked["/2026/EL-104.json"] = "/sums/EL-104.json.sha512"
		p.documents["/sums/EL-104.json.sha512"] = sha512Of(body + "x")

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Refused != 1 || took.Recorded != 0 {
			t.Errorf("the digest the feed named was not the one compared: %+v", took)
		}
		for _, path := range p.asked {
			if path == "/2026/EL-104.json.sha256" || path == "/2026/EL-104.json.sha512" {
				t.Errorf("a digest was looked for beside the document when the feed named one: %s",
					path)
			}
		}
	})
}

func TestASHA512BesideTheDocumentIsFoundWhereNoSHA256Is(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		first := advisory("EL-2026-0105", "libnl-3-200", "3.7.1", "CVE-2026-1105")
		second := advisory("EL-2026-0106", "libnl-3-200", "3.7.1", "CVE-2026-1106")
		p.publishes("/2026/EL-105.json", "2026-09-20T00:00:00Z", first)
		p.publishes("/2026/EL-106.json", "2026-09-21T00:00:00Z", second)
		p.documents["/2026/EL-105.json.sha512"] = sha512Of(first)
		p.documents["/2026/EL-106.json.sha512"] = sha512Of(second)

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 2 || took.Checked != 2 {
			t.Errorf("a SHA-512 file beside each document was taken as %+v", took)
		}
		// The kind that answered is asked for first after, so the one a
		// publisher does not serve is asked for once a pass.
		missed := 0
		for _, path := range p.asked {
			if path == "/2026/EL-105.json.sha256" || path == "/2026/EL-106.json.sha256" {
				missed++
			}
		}
		if missed != 1 {
			t.Errorf("a SHA-256 file nobody serves was asked for %d times", missed)
		}
	})
}

func TestAPublisherServingNoDigestIsReadUnchecked(t *testing.T) {
	// The format asks for a digest file of its trusted providers only.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-107.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0107", "libnl-3-200", "3.7.1", "CVE-2026-1107"))
		// One publisher answers a missing file 403 rather than 404.
		p.failing["/2026/EL-107.json.sha512"] = http.StatusForbidden

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 || took.Recorded != 1 || took.Checked != 0 {
			t.Errorf("a document with no digest beside it was taken as %+v", took)
		}
	})
}

func TestADigestThatCannotBeReachedHoldsTheMark(t *testing.T) {
	// A publisher having a bad day has not shown whether the document is what
	// they published.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-108.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0108", "libnl-3-200", "3.7.1", "CVE-2026-1108"))
		p.failing["/2026/EL-108.json.sha256"] = http.StatusBadGateway

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err == nil {
			t.Fatal("a digest file answering 502 was read as no digest")
		}
		if took.Recorded != 0 || took.Mark != "" {
			t.Errorf("the pass moved on past a document it could not check: %+v", took)
		}
	})
}
