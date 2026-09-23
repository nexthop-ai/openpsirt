package supplier_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
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
		if took.Mismatched != 1 || took.Refused != 0 || took.Documents != 0 || took.Recorded != 0 {
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
		p.linked["/2026/EL-104.json"] = []string{"/sums/EL-104.json.sha512"}
		p.documents["/sums/EL-104.json.sha512"] = sha512Of(body + "x")

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Mismatched != 1 || took.Recorded != 0 {
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

func TestADigestTheClientRefusesToFetchIsReadAsNoDigest(t *testing.T) {
	// A redirect and a host nobody configured are turned away by the client
	// itself. Read as a publisher that cannot be reached, the pass would stop
	// at that document on every wake.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		body := advisory("EL-2026-0109", "libnl-3-200", "3.7.1", "CVE-2026-1109")
		p.publishes("/2026/EL-109.json", "2026-09-20T00:00:00Z", body)
		p.linked["/2026/EL-109.json"] = []string{"https://elsewhere.example/EL-109.json.sha256"}
		p.moved["/2026/EL-109.json.sha256"] = "https://elsewhere.example/missing"
		p.moved["/2026/EL-109.json.sha512"] = "https://elsewhere.example/missing"

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatalf("a digest the client refused held the pass: %v", err)
		}
		if took.Recorded != 1 || took.Checked != 0 || took.Mark == "" {
			t.Errorf("a document whose digests were refused was taken as %+v", took)
		}
	})
}

func TestAPublisherServingNoDigestIsAskedTwiceAPass(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		for i := range 4 {
			p.publishes(fmt.Sprintf("/2026/EL-12%d.json", i),
				fmt.Sprintf("2026-09-2%dT00:00:00Z", i),
				advisory(fmt.Sprintf("EL-2026-012%d", i), "libnl-3-200", "3.7.1",
					fmt.Sprintf("CVE-2026-112%d", i)))
		}

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 4 {
			t.Fatalf("%d documents were read", took.Documents)
		}
		asked := 0
		for _, path := range p.asked {
			if strings.HasSuffix(path, ".sha256") || strings.HasSuffix(path, ".sha512") {
				asked++
			}
		}
		if asked != 4 {
			t.Errorf("digest files were asked for %d times, want two documents' worth", asked)
		}
	})
}

func TestAFeedEntryNamingManyDigestsIsAskedOnePerAlgorithm(t *testing.T) {
	// Nothing in the format bounds the links an entry carries, and each
	// asked is a request with a pause before it.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-130.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0130", "libnl-3-200", "3.7.1", "CVE-2026-1130"))
		for i := range 50 {
			p.linked["/2026/EL-130.json"] = append(p.linked["/2026/EL-130.json"],
				fmt.Sprintf("/sums/%d.json.sha256", i), fmt.Sprintf("/sums/%d.json.sha512", i))
		}

		if _, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p)); err != nil {
			t.Fatal(err)
		}
		named := 0
		for _, path := range p.asked {
			if strings.HasPrefix(path, "/sums/") {
				named++
			}
		}
		if named != 2 {
			t.Errorf("%d of the digests the entry named were asked for, want one per algorithm",
				named)
		}
	})
}

func TestAStatementSetIsSetAsideBeforeItsDigestIsAskedFor(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-VEX.json", "2026-09-20T00:00:00Z", vexDocument)
		p.documents["/2026/EL-VEX.json.sha256"] = sha256Of(vexDocument, "EL-VEX.json")

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Skipped != 1 {
			t.Errorf("the statement set was taken as %+v", took)
		}
		for _, path := range p.asked {
			if strings.HasPrefix(path, "/2026/EL-VEX.json.") {
				t.Errorf("a digest was asked for a document set aside anyway: %s", path)
			}
		}
	})
}

func TestAPassThatLosesTheLeaseStopsAndLeavesTheSupplierDue(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-140.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0140", "libnl-3-200", "3.7.1", "CVE-2026-1140"))

		fetch := fetching(t, f, p)
		fetch.Keep = func(context.Context) (bool, error) { return false, nil }
		took, err := fetch.From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 0 || !took.Filled {
			t.Errorf("a pass that lost the lease read as %+v", took)
		}
		for _, path := range p.asked {
			if path == "/2026/EL-140.json" {
				t.Error("a document was fetched after the lease was lost")
			}
		}
	})
}
