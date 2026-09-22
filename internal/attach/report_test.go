package attach_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAFileArrivesWithAClaimNobodyHasJudged(t *testing.T) {
	// A claim that has not been judged has no issue to hang a screenshot on,
	// and the screenshot is often the whole of what was sent. Without this
	// the evidence is lost or the claim has to be turned into a flaw nobody
	// believes in order to keep it.
	each(t, func(t *testing.T, f *fixture) {
		who := f.who(t, access.PrivateTriage)
		report := f.aReport(t, who, nil)

		stored, err := f.store.Upload(t.Context(), who,
			attach.Against{ProductID: f.product, FlawReportID: report},
			"screenshot.png", strings.NewReader("not really a png"), 16,
			roomy, plenty, plenty, true)
		if err != nil {
			t.Fatal(err)
		}
		if stored.VulnerabilityID != nil {
			t.Errorf("a file on a claim points at issue %d", *stored.VulnerabilityID)
		}
		if stored.FlawReportID == nil || *stored.FlawReportID != report {
			t.Errorf("a file on a claim points at report %v", stored.FlawReportID)
		}

		rows, err := f.store.ForReport(t.Context(), who, f.product, report)
		if err != nil || len(rows) != 1 {
			t.Fatalf("what arrived with the claim: %d rows, %v", len(rows), err)
		}
		back, err := f.store.Find(t.Context(), who, stored.Token)
		if err != nil || back.Token != stored.Token {
			t.Errorf("fetching it by token answered %v", err)
		}
	})
}

func TestAFileOnAnUnjudgedClaimIsReachedOnlyByWhoeverTriagesUnannouncedWork(t *testing.T) {
	// There is no issue to be public about, and nobody has decided the claim
	// is safe to repeat. So the file takes the same answer the report does,
	// and a reader who may see this product's announced work sees none of it.
	each(t, func(t *testing.T, f *fixture) {
		owner := f.who(t, access.PrivateTriage)
		report := f.aReport(t, owner, nil)
		stored, err := f.store.Upload(t.Context(), owner,
			attach.Against{ProductID: f.product, FlawReportID: report},
			"evidence.log", strings.NewReader("what they sent"), 14,
			roomy, plenty, plenty, true)
		if err != nil {
			t.Fatal(err)
		}

		for _, held := range []access.Role{access.PublicRead, access.PublicTriage} {
			stranger := f.who(t, held)
			if _, err := f.store.Find(t.Context(), stranger, stored.Token); err == nil {
				t.Errorf("%s fetched a file on a claim nobody has judged", held)
			}
			if _, err := f.store.ForReport(t.Context(), stranger, f.product,
				report); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s listed what arrived with it: %v", held, err)
			}
			// Writing is the same right as reading here, because reaching a
			// report already asks for a role that triages.
			if _, err := f.store.Upload(t.Context(), stranger,
				attach.Against{ProductID: f.product, FlawReportID: report},
				"theirs.log", strings.NewReader("x"), 1,
				roomy, plenty, plenty, true); !errors.Is(err, access.ErrDenied) {
				t.Errorf("%s attached a file to it: %v", held, err)
			}
		}
	})
}

func TestAFileOnAJudgedClaimIsAsReadableAsTheIssue(t *testing.T) {
	// Asked at the moment of the request rather than copied onto the file, so
	// a claim becoming a disclosed issue carries its evidence with it — the
	// same rule that makes an embargo ending carry the file with the words.
	each(t, func(t *testing.T, f *fixture) {
		owner := f.who(t, access.PrivateTriage)
		undisclosed := f.anIssue(t, "CVE-2026-7000", access.Private)
		report := f.aReport(t, owner, &undisclosed)
		stored, err := f.store.Upload(t.Context(), owner,
			attach.Against{ProductID: f.product, FlawReportID: report},
			"proof.log", strings.NewReader("what they sent"), 14,
			roomy, plenty, plenty, true)
		if err != nil {
			t.Fatal(err)
		}
		reader := f.who(t, access.PublicRead)
		if _, err := f.store.Find(t.Context(), reader, stored.Token); err == nil {
			t.Error("a reader of announced work fetched a file on an undisclosed issue")
		}

		// The same file, on a claim that turned out to be announced work.
		announced := f.aReport(t, owner, &f.issue)
		open, err := f.store.Upload(t.Context(), owner,
			attach.Against{ProductID: f.product, FlawReportID: announced},
			"open.log", strings.NewReader("what they sent"), 14,
			roomy, plenty, plenty, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Find(t.Context(), reader, open.Token); err != nil {
			t.Errorf("a reader could not fetch a file on a disclosed issue: %v", err)
		}
	})
}

func TestAFileHangsOffOneThingOrTheOther(t *testing.T) {
	// A row naming both, or neither, is one nothing can answer "who may read
	// this" about.
	each(t, func(t *testing.T, f *fixture) {
		who := f.who(t, access.PrivateTriage)
		report := f.aReport(t, who, nil)
		for what, at := range map[string]attach.Against{
			"both":    {ProductID: f.product, VulnerabilityID: f.issue, FlawReportID: report},
			"neither": {ProductID: f.product},
		} {
			if _, err := f.store.Upload(t.Context(), who, at, "x.log",
				strings.NewReader("x"), 1, roomy, plenty, plenty, true); err == nil {
				t.Errorf("a file hanging off %s was accepted", what)
			}
		}
	})
}

// aReport records a claim against the fixture's product, pointed at an issue
// where one is given.
func (f *fixture) aReport(t *testing.T, who access.Subject, issue *int64) int64 {
	t.Helper()
	row := &finding.FlawReport{
		Reference: "SONIC-R-2026-" + time.Now().Format("150405.000000000"),
		ProductID: f.product, VulnerabilityID: issue,
		Summary:    "They say the management socket lets anybody in.",
		Contact:    "them@example.org",
		RecordedBy: who.ID, RecordedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatalf("record a claim: %v", err)
	}
	return row.ID
}
