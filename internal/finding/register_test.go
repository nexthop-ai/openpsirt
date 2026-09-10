package finding_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The page and the count are two questions, and the export asks only one.
//
// Counting a register is a scan of every finding in the build — a quarter of a
// million rows on a real image — and a file is written by asking for a page a
// thousand times, so the export was answering "how many are there altogether"
// a thousand times to fill in a number the file has no column for. The two
// readers are separate now, and this is what keeps them saying the same thing:
// a page read without the count has to be the page read with it.
func TestTheRegistersPageIsTheSameWithoutItsCount(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
			found("CVE-2026-3", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		withCount, total, err := f.store.Register(t.Context(), who, f.target, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		without, err := f.store.RegisterPage(t.Context(), who, f.target, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total == 0 || len(withCount) == 0 {
			t.Fatal("the register is empty for a build holding three findings")
		}
		if len(without) != len(withCount) {
			t.Fatalf("the page is %d rows without the count and %d with it",
				len(without), len(withCount))
		}
		for i := range withCount {
			if asText(without[i]) != asText(withCount[i]) {
				t.Errorf("row %d differs:\n without %s\n with    %s",
					i, asText(without[i]), asText(withCount[i]))
			}
		}
		// And the same refusal. A reader who may see nothing here has to be
		// refused by both, or the export is the way around the check.
		nobody := f.holdingIn(t, nil, access.PublicRead)
		if _, err := f.store.RegisterPage(t.Context(), nobody, f.target, 50, 0); err == nil {
			t.Error("a page read without the count answered somebody holding nothing")
		}
		if err := f.store.RegisterEach(t.Context(), nobody, f.target,
			func(finding.Disposed) error { return nil }); err == nil {
			t.Error("the walk answered somebody holding nothing")
		}
	})
}

// The walk and the page are the same register.
//
// The export streams and the screen pages, which is two readers over one
// statement — so this is what stops them drifting into two registers. It is
// the same shape as the count check above and exists for the same reason: an
// auditor's file and the screen it is checked against have to be the same
// rows in the same order.
func TestTheRegisterWalkedIsTheRegisterPaged(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
			found("CVE-2026-3", teamd), found("CVE-2026-4", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		paged, err := f.store.RegisterPage(t.Context(), who, f.target, 500, 0)
		if err != nil {
			t.Fatal(err)
		}
		var walked []finding.Disposed
		if err := f.store.RegisterEach(t.Context(), who, f.target,
			func(row finding.Disposed) error {
				walked = append(walked, row)
				return nil
			}); err != nil {
			t.Fatal(err)
		}
		if len(paged) == 0 {
			t.Fatal("the register is empty for a build holding four findings")
		}
		if len(walked) != len(paged) {
			t.Fatalf("the walk gave %d rows and the page gave %d", len(walked), len(paged))
		}
		for i := range paged {
			if asText(walked[i]) != asText(paged[i]) {
				t.Errorf("row %d differs:\n walked %s\n paged  %s",
					i, asText(walked[i]), asText(paged[i]))
			}
		}

		// A walk that gives up partway gives up: the caller's refusal is the
		// export saying it could not finish, and swallowing it is how a file
		// ends early and reads as complete.
		stop := fmt.Errorf("enough")
		seen := 0
		err = f.store.RegisterEach(t.Context(), who, f.target, func(finding.Disposed) error {
			seen++
			return stop
		})
		if !errors.Is(err, stop) {
			t.Errorf("a walk told to stop answered %v", err)
		}
		if seen != 1 {
			t.Errorf("it kept walking after being told to stop, %d rows in", seen)
		}
	})
}

// asText is one register row as a value rather than as a struct holding
// pointers. Two reads of the same row allocate different pointers, so
// comparing the structs compares where the times live rather than when they
// are — which is a test that fails on every row and says nothing.
func asText(row finding.Disposed) string {
	at := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	met := "-"
	if row.Met != nil {
		met = fmt.Sprint(*row.Met)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		row.Vulnerability, row.Severity, row.Component, row.Version, row.Place,
		row.State, row.Outcome, row.Justification, row.ProposedBy, at(row.ProposedAt),
		row.ApprovedBy, at(row.ApprovedAt), at(&row.OpenedAt), at(row.ClosedAt), met)
}
