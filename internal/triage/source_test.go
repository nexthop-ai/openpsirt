// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// perfPaths is what Debian builds linux-perf from.
var perfPaths = []string{"tools/perf/", "tools/lib", "./tools/include"}

// kernelIssue interns a kernel issue whose record lists the files given, or
// none.
func (f *fixture) kernelIssue(t *testing.T, identifier string, files ...string) int64 {
	t.Helper()
	interned, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(), []finding.Named{
		{Identifier: identifier, Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := interned[identifier]
	if len(files) > 0 {
		if _, err := f.db.DB.NewUpdate().Table("vulnerability").
			Set(`"program_files" = ?`, finding.JoinFiles(files)).
			Where(`"id" = ?`, id).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// throughSource opens an issue against a component in a build, matched
// through the source given, or on the package itself where none is.
func (f *fixture) throughSource(t *testing.T, in build, issue, componentID int64, occurrence, source string,
	visibility access.Visibility) int64 {
	t.Helper()
	row := &finding.Finding{
		BuildID: in.build, Kind: finding.Vulnerable, VulnerabilityID: issue,
		Visibility: visibility, ComponentID: componentID, OccurrenceIdentity: occurrence,
		MatchedThrough: source,
		OpenedAt:       time.Now().Truncate(time.Microsecond), OpenedRunID: &in.run,
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The run that opened it is the last the build applied, as applying a
	// scan records it.
	if _, err := f.db.DB.NewUpdate().Table("build").Set(`"last_run_id" = ?`, in.run).
		Where(`"id" = ?`, in.build).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row.ID
}

// perfCorrection is a correction that linux-perf is not the kernel.
func (f *fixture) perfCorrection() triage.SourceProposal {
	return triage.SourceProposal{
		ProductID: f.product, Package: "Linux-Perf", Source: "linux", Paths: perfPaths,
		Justification: triage.CodeNotPresent,
		Reasoning:     "linux-perf is built from tools/perf, tools/lib and tools/include; the kernel is not in it.",
		By:            f.proposer,
	}
}

// answeredIssues is the issues a decision has a live row for, and the rows.
func (f *fixture) answeredIssues(t *testing.T, decisionID int64) (map[int64]triage.DecisionOccurrence, []int64) {
	t.Helper()
	var rows []triage.DecisionOccurrence
	if err := f.db.DB.NewSelect().Model(&rows).
		Where(`"de"."decision_id" = ?`, decisionID).
		Where(`"de"."live_key" IS NOT NULL`).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	out := map[int64]triage.DecisionOccurrence{}
	var ids []int64
	for _, row := range rows {
		out[row.VulnerabilityID] = row
		ids = append(ids, row.ID)
	}
	return out, ids
}

// perfWorld is a build shipping linux-perf with one finding per case a
// correction by source paths has to tell apart, by issue.
type perfWorld struct {
	in                   build
	perf                 int64
	outside, alsoOutside int64
	inPerf, mixed        int64
	noFiles              int64
	ownName, private     int64
	otherPackage         int64
}

func (f *fixture) perfWorld(t *testing.T) perfWorld {
	t.Helper()
	w := perfWorld{in: f.build(t, f.product, "2026.11")}
	w.perf = f.component(t, "linux-perf", "6.12.117-1")
	kbuild := f.component(t, "linux-kbuild-6.12", "6.12.117-1")

	w.outside = f.kernelIssue(t, "CVE-2024-26600", "drivers/phy/ti/phy-omap-usb2.c")
	w.alsoOutside = f.kernelIssue(t, "CVE-2023-52603", "fs/jfs/jfs_dtree.c")
	w.inPerf = f.kernelIssue(t, "CVE-2026-90001", "tools/perf/util/annotate.c")
	w.mixed = f.kernelIssue(t, "CVE-2026-90002", "drivers/net/x.c", "tools/lib/bpf/libbpf.c")
	w.noFiles = f.kernelIssue(t, "CVE-2026-90003")
	w.ownName = f.kernelIssue(t, "CVE-2026-90004", "drivers/gpu/y.c")
	w.private = f.kernelIssue(t, "CVE-2026-90005", "drivers/gpu/z.c")
	w.otherPackage = f.kernelIssue(t, "CVE-2026-90006", "drivers/gpu/w.c")

	for _, issue := range []int64{w.outside, w.alsoOutside, w.inPerf, w.mixed, w.noFiles} {
		f.throughSource(t, w.in, issue, w.perf, "place-of-linux-perf", "linux", access.Public)
	}
	// Matched on the binary's own name or a CPE: the scanner names no source.
	f.throughSource(t, w.in, w.ownName, w.perf, "place-of-linux-perf", "", access.Public)
	f.throughSource(t, w.in, w.private, w.perf, "place-of-linux-perf", "linux", access.Private)
	f.throughSource(t, w.in, w.otherPackage, kbuild, "place-of-linux-kbuild", "linux", access.Public)
	return w
}

func TestACorrectionBySourcePathsAnswersOnlyIssuesWhoseFilesLieOutside(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		answered, ids := f.answeredIssues(t, proposed.DecisionID)
		if proposed.Answered != 2 || len(answered) != 2 {
			t.Errorf("answered %d occurrences, %d issues, want the two whose files lie outside", proposed.Answered, len(answered))
		}
		for issue, why := range map[int64]string{
			w.inPerf:       "an issue in a file under the paths",
			w.mixed:        "an issue with one file under the paths",
			w.noFiles:      "an issue whose record lists no files",
			w.ownName:      "a match on the package's own name",
			w.private:      "an undisclosed finding",
			w.otherPackage: "another package of the same source",
		} {
			if _, ok := answered[issue]; ok {
				t.Errorf("%s was answered", why)
			}
		}
		for _, issue := range []int64{w.outside, w.alsoOutside} {
			row, ok := answered[issue]
			if !ok {
				t.Errorf("issue %d, every file outside the paths, was not answered", issue)
				continue
			}
			if row.ComponentUpstreamVersion != nil && row.Decision != nil && row.Decision.Outcome != triage.Mismatched {
				t.Errorf("issue %d was answered as %q", issue, row.Decision.Outcome)
			}
		}

		// Each answer records the files that justified it.
		files, err := f.store.SourceAnswers(t.Context(), ids)
		if err != nil {
			t.Fatal(err)
		}
		if got := files[answered[w.outside].ID].AnsweredOn; !slices.Equal(got, []string{"drivers/phy/ti/phy-omap-usb2.c"}) {
			t.Errorf("the answer to CVE-2024-26600 records %v", got)
		}

		// And the correction says what it names.
		rule, err := f.store.SourceOf(t.Context(), proposed.DecisionID)
		if err != nil {
			t.Fatal(err)
		}
		if rule == nil || rule.Package != "linux-perf" || rule.Source != "linux" ||
			!slices.Equal(rule.PathList(), []string{"tools/include", "tools/lib", "tools/perf"}) {
			t.Errorf("the correction names %+v", rule)
		}
	})
}

func TestACorrectionBySourcePathsWaitsForASecondPerson(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		at := triage.Occurrence{ProductID: f.product, VulnerabilityID: w.outside,
			OccurrenceIdentity: "place-of-linux-perf", Visibility: access.Public, ComponentUpstream: "6.12.117-1"}
		standing, err := f.store.Applying(t.Context(), at)
		if err != nil {
			t.Fatal(err)
		}
		if standing != nil {
			t.Fatalf("a correction nobody has agreed to already answers, as %q", standing.State)
		}
		if err := agreeTo(t.Context(), f.store, f.triager, proposed.DecisionID, ""); !errors.Is(err, triage.ErrSamePerson) {
			t.Errorf("the proposer agreeing to their own correction gave %v, want refused", err)
		}
		if err := agreeTo(t.Context(), f.store, f.reviewer, proposed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		if standing, err = f.store.Applying(t.Context(), at); err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.DecisionID != proposed.DecisionID {
			t.Errorf("an agreed correction does not answer the finding: %+v", standing)
		}
	})
}

func TestAnIssuePublishedLaterIsAnsweredByTheAgreedCorrection(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(t.Context(), f.store, f.reviewer, proposed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}

		// A later scan of a later build reports two kernel issues published
		// since: one in a driver, one in perf.
		later := f.build(t, f.product, "2026.12")
		driver := f.kernelIssue(t, "CVE-2026-90100", "drivers/usb/core/hub.c")
		perf := f.kernelIssue(t, "CVE-2026-90101", "tools/perf/builtin-top.c")
		f.throughSource(t, later, driver, w.perf, "place-of-linux-perf", "linux", access.Public)
		f.throughSource(t, later, perf, w.perf, "place-of-linux-perf", "linux", access.Public)
		// The earlier issue sits in this build too, already answered.
		f.throughSource(t, later, w.outside, w.perf, "place-of-linux-perf", "linux", access.Public)

		pass, err := f.store.AnswerBySource(t.Context(), later.build)
		if err != nil {
			t.Fatal(err)
		}
		if n := pass.Answered; n != 1 {
			t.Errorf("the scan answered %d occurrences, want the one new driver issue", n)
		}
		answered, _ := f.answeredIssues(t, proposed.DecisionID)
		if row, ok := answered[driver]; !ok || row.State != triage.Approved {
			t.Errorf("the later driver issue is answered as %+v, want approved under the agreed correction", row)
		}
		if _, ok := answered[perf]; ok {
			t.Error("a later issue in perf's own files was answered")
		}

		// Answering again finds nothing new.
		if again, err := f.store.AnswerBySource(t.Context(), later.build); err != nil || again.Answered != 0 {
			t.Errorf("a second pass answered %d (%v), want none", again.Answered, err)
		}
	})
}

func TestARevisedCorrectionAnswersLaterIssuesOnlyOnceAgreedAgain(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(t.Context(), f.store, f.reviewer, proposed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(t.Context(), f.triager, proposed.DecisionID,
			"linux-perf is userspace; it is built from tools/ alone."); err != nil {
			t.Fatal(err)
		}
		later := f.kernelIssue(t, "CVE-2026-90200", "net/core/dev.c")
		f.throughSource(t, w.in, later, w.perf, "place-of-linux-perf", "linux", access.Public)
		if _, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil {
			t.Fatal(err)
		}
		answered, _ := f.answeredIssues(t, proposed.DecisionID)
		if row, ok := answered[later]; !ok || row.State != triage.Proposed {
			t.Errorf("an issue answered after the reasoning changed is %+v, want waiting", row)
		}
	})
}

func TestAWithdrawnCorrectionAnswersNothingMore(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Withdraw(t.Context(), f.triager, proposed.DecisionID); err != nil {
			t.Fatal(err)
		}
		later := f.kernelIssue(t, "CVE-2026-90300", "sound/core/pcm.c")
		f.throughSource(t, w.in, later, w.perf, "place-of-linux-perf", "linux", access.Public)
		pass, err := f.store.AnswerBySource(t.Context(), w.in.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Answered != 0 {
			t.Errorf("a withdrawn correction answered %d occurrences", pass.Answered)
		}
	})
}

// setFiles puts what an issue's record now lists, or none.
func (f *fixture) setFiles(t *testing.T, issue int64, files ...string) {
	t.Helper()
	var value any
	if len(files) > 0 {
		value = finding.JoinFiles(files)
	}
	if _, err := f.db.DB.NewUpdate().Table("vulnerability").
		Set(`"program_files" = ?`, value).
		Where(`"id" = ?`, issue).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// An answer a later record no longer bears out is withdrawn on the next
// scan: the row lapses, the proposer is told, and the answer keeps the files
// it was answered on beside the files the record lists now. An answer whose
// record still puts every file outside stands, whatever else moved.
func TestAnAnswerALaterRecordContradictsIsWithdrawn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		third := f.kernelIssue(t, "CVE-2026-90400", "net/ipv4/tcp.c")
		f.throughSource(t, w.in, third, w.perf, "place-of-linux-perf", "linux", access.Public)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(t.Context(), f.store, f.reviewer, proposed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		before, _ := f.answeredIssues(t, proposed.DecisionID)
		if len(before) != 3 {
			t.Fatalf("the correction answers %d issues, want three", len(before))
		}

		// The records move: one now names a file in perf, one names no
		// files, one names another file outside the paths.
		f.setFiles(t, w.outside, "drivers/phy/ti/phy-omap-usb2.c", "tools/perf/util/evsel.c")
		f.setFiles(t, w.alsoOutside)
		f.setFiles(t, third, "net/ipv4/tcp_input.c")

		pass, err := f.store.AnswerBySource(t.Context(), w.in.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Withdrawn.Rows != 2 {
			t.Errorf("the scan withdrew %d answers, want the two the records no longer bear out", pass.Withdrawn.Rows)
		}
		if len(pass.Withdrawn.Told) != 1 || pass.Withdrawn.Told[0].PersonID != f.triager.ID ||
			pass.Withdrawn.Told[0].SourceWithdrawn != triage.WithdrawnByRecord {
			t.Errorf("who is told reads %+v, want the proposer, for the record", pass.Withdrawn.Told)
		}
		after, _ := f.answeredIssues(t, proposed.DecisionID)
		for issue, why := range map[int64]string{
			w.outside:     "an answer whose record now names a file under the paths",
			w.alsoOutside: "an answer whose record now names no files",
		} {
			if _, ok := after[issue]; ok {
				t.Errorf("%s still stands", why)
			}
			row := before[issue]
			var state triage.State
			if err := f.db.DB.NewSelect().Model((*triage.DecisionOccurrence)(nil)).Column("state").
				Where(`"de"."id" = ?`, row.ID).Scan(t.Context(), &state); err != nil {
				t.Fatal(err)
			}
			if state != triage.LapsedState {
				t.Errorf("%s is %q, want lapsed so the finding is open for a person", why, state)
			}
		}
		if _, ok := after[third]; !ok {
			t.Error("an answer whose record still names only files outside was withdrawn")
		}

		answers, err := f.store.SourceAnswers(t.Context(),
			[]int64{before[w.outside].ID, before[w.alsoOutside].ID, before[third].ID})
		if err != nil {
			t.Fatal(err)
		}
		if got := answers[before[w.outside].ID]; !got.Withdrawn ||
			!slices.Equal(got.AnsweredOn, []string{"drivers/phy/ti/phy-omap-usb2.c"}) ||
			!slices.Equal(got.WithdrawnOn, []string{"drivers/phy/ti/phy-omap-usb2.c", "tools/perf/util/evsel.c"}) {
			t.Errorf("the answer the perf file withdrew reads %+v", got)
		}
		if got := answers[before[w.alsoOutside].ID]; !got.Withdrawn || len(got.WithdrawnOn) != 0 ||
			!slices.Equal(got.AnsweredOn, []string{"fs/jfs/jfs_dtree.c"}) {
			t.Errorf("the answer an empty record withdrew reads %+v", got)
		}
		if got := answers[before[third].ID]; got.Withdrawn {
			t.Errorf("the answer still borne out reads %+v", got)
		}

		// A second pass withdraws nothing more and answers nothing back.
		again, err := f.store.AnswerBySource(t.Context(), w.in.build)
		if err != nil {
			t.Fatal(err)
		}
		if again.Withdrawn.Rows != 0 || again.Answered != 0 {
			t.Errorf("a second pass withdrew %d and answered %d, want neither", again.Withdrawn.Rows, again.Answered)
		}
	})
}

// A correction every answer of which a later record withdrew still stands, and
// answers an issue published after; withdrawing it ends it.
func TestACorrectionWhoseAnswersWereAllWithdrawnStillAnswers(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		f.setFiles(t, w.outside)
		f.setFiles(t, w.alsoOutside)
		if pass, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil || pass.Withdrawn.Rows != 2 {
			t.Fatalf("the scan withdrew %d (%v), want both answers", pass.Withdrawn.Rows, err)
		}

		later := f.kernelIssue(t, "CVE-2026-90500", "mm/slub.c")
		f.throughSource(t, w.in, later, w.perf, "place-of-linux-perf", "linux", access.Public)
		pass, err := f.store.AnswerBySource(t.Context(), w.in.build)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Answered != 1 {
			t.Errorf("a correction whose answers were all withdrawn answered %d later issues, want one", pass.Answered)
		}

		if _, err := f.store.Withdraw(t.Context(), f.triager, proposed.DecisionID); err != nil {
			t.Fatal(err)
		}
		f.setFiles(t, w.outside, "drivers/phy/ti/phy-omap-usb2.c")
		if pass, err := f.store.AnswerBySource(t.Context(), w.in.build); err != nil || pass.Answered != 0 {
			t.Errorf("a withdrawn correction answered %d (%v)", pass.Answered, err)
		}
	})
}

func TestAnAttackedIssueIsNotAnsweredBySourcePaths(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		w := f.perfWorld(t)
		if _, _, err := f.store.RecordIncident(t.Context(), f.triager, f.product, w.outside, knownAt,
			"Exploited through the USB PHY on a customer's board."); err != nil {
			t.Fatal(err)
		}
		proposed, err := f.store.ProposeBySource(t.Context(), f.triager, f.perfCorrection())
		if err != nil {
			t.Fatal(err)
		}
		answered, _ := f.answeredIssues(t, proposed.DecisionID)
		if _, ok := answered[w.outside]; ok {
			t.Error("an issue this product was attacked through was answered")
		}
		if _, ok := answered[w.alsoOutside]; !ok {
			t.Error("the issue beside it was not answered")
		}
	})
}

func TestACorrectionBySourcePathsIsRefusedWhatItCannotSay(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.perfWorld(t)
		for name, change := range map[string]func(*triage.SourceProposal){
			"a reason about reachability": func(p *triage.SourceProposal) { p.Justification = triage.CodeNotInExecutePath },
			"no reasoning":                func(p *triage.SourceProposal) { p.Reasoning = " " },
			"the package as its source":   func(p *triage.SourceProposal) { p.Source = "LINUX-PERF" },
			"no package":                  func(p *triage.SourceProposal) { p.Package = "" },
			"no source":                   func(p *triage.SourceProposal) { p.Source = "" },
			"no paths":                    func(p *triage.SourceProposal) { p.Paths = []string{" "} },
			"the root":                    func(p *triage.SourceProposal) { p.Paths = []string{"/"} },
			"a path leaving the tree":     func(p *triage.SourceProposal) { p.Paths = []string{"../drivers"} },
			"somebody else's name":        func(p *triage.SourceProposal) { p.By = f.approver },
		} {
			p := f.perfCorrection()
			change(&p)
			// Refused for what it says, before anything is matched: a refusal
			// for answering nothing would also turn these away.
			if _, err := f.store.ProposeBySource(t.Context(), f.triager, p); err == nil ||
				errors.Is(err, triage.ErrNothingMatchedThrough) {
				t.Errorf("%s gave %v, want refused for what it says", name, err)
			}
		}
		// A line break would split one stated path into two once the paths are
		// joined a line each, past every check made of the one.
		broken := f.perfCorrection()
		broken.Paths = []string{"tools/perf\n.."}
		if _, err := f.store.ProposeBySource(t.Context(), f.triager, broken); err == nil ||
			!strings.Contains(err.Error(), "control character") {
			t.Errorf("a path holding a line break gave %v, want refused for it", err)
		}
		if _, err := f.store.ProposeBySource(t.Context(), f.onlooker, func() triage.SourceProposal {
			p := f.perfCorrection()
			p.By = f.onlooker.ID
			return p
		}()); err == nil {
			t.Error("somebody who may not triage here recorded a correction")
		}
		// Everything under the paths: nothing to answer, so nothing recorded.
		p := f.perfCorrection()
		p.Paths = []string{"drivers", "fs", "tools"}
		if _, err := f.store.ProposeBySource(t.Context(), f.triager, p); !errors.Is(err, triage.ErrNothingMatchedThrough) {
			t.Errorf("a correction answering nothing gave %v", err)
		}
		var kept []int64
		if err := f.db.DB.NewSelect().Table("source_correction").Column("id").Scan(t.Context(), &kept); err != nil {
			t.Fatal(err)
		}
		sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })
		if len(kept) != 0 {
			t.Errorf("refused proposals left %d corrections", len(kept))
		}
	})
}
