// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
)

// A fork trusting an upstream that publishes this deployment's own documents
// takes a statement holding for anybody shipping the component, at that
// component and version and no other, and closes nothing by a statement that
// depends on the upstream's own build: that one is offered for review.
func TestAForkTakesWhatItsUpstreamSaysForAnybody(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		if got := w.state(w.forkBuild, portable, openssl); !got.open {
			t.Fatalf("the fork's finding is closed before it trusts anybody: %+v", got)
		}
		w.trust()
		took := w.read()
		if took.Documents < 2 || took.Refused != 0 || !took.Moved {
			t.Fatalf("the first read took %+v, want both documents", took)
		}
		w.rescan()

		said := w.statement(portable, finding.PlacedAnybody)
		if said == nil {
			t.Fatal("the statement holding for anybody was not recorded as one")
		}
		got := w.state(w.forkBuild, portable, openssl)
		if got.open || got.because != string(finding.Disclaimed) || got.statedBy == nil || *got.statedBy != said.ID {
			t.Errorf("the fork's openssl at the upstream's version stands %+v, want closed by statement %d",
				got, said.ID)
		}
		if !strings.Contains(said.Document, w.server.base) {
			t.Errorf("the statement names the document %q, not where the upstream serves it", said.Document)
		}
		if got := w.state(w.forkLater, portable, opensslNext); !got.open {
			t.Errorf("openssl at a version the upstream did not speak about stands %+v, want open", got)
		}
		if got := w.state(w.forkBuild, ownBuild, libnl); !got.open {
			t.Errorf("a statement about the upstream's own build closed the fork's finding: %+v", got)
		}
		if w.statement(ownBuild, "") == nil {
			t.Error("the statement about the upstream's own build was not recorded for review")
		}

		offers, err := w.findings.Offers(t.Context(), w.proposer, w.fork.ID)
		if err != nil {
			t.Fatal(err)
		}
		var offered []string
		for _, one := range offers {
			offered = append(offered, one.Issue+" at "+one.Component+" "+one.Version)
			if one.Issue == portable {
				t.Errorf("a statement applied by itself is offered for review: %+v", one)
			}
		}
		if len(offers) != 2 || offers[0].Issue != ownBuild {
			t.Errorf("offered %v, want the upstream's own-build statement at both of the fork's builds", offered)
		}
	})
}

// A statement holding for anybody only narrows. Where somebody here decided
// about a place, whatever they decided, it closes nothing there; and nothing
// the upstream says opens a finding.
func TestALocalDecisionStandsOverAnUpstreamsWord(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		// Not applicable, for a reason of the fork's own: the upstream would
		// close the place, and the decision here is the one that stands.
		w.claim(w.forkBuild, portable, openssl.Name, triage.NotApplicable, triage.CodeNotInExecutePath)
		w.trust()
		w.read()
		w.rescan()
		if got := w.state(w.forkBuild, portable, openssl); !got.open {
			t.Errorf("the upstream closed a place somebody here said is affected: %+v", got)
		}
	})
}

// Each way a statement stops holding opens what it closed at the next run:
// somebody here declining it, the upstream withdrawing it, and the fork
// stopping trusting the upstream. Taking a decline back closes it again.
func TestWhatAnUpstreamClosedOpensWhenItsWordStopsHolding(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		w.rescan()
		said := w.statement(portable, finding.PlacedAnybody)
		if said == nil || w.state(w.forkBuild, portable, openssl).open {
			t.Fatal("the upstream's statement did not close the fork's finding to begin with")
		}

		if _, err := w.findings.Decline(t.Context(), w.proposer, said.ID); err != nil {
			t.Fatal(err)
		}
		w.rescan()
		if got := w.state(w.forkBuild, portable, openssl); !got.open {
			t.Errorf("a declined statement still closes the finding: %+v", got)
		}
		if _, err := w.findings.Restore(t.Context(), w.proposer, said.ID); err != nil {
			t.Fatal(err)
		}
		w.rescan()
		if got := w.state(w.forkBuild, portable, openssl); got.open {
			t.Errorf("a statement whose decline was taken back does not close the finding: %+v", got)
		}

		// The upstream withdraws its document about the issue, and its
		// listing stops naming it while it still lists the other.
		if _, err := w.DB.DB.NewUpdate().Model((*publish.Document)(nil)).
			Set(`"withdrawn_at" = ?`, time.Now().UTC()).
			Where(`"subject" = ?`, portable).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		took := w.read()
		if took.Withdrawn != 1 || !took.Moved {
			t.Fatalf("the read after the upstream withdrew its statement took %+v", took)
		}
		w.rescan()
		if w.statement(portable, finding.PlacedAnybody) != nil {
			t.Error("a statement the upstream withdrew still stands")
		}
		if got := w.state(w.forkBuild, portable, openssl); !got.open {
			t.Errorf("a statement the upstream withdrew still closes the finding: %+v", got)
		}
	})
}

// Stopping trusting the upstream sets aside everything it said, so the next
// run opens what it closed.
func TestStoppingTrustingAnUpstreamOpensWhatItClosed(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		w.rescan()
		if w.state(w.forkBuild, portable, openssl).open {
			t.Fatal("the upstream's statement did not close the fork's finding to begin with")
		}
		if _, err := upstream.NewStore(w.DB.DB).Withdraw(t.Context(), w.admin, w.fork.ID); err != nil {
			t.Fatal(err)
		}
		w.rescan()
		if got := w.state(w.forkBuild, portable, openssl); !got.open {
			t.Errorf("an upstream no longer trusted still closes the finding: %+v", got)
		}
		if w.statement(portable, finding.PlacedAnybody) != nil {
			t.Error("a statement of an upstream no longer trusted still stands")
		}
	})
}

// A document that does not match the digest served beside it, one served
// with no digest, and one whose signature the trusted key did not make are
// not taken, and nothing they say closes anything.
func TestADocumentThatFailsItsChecksIsNotTaken(t *testing.T) {
	for _, c := range []struct {
		what   string
		break_ func(w *world, path string)
	}{
		{"served with no digest", func(w *world, path string) {
			w.server.drop(path + publish.SHA256Suffix)
			w.server.drop(path + publish.SHA512Suffix)
		}},
		{"served with no signature", func(w *world, path string) {
			w.server.drop(path + publish.SignatureSuffix)
		}},
		{"signed by another key", func(w *world, path string) {
			other := otherSignature(w.t)
			w.server.change(path+publish.SignatureSuffix, func([]byte) []byte { return other })
		}},
	} {
		t.Run(c.what, func(t *testing.T) {
			fixture.Each(t, func(t *testing.T, f *fixture.World) {
				w := newWorld(t, f)
				c.break_(w, w.server.pathOf(t, portable))
				w.trust()
				took := w.read()
				if took.Refused != 1 {
					t.Errorf("the read refused %d documents, want the one %s", took.Refused, c.what)
				}
				w.rescan()
				if w.statement(portable, finding.PlacedAnybody) != nil {
					t.Errorf("a document %s was recorded", c.what)
				}
				if got := w.state(w.forkBuild, portable, openssl); !got.open {
					t.Errorf("a document %s closed the fork's finding: %+v", c.what, got)
				}
			})
		})
	}
}

// An upstream naming a key other than the one trusted is read no further, and
// says which key it names, until an administrator trusts it again.
func TestAnUpstreamWhoseKeyChangedIsNotRead(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.server.change(publish.MetadataPath, func(body []byte) []byte {
			return fingerprinted.ReplaceAll(body, []byte(`${1}00`))
		})
		took := w.read()
		if took.Documents != 0 {
			t.Errorf("an upstream whose key changed was read: %+v", took)
		}
		up, err := upstream.NewStore(w.DB.DB).For(t.Context(), w.admin, w.fork.ID)
		if err != nil {
			t.Fatal(err)
		}
		if up.KeyOffered == "" || !strings.HasPrefix(up.KeyOffered, "00") || up.Failed == "" {
			t.Errorf("the upstream records %q offered and %q failed, want the key it names now",
				up.KeyOffered, up.Failed)
		}
	})
}

// keysListed is where a provider description lists its keys.
var keysListed = regexp.MustCompile(`("public_openpgp_keys"\s*:\s*\[)`)

// fingerprinted is where a provider description states its key's
// fingerprint.
var fingerprinted = regexp.MustCompile(`("fingerprint"\s*:\s*")`)

// Nothing is fetched from a host other than the one the upstream is named
// by: a provider description naming its feed on another host reaches nothing.
func TestOnlyTheConfiguredHostIsReached(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.server.change(publish.MetadataPath, func(body []byte) []byte {
			return bytes.ReplaceAll(body, []byte(w.server.base), []byte("https://elsewhere.example.test"))
		})
		took := w.read()
		if took.Documents != 0 {
			t.Errorf("documents listed on another host were read: %+v", took)
		}
		up, err := upstream.NewStore(w.DB.DB).For(t.Context(), w.admin, w.fork.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(up.Failed, "only the configured host") {
			t.Errorf("the read records %q, want the other host refused", up.Failed)
		}
	})
}

// A read whose listings have not moved asks each listing whether it moved and
// fetches no document.
func TestAReadOfNothingThatMovedFetchesNoDocument(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		w.server.mu.Lock()
		w.server.asked = nil
		w.server.mu.Unlock()
		took := w.read()
		if took.Documents != 0 || took.Moved {
			t.Errorf("a read of nothing that moved took %+v", took)
		}
		w.server.mu.Lock()
		defer w.server.mu.Unlock()
		if got := w.server.answered[publish.FeedPath]; got != http.StatusNotModified {
			t.Errorf("the feed was answered %d, want that nothing moved", got)
		}
		for _, path := range w.server.asked {
			if strings.HasSuffix(path, ".json") && strings.Contains(path, "/white/20") {
				t.Errorf("a read of nothing that moved fetched %s", path)
			}
		}
	})
}

// Only somebody who may triage the fork declines one of its upstream's
// statements; to anybody else the statement does not exist.
func TestDecliningAStatementAsksForTriage(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		said := w.statement(portable, finding.PlacedAnybody)
		reader := access.NewPerson(w.proposer.ID, "reader", false,
			map[int64][]access.Role{w.fork.ID: {access.PublicRead}}, 0)
		if _, err := w.findings.Decline(t.Context(), reader, said.ID); err != finding.ErrStatementNotFound {
			t.Errorf("somebody who only reads the fork declined a statement: %v", err)
		}
	})
}

// A description that cannot be read withdraws nothing, however it failed:
// what the upstream said stands, and the failure is recorded for an
// administrator to see.
func TestAFailedDescriptionWithdrawsNothing(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		w.server.drop(publish.MetadataPath)
		took := w.read()
		if took.Withdrawn != 0 {
			t.Errorf("a description answering 404 withdrew %d documents", took.Withdrawn)
		}
		w.rescan()
		if w.statement(portable, finding.PlacedAnybody) == nil {
			t.Error("a statement stopped standing because the description could not be read")
		}
		if got := w.state(w.forkBuild, portable, openssl); got.open {
			t.Errorf("the fork's finding opened because the description could not be read: %+v", got)
		}
		up, err := upstream.NewStore(w.DB.DB).For(t.Context(), w.admin, w.fork.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(up.Failed, "404") || up.ReachedAt == nil {
			t.Errorf("the failed read records %q, last read %v", up.Failed, up.ReachedAt)
		}
	})
}

// An upstream moved to another address keeps what it said until the first
// complete read there: a statement repeated stays as it is, declined or not;
// one revised replaces it; one the new address does not list is withdrawn;
// and nothing is withdrawn while the new address cannot be read whole.
func TestAMovedUpstreamIsReconciledByItsFirstCompleteRead(t *testing.T) {
	relabel := func(body []byte) []byte {
		return bytes.ReplaceAll(body, []byte("vulnerable_code_not_present"), []byte("component_not_present"))
	}
	for _, c := range []struct {
		what    string
		alter   map[string]func([]byte) []byte
		omit    []string
		corrupt []string
		fails   bool
		// stays says the portable statement stands as the row it was;
		// revised that another row stands in its place; withdrawn that none
		// does.
		stays, revised, withdrawn bool
	}{
		{what: "unchanged", stays: true},
		{what: "revised", alter: map[string]func([]byte) []byte{portable: relabel}, revised: true},
		{what: "absent", omit: []string{portable}, withdrawn: true},
		{what: "absent, the read incomplete", omit: []string{portable}, corrupt: []string{ownBuild}, stays: true},
		{what: "unreadable", fails: true, stays: true},
	} {
		t.Run(c.what, func(t *testing.T) {
			fixture.Each(t, func(t *testing.T, f *fixture.World) {
				w := newWorld(t, f)
				first := mirror(t, w, nil, nil, nil)
				moved := mirror(t, w, c.alter, c.omit, c.corrupt)
				w.readingBoth(first, moved)
				w.trustAt(first.address())
				w.read()
				w.rescan()
				before := w.statement(portable, finding.PlacedAnybody)
				review := w.statement(ownBuild, "")
				if before == nil || review == nil {
					t.Fatal("the first address recorded nothing")
				}
				if _, err := w.findings.Decline(t.Context(), w.proposer, review.ID); err != nil {
					t.Fatal(err)
				}

				w.trustAt(moved.address())
				if c.fails {
					// Readable when it was named, and not since.
					moved.fail()
				}
				w.read()
				w.rescan()
				after := w.statement(portable, finding.PlacedAnybody)
				switch {
				case c.stays && (after == nil || after.ID != before.ID):
					t.Errorf("the statement is %+v, want the row it was", after)
				case c.revised && (after == nil || after.ID == before.ID ||
					after.Justification != "component_not_present"):
					t.Errorf("the statement is %+v, want the revision in its place", after)
				case c.withdrawn && after != nil:
					t.Errorf("a statement the new address does not list still stands: %+v", after)
				}
				got := w.state(w.forkBuild, portable, openssl)
				if got.open != c.withdrawn {
					t.Errorf("the fork's finding stands %+v", got)
				}
				if c.withdrawn || c.fails {
					return
				}
				kept := w.statement(ownBuild, "")
				if c.corrupt == nil && (kept == nil || kept.ID != review.ID || kept.DeclinedAt == nil) {
					t.Errorf("the statement repeated at the new address is %+v, want it as it was, declined", kept)
				}
			})
		})
	}
}

// A moved upstream naming a key other than the one trusted is not read until
// an administrator trusts it again.
func TestAMovedUpstreamKeepsTheTrustedKey(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		moved := mirror(t, w, nil, []string{portable}, nil)
		w.readingBoth(moved)
		w.trust()
		w.read()
		up := w.trustAt(moved.address())
		if up.Fingerprint == "" || up.KeyOffered != upstream.NoKey {
			t.Fatalf("the moved upstream holds key %q, offered %q", up.Fingerprint, up.KeyOffered)
		}
		if took := w.read(); took.Withdrawn != 0 || took.Documents != 0 {
			t.Errorf("a moved upstream naming another key was read: %+v", took)
		}
		if w.statement(portable, finding.PlacedAnybody) == nil {
			t.Error("a moved upstream naming another key withdrew a statement")
		}
	})
}

// A component named alone holds for anybody only by this deployment's own
// convention, so the same shape in a document another piece of software
// generated is offered for review and closes nothing.
func TestOnlyADocumentThisSoftwareGeneratedAppliesByItself(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		other := mirrorWith(t, w, mirroring{every: func(body []byte) []byte {
			return bytes.ReplaceAll(body, []byte(`"name":"OpenPSIRT"`), []byte(`"name":"Another Tool"`))
		}})
		w.readingBoth(other)
		w.trustAt(other.address())
		w.read()
		w.rescan()
		if got := w.state(w.forkBuild, portable, openssl); !got.open {
			t.Errorf("another tool's statement closed the fork's finding by itself: %+v", got)
		}
		if w.statement(portable, finding.PlacedAnybody) != nil {
			t.Error("another tool's statement was recorded as holding for anybody")
		}
		offers, err := w.findings.Offers(t.Context(), w.proposer, 0)
		if err != nil {
			t.Fatal(err)
		}
		offered := false
		for _, one := range offers {
			offered = offered || one.Issue == portable
		}
		if !offered {
			t.Errorf("another tool's statement is not offered for review: %+v", offers)
		}
	})
}

// A read that stops at its bound leaves the upstream due and withdraws
// nothing; the next read takes the rest.
func TestAReadStoppedAtItsBoundLeavesTheUpstreamDue(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		upstream.TakingAtMost(w.reader, 1)
		w.trust()
		took := w.read()
		if !took.Filled || took.Documents != 1 {
			t.Fatalf("a read bounded at one took %+v", took)
		}
		due, err := upstream.NewStore(w.DB.DB).Due(t.Context(),
			access.Everything("reading what upstreams publish"), time.Now().UTC().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 1 {
			t.Errorf("an upstream whose read stopped at its bound is not due: %d due", len(due))
		}
		if took := w.read(); took.Documents != 1 {
			t.Errorf("the next read took %+v, want the rest", took)
		}
	})
}

// An upstream naming a second key beside the one trusted is read no further
// until the set it names now is trusted.
func TestAnUpstreamNamingAnotherKeyBesideTheTrustedOneIsNotRead(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		up := w.trust()
		w.server.change(publish.MetadataPath, func(body []byte) []byte {
			return keysListed.ReplaceAll(body, []byte(`${1}{"fingerprint":"00FF","url":"/k.asc"},`))
		})
		if took := w.read(); took.Documents != 0 {
			t.Errorf("an upstream naming another key beside the trusted one was read: %+v", took)
		}
		held, err := upstream.NewStore(w.DB.DB).For(t.Context(), w.admin, w.fork.ID)
		if err != nil {
			t.Fatal(err)
		}
		if want := upstream.FingerprintOf("00FF," + up.Fingerprint); held.KeyOffered != want {
			t.Errorf("the upstream records %q offered, want %q", held.KeyOffered, want)
		}
	})
}

// A listing entry naming no document this can read leaves the listing unread
// in full, so a document it no longer names is not withdrawn.
func TestAListingWithAnEntryThatCannotBeReadWithdrawsNothing(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		first := mirror(t, w, nil, nil, nil)
		gone := mirrorWith(t, w, mirroring{omit: []string{portable}, junk: true})
		w.readingBoth(first, gone)
		w.trustAt(first.address())
		w.read()
		w.trustAt(gone.address())
		w.read()
		if w.statement(portable, finding.PlacedAnybody) == nil {
			t.Error("a statement was withdrawn by a read with an entry it could not read")
		}
	})
}

// A claim here that the match is wrong stands at whatever version the place
// holds, so an upstream's word closes nothing there when the version moves
// to the one it speaks about.
func TestAWrongMatchClaimStandsOverAnUpstreamAtAnyVersion(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.claim(w.forkLater, portable, opensslNext.Name, triage.Mismatched, triage.ComponentNotPresent)
		w.trust()
		w.read()
		w.ship(w.forkLater, forkNext, forkNext, openssl, forkNext, swss, swss, libnl)
		w.report(w.forkLater, portable, openssl, ownBuild, libnl)
		if got := w.state(w.forkLater, portable, openssl); !got.open {
			t.Errorf("the upstream closed a place somebody here said is a wrong match: %+v", got)
		}
	})
}

// A pass that finds what the upstream says moved queues the product's builds
// to be scanned again, so a withdrawn statement stops closing anything without
// waiting for the schedule.
func TestAPassThatMovedQueuesTheProductsBuilds(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		work := queue.New(w.DB, queue.DefaultOptions())
		pass := upstream.NewPass(w.DB.DB, work, slog.New(slog.DiscardHandler), "test", sbom.Limits{},
			w.server.roots)
		if _, err := pass.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		var queued []string
		if err := w.DB.DB.NewSelect().Model((*queue.Job)(nil)).Column("reference").
			Where(`"kind" = ?`, queue.Scan).Scan(t.Context(), &queued); err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{fmt.Sprint(w.forkBuild.ID): true, fmt.Sprint(w.forkLater.ID): true}
		for _, one := range queued {
			delete(want, one)
		}
		if len(want) != 0 {
			t.Errorf("the pass queued %v, missing the fork's builds %v", queued, want)
		}
	})
}

// A decision started from an upstream's statement is told the upstream stopped
// being trusted in those words, and the notice clears once the upstream is
// trusted again and says the same thing.
func TestStoppingTrustingAnUpstreamIsSaidAsThatToADecisionCitingIt(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.read()
		review := w.statement(ownBuild, "")
		if err := w.Access.GrantRole(t.Context(), w.proposer.ID, w.fork.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		w.claimCiting(w.forkBuild, ownBuild, libnl.Name, triage.NotApplicable,
			triage.CodeNotInExecutePath, &review.ID)
		said := func() []string {
			t.Helper()
			if _, _, err := notify.NewWatch(w.DB.DB, slog.New(slog.DiscardHandler)).Once(t.Context()); err != nil {
				t.Fatal(err)
			}
			rows, _, err := notify.NewStore(w.DB.DB).Waiting(t.Context(), w.proposer, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, row := range rows {
				if row.Kind == notify.StatementRevised && row.ClearedAt == nil {
					out = append(out, row.Body)
				}
			}
			return out
		}
		if _, err := upstream.NewStore(w.DB.DB).Withdraw(t.Context(), w.admin, w.fork.ID); err != nil {
			t.Fatal(err)
		}
		got := said()
		if len(got) != 1 || !strings.Contains(got[0], "stopped trusting its upstream") {
			t.Fatalf("a decision citing an upstream no longer trusted is told %v", got)
		}
		w.trust()
		w.read()
		if got := said(); len(got) != 0 {
			t.Errorf("trusted again and saying the same, the decision is still told %v", got)
		}
	})
}

// A document that does not match the digest served beside it is not taken,
// from an upstream that signs nothing, so only the digest stands in the way.
func TestADocumentNotMatchingItsDigestIsNotTaken(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		unsigned := mirror(t, w, nil, nil, []string{portable})
		w.readingBoth(unsigned)
		w.trustAt(unsigned.address())
		if took := w.read(); took.Refused != 1 {
			t.Errorf("the read refused %d documents, want the one not matching its digest", took.Refused)
		}
		w.rescan()
		if w.statement(portable, finding.PlacedAnybody) != nil {
			t.Error("a document not matching its digest was recorded")
		}
	})
}
