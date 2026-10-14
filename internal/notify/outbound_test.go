// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// took records what a destination received.
type took struct {
	mu       sync.Mutex
	bodies   []string
	signed   []string
	stamped  []string
	requests int
}

func (t *took) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requests++
	t.bodies = append(t.bodies, string(body))
	t.signed = append(t.signed, r.Header.Get("X-OpenPSIRT-Signature"))
	t.stamped = append(t.stamped, r.Header.Get("X-OpenPSIRT-Timestamp"))
	w.WriteHeader(http.StatusNoContent)
}

// count is how many requests the destination received.
func (t *took) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.requests
}

// sharedSecret is the signing secret every test destination is configured
// with.
const sharedSecret = "a-shared-secret-long-enough"

// webhook is a deployment with one administrator and one destination, pointed
// at a test server that records what it takes.
type webhook struct {
	store  *notify.Store
	signal *notify.Signal
	saw    *took
	admin  *access.Account
	server *httptest.Server
}

// webhookWorld configures one destination by name and kind, administered by
// Ana, at a test server that records every request.
func webhookWorld(t *testing.T, db *database.DB, name, kind string) *webhook {
	t.Helper()
	saw := &took{}
	hook := webhookAnswering(t, db, name, kind, http.HandlerFunc(saw.handle))
	hook.saw = saw
	return hook
}

// webhookAnswering is webhookWorld with a server that answers through the
// handler given, and records nothing.
func webhookAnswering(t *testing.T, db *database.DB, name, kind string, handler http.Handler) *webhook {
	t.Helper()
	ctx := t.Context()
	admin, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	store := notify.NewStore(db.DB)
	if _, err := store.AddDestination(ctx, asks(t, db, admin), notify.Destination{
		Name: name, Kind: kind, URL: server.URL, Secret: sharedSecret,
	}, nil); err != nil {
		t.Fatal(err)
	}

	// The client refuses anything but https and does not follow a redirect,
	// so the test server's own certificate is trusted the way a deployment
	// trusts its destination's.
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
	notify.TrustForTest(signal, server.Client())
	return &webhook{store: store, signal: signal, admin: admin, server: server}
}

func TestOneSignedRequestCarriesWhatWasSaid(t *testing.T) {
	// One signed request gives a chat channel, a tracker and paging without
	// an adapter for any of them.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)
		saw := hook.saw
		if err := hook.store.Tell(ctx, notify.Telling{
			PersonID: hook.admin.ID, Kind: notify.Assigned,
			Body: "CVE-2026-9999 in libnl-3-200 is yours", Link: "/products/x",
		}); err != nil {
			t.Fatal(err)
		}

		sent, failed, err := hook.signal.Once(ctx)
		if err != nil {
			t.Fatalf("signalling: %v", err)
		}
		if sent != 1 || failed != 0 {
			t.Fatalf("sent %d and failed %d, want one sent", sent, failed)
		}
		if got := saw.count(); got != 1 {
			t.Fatalf("the destination received %d requests", got)
		}

		// It carries what a mail would carry, composed by the same code.
		var body struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
			Text    string `json:"text"`
			Link    string `json:"link"`
		}
		if err := json.Unmarshal([]byte(saw.bodies[0]), &body); err != nil {
			t.Fatal(err)
		}
		if body.Kind != string(notify.Assigned) || body.Subject == "" {
			t.Errorf("the body reads as %+v", body)
		}
		if !strings.Contains(body.Text, "CVE-2026-9999") {
			t.Errorf("the body does not carry what was said: %q", body.Text)
		}
		if !strings.HasPrefix(body.Link, "https://openpsirt.example") {
			t.Errorf("the link is not one a reader elsewhere can follow: %q", body.Link)
		}

		// Signed over the timestamp and the body, so a receiver can tell one
		// of ours from one anybody could make and cannot replay yesterday's.
		mac := hmac.New(sha256.New, []byte(sharedSecret))
		mac.Write([]byte(saw.stamped[0]))
		mac.Write([]byte("."))
		mac.Write([]byte(saw.bodies[0]))
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if saw.signed[0] != want {
			t.Errorf("the signature is %q, want %q", saw.signed[0], want)
		}

		// And it goes once. A sweep every minute must not repeat what it has
		// already said.
		if sent, _, err := hook.signal.Once(ctx); err != nil || sent != 0 {
			t.Errorf("a second sweep sent %d (%v)", sent, err)
		}
		if got := saw.count(); got != 1 {
			t.Errorf("the destination received %d requests in total", got)
		}
	})
}

func TestAWebhookCarriesThirdPartyTextAsTextToAChatChannel(t *testing.T) {
	// A publisher's name, a supplier's failure text and a component name
	// reach a notification body, and a chat channel reads angle brackets as
	// its own markup: a ping for the whole channel, or a link labelled
	// anything. The three characters that open it are escaped.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)
		saw := hook.saw
		if err := hook.store.Tell(ctx, notify.Telling{
			PersonID: hook.admin.ID, Kind: notify.StatementRevised,
			Body: "<!channel> <https://evil.example|security update> & Sons changed a statement " +
				"on [Download the fix](https://evil.example/p)",
			Link: "/issues/CVE-2026-1?from=a&to=b",
		}); err != nil {
			t.Fatal(err)
		}
		if sent, _, err := hook.signal.Once(ctx); err != nil || sent != 1 {
			t.Fatalf("sent %d (%v), want one", sent, err)
		}

		var body struct {
			Subject string `json:"subject"`
			Text    string `json:"text"`
			Link    string `json:"link"`
		}
		if err := json.Unmarshal([]byte(saw.bodies[0]), &body); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(body.Text, "<>") || strings.ContainsAny(body.Subject, "<>") {
			t.Errorf("chat markup reached a channel: %q", body.Text)
		}
		for _, want := range []string{
			`\&lt;!channel&gt; \&lt;https\://evil.example\|security update&gt; &amp; Sons`,
			`\[Download the fix\](https\://evil.example/p)`,
			// The address this deployment composed is still one to follow.
			"\nhttps://openpsirt.example/issues/CVE-2026-1?from=a&amp;to=b\n",
		} {
			if !strings.Contains(body.Text, want) {
				t.Errorf("the text reads %q, want it to carry %q", body.Text, want)
			}
		}
		// The address is ours and travels in its own field, as it is.
		if body.Link != "https://openpsirt.example/issues/CVE-2026-1?from=a&to=b" {
			t.Errorf("the link reads %q", body.Link)
		}
	})
}

// A webhook body is composed by the same code that composes a mail, so the
// no-detail rule reaches it — including the address, which travels in a field
// of its own where a receiver reads it without opening the text.
//
// A link rebuilt from the row beside the body announces the identifier, the
// product, the stream, the variant and the component to every server the
// request crosses.
func TestNothingUndisclosedTravelsInAWebhookAddress(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)
		saw := hook.saw
		product := w.Product
		ids, err := finding.NewVulnerabilities(db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "SONIC-2026-7002", Severity: "critical"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := ids["SONIC-2026-7002"]

		// The shape a disclosure notice takes: every part of what it is about
		// is in the path.
		const where = "/products/sonic/streams/master/variants/broadcom" +
			"/findings/SONIC-2026-7002/components/swss"
		if err := hook.store.Tell(ctx, notify.Telling{
			PersonID: hook.admin.ID, Kind: notify.DisclosureDue,
			Body: "SONIC-2026-7002 in swss reached its date",
			Link: where, Private: true,
			ProductID: &product.ID, VulnerabilityID: &issue,
		}); err != nil {
			t.Fatal(err)
		}

		if sent, failed, err := hook.signal.Once(ctx); err != nil || sent != 1 || failed != 0 {
			t.Fatalf("signalling sent %d and failed %d (%v)", sent, failed, err)
		}
		if got := saw.count(); got != 1 {
			t.Fatalf("the destination received %d requests", got)
		}

		// Whole-body, not field by field: the rule is about what crosses the
		// wire, and a field added later is covered by this and not by a check
		// on the fields somebody thought of.
		body := saw.bodies[0]
		for _, leaked := range []string{
			"SONIC-2026-7002", "sonic", "master", "broadcom", "swss", "/findings/",
		} {
			if strings.Contains(body, leaked) {
				t.Errorf("the request carries %q, which is the announcement it exists to avoid:\n%s",
					leaked, body)
			}
		}

		// And it still says there is something, with the way in. A message
		// carrying nothing at all is one nobody acts on.
		var carried struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
			Link    string `json:"link"`
			Private bool   `json:"undisclosed"`
		}
		if err := json.Unmarshal([]byte(body), &carried); err != nil {
			t.Fatal(err)
		}
		if carried.Link != "https://openpsirt.example/" {
			t.Errorf("the address is %q, want the front door", carried.Link)
		}
		if !carried.Private || carried.Subject == "" {
			t.Errorf("the body reads as %+v, which does not say there is something", carried)
		}
	})
}

func TestADestinationTakesOnlyItsOwnKind(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		// Paging takes what is worth interrupting somebody for, and nothing
		// else — which is the whole reason a destination names a kind.
		hook := webhookWorld(t, db, "paging", string(notify.CriticalOnRelease))
		who := hook.admin
		if err := hook.store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.Assigned, Body: "yours", Link: "/x",
		}); err != nil {
			t.Fatal(err)
		}

		if sent, _, err := hook.signal.Once(ctx); err != nil || sent != 0 {
			t.Errorf("a destination took a kind it did not ask for: %d (%v)", sent, err)
		}
		if got := hook.saw.count(); got != 0 {
			t.Errorf("it received %d requests", got)
		}

		// A kind nothing is of is refused rather than stored as a
		// destination that never receives anything. Case is folded first.
		if _, err := hook.store.AddDestination(ctx, asks(t, db, who), notify.Destination{
			Name: "typo", Kind: "asigned", URL: hook.server.URL, Secret: sharedSecret,
		}, nil); err == nil {
			t.Error("a destination was stored for a kind nothing is of")
		}
		if _, err := hook.store.AddDestination(ctx, asks(t, db, who), notify.Destination{
			Name: "folded", Kind: " Assigned ", URL: hook.server.URL, Secret: sharedSecret,
		}, nil); err != nil {
			t.Errorf("a kind written in capitals was refused: %v", err)
		}
	})
}

func TestNothingLeavesOverPlainHTTP(t *testing.T) {
	// The body is signed and not encrypted, and what it carries is what
	// somebody is being told about a vulnerability.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		// Refused where it is configured, which is the first of the two.
		if _, err := store.AddDestination(ctx, asks(t, db, who), notify.Destination{
			Name: "plain", Kind: notify.Everything, URL: server.URL, Secret: sharedSecret,
		}, nil); err == nil {
			t.Fatal("a plain http destination was accepted")
		}
		// And refused again where the request is made, which is the one that
		// holds for a row that reached the table any other way — an upgrade
		// from a build that did not refuse it, or somebody editing the
		// database. The row is written directly here for exactly that reason.
		if _, err := db.DB.NewInsert().Model(&notify.Outbound{
			Name: "plain", Kind: notify.Everything, Platform: notify.Webhook, URL: server.URL,
			Secret: sharedSecret, CreatedBy: who.ID,
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.Assigned, Body: "yours", Link: "/x",
		}); err != nil {
			t.Fatal(err)
		}

		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		sent, failed, err := signal.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sent != 0 || failed != 1 {
			t.Errorf("plain http sent %d and failed %d", sent, failed)
		}
		if got := saw.count(); got != 0 {
			t.Errorf("something reached a plain http destination: %d", got)
		}
	})
}

func TestTheSweepReachesWhatIsCreatedAfterABacklogOfEvents(t *testing.T) {
	// An event row is never cleared — only a condition is. A window of the
	// oldest two hundred uncleared notifications re-reads the same two
	// hundred on every cycle once that many events exist, and signals nothing
	// created afterwards, with no error, no log and no counter. A deployment
	// reaches that in the first two hundred events of its life.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "everything", notify.Everything)
		store, signal, saw, who := hook.store, hook.signal, hook.saw, hook.admin

		// A backlog the size of one sweep, so the next thing said falls
		// outside the window the sweep reads.
		for i := range notify.SweepBatch {
			if err := store.Tell(ctx, notify.Telling{
				PersonID: who.ID, Kind: notify.Assigned,
				Body: fmt.Sprintf("backlog %d", i), Link: "/x",
			}); err != nil {
				t.Fatal(err)
			}
		}
		if sent, _, err := signal.Once(ctx); err != nil || sent != notify.SweepBatch {
			t.Fatalf("the backlog carried %d of %d (%v)", sent, notify.SweepBatch, err)
		}

		if err := store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.Assigned, Body: "the newest one", Link: "/x",
		}); err != nil {
			t.Fatal(err)
		}
		sent, _, err := signal.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sent != 1 {
			t.Fatalf("the sweep carried %d after the backlog, want the one created since", sent)
		}
		saw.mu.Lock()
		defer saw.mu.Unlock()
		if last := saw.bodies[len(saw.bodies)-1]; !strings.Contains(last, "the newest one") {
			t.Errorf("what went was %q, want the notification created after the backlog", last)
		}
	})
}

func TestWhereThingsGoIsAnAdministratorsQuestionAndCarriesNoSecret(t *testing.T) {
	// The store asks the subject itself, so a caller marshalling what comes
	// back cannot publish a shared secret, and no handler has to remember to
	// refuse.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		other, err := rights.Ensure(ctx, "bo@example.com", "Bo", nil, nil)
		if err != nil {
			t.Fatal(err)
		}

		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, admin), notify.Destination{
			Name: "chat", Kind: notify.Everything, URL: "https://chat.example.test/hook", Secret: sharedSecret,
		}, nil); err != nil {
			t.Fatal(err)
		}

		// Nothing about a destination is anybody else's to read or to change.
		if _, err := store.Destinations(ctx, asks(t, db, other)); !errors.Is(err, access.ErrDenied) {
			t.Errorf("reading where things go as a non-administrator answered %v", err)
		}
		if _, err := store.AddDestination(ctx, asks(t, db, other), notify.Destination{
			Name: "theirs", Kind: notify.Everything, URL: "https://elsewhere.example.test/hook", Secret: sharedSecret,
		}, nil); !errors.Is(err, access.ErrDenied) {
			t.Errorf("configuring a destination as a non-administrator answered %v", err)
		}
		if _, err := store.RetireDestination(ctx, asks(t, db, other), "chat",
			notify.Everything); !errors.Is(err, access.ErrDenied) {
			t.Errorf("retiring a destination as a non-administrator answered %v", err)
		}

		// And what an administrator does read carries no secret to leave
		// behind — the type has no field for one.
		rows, err := store.Destinations(ctx, asks(t, db, admin))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("%d destinations came back, want the one", len(rows))
		}
		shown, err := json.Marshal(rows[0])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(shown), sharedSecret) {
			t.Errorf("the signing secret crossed the store boundary: %s", shown)
		}
	})
}

func TestADestinationTakingOneKindReachesPastABacklogOfAnother(t *testing.T) {
	// A row this destination does not take never gets a delivery row, so a
	// window chosen whatever the kind keeps it for ever. The kind decides the
	// window, and a paging destination behind two hundred ordinary events
	// still advances. The backlog test above does not reach this, because its
	// destination takes every kind.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "paging", string(notify.CriticalOnRelease))
		store, who := hook.store, hook.admin

		// A window's worth of a kind this destination does not take.
		for i := range notify.SweepBatch {
			if err := store.Tell(ctx, notify.Telling{
				PersonID: who.ID, Kind: notify.Assigned,
				Body: fmt.Sprintf("not for paging %d", i), Link: "/x",
			}); err != nil {
				t.Fatal(err)
			}
		}
		// And then the one it does, created after all of them.
		if _, _, err := store.Reconcile(ctx, who.ID, notify.CriticalOnRelease, []notify.Holds{{
			About: "critical-on-release sonic v1.0 broadcom",
			Body:  "A release carries an unaddressed critical.",
			Link:  "/findings/1",
		}}); err != nil {
			t.Fatal(err)
		}

		sent, _, err := hook.signal.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sent != 1 {
			t.Fatalf("the sweep carried %d, want the one of this destination's kind "+
				"from behind the backlog", sent)
		}
	})
}

func TestAConditionOpenedForSeveralPeopleDoesNotFillTheWindow(t *testing.T) {
	// A delivery is keyed on what was said, so a condition opened for six
	// people is six notification rows and one delivery — which is deliberate,
	// because a channel wants it once. Asked "settled here?" by the row's own
	// number, five of those six are never settled: the duplicate arm returns
	// without writing anything for them, so they answer the predicate for
	// ever and, being the oldest, hold the front of the window. A few dozen
	// people across the condition kinds is enough to stop the sweep
	// advancing.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)
		store, first := hook.store, hook.admin
		rights := access.NewStore(db.DB)

		// One condition, opened for several people: one thing to say and
		// several rows saying it.
		held := []notify.Holds{{
			About: "build-quiet sonic master broadcom",
			Body:  "Nothing has been filed against sonic master broadcom.",
			Link:  "/builds/1",
		}}
		for i := range 6 {
			who := first
			if i > 0 {
				var err error
				who, err = rights.Ensure(ctx,
					fmt.Sprintf("them-%d@example.com", i), "Them", access.Stated(true), nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := store.Reconcile(ctx, who.ID, notify.BuildQuiet, held); err != nil {
				t.Fatal(err)
			}
		}

		if _, _, err := hook.signal.Once(ctx); err != nil {
			t.Fatal(err)
		}
		// One request, which is the point of keying on what was said.
		if requests := hook.saw.count(); requests != 1 {
			t.Errorf("a condition opened for six people was sent %d times", requests)
		}

		// And every one of the six has left the window. Asked of what was
		// sent, six rows still fit inside it and the sweep reaches past them
		// — so the question is put to the predicate, which is what wedges.
		left, err := notify.StillToTell(hook.signal, ctx, "chat")
		if err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("%d of the six rows can never be settled, so they hold the front "+
				"of the window for ever", left)
		}
	})
}

// A condition that clears and later comes back is carried again. The
// delivery is keyed on the condition, so without scoping it to one opening
// the second failure of a control reaches no channel at all.
func TestAConditionThatClearsAndReturnsIsCarriedAgain(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)
		store, signal, admin := hook.store, hook.signal, hook.admin
		held := []notify.Holds{{
			About: "risk-unagreed", Body: "A claim stands with nobody agreeing.",
			Link: "/reports/approval-quality",
		}}

		for _, step := range []struct {
			holding []notify.Holds
			want    int
		}{
			{held, 1},
			{nil, 1},  // it cleared, which is not news
			{held, 2}, // it came back, which is
			{held, 2}, // and is still the same opening
		} {
			if _, _, err := store.Reconcile(ctx, admin.ID, notify.RiskUnagreed, step.holding); err != nil {
				t.Fatal(err)
			}
			if _, _, err := signal.Once(ctx); err != nil {
				t.Fatal(err)
			}
			if got := hook.saw.count(); got != step.want {
				t.Fatalf("the channel was sent %d requests, want %d", got, step.want)
			}
		}
		left, err := notify.StillToTell(signal, ctx, "chat")
		if err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("%d rows are still to tell after the returned condition was carried", left)
		}
	})
}

// A condition held by several people is one opening while any of them still
// holds it. The row the delivery was claimed for clearing, while another
// holder's row stays open across that moment, is not the condition returning.
func TestAConditionStillHeldBySomebodyElseIsNotCarriedAgain(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)
		store, signal, ana := hook.store, hook.signal, hook.admin
		ben, err := access.NewStore(db.DB).Ensure(ctx, "ben@example.com", "Ben", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		held := []notify.Holds{{
			About: "risk-unagreed", Body: "A claim stands with nobody agreeing.",
			Link: "/reports/approval-quality",
		}}

		// Ana's row opens first, so the delivery is claimed for it.
		for _, step := range []struct {
			name    string
			who     int64
			holding []notify.Holds
			want    int
		}{
			{"Ana holds it", ana.ID, held, 1},
			{"Ben holds it too", ben.ID, held, 1},
			{"Ana's row clears while Ben's stays open", ana.ID, nil, 1},
			{"Ana holds it again while Ben still does", ana.ID, held, 1},
			{"Ana's second row clears", ana.ID, nil, 1},
			{"Ben's row clears, so nobody holds it", ben.ID, nil, 1},
			{"Ana holds it after it ended", ana.ID, held, 2},
		} {
			if _, _, err := store.Reconcile(ctx, step.who, notify.RiskUnagreed, step.holding); err != nil {
				t.Fatal(err)
			}
			if _, _, err := signal.Once(ctx); err != nil {
				t.Fatal(err)
			}
			if got := hook.saw.count(); got != step.want {
				t.Fatalf("%s: the channel was sent %d requests, want %d", step.name, got, step.want)
			}
		}
		left, err := notify.StillToTell(signal, ctx, "chat")
		if err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("%d rows are still to tell after one opening was carried", left)
		}
	})
}

// A destination's reason is why the last delivery failed, and nothing once one
// has gone since.
func TestADestinationSaysWhyItLastFailed(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()

		// Answers by what it is sent, so each delivery fails its own way.
		hook := webhookAnswering(t, db, "chat", notify.Everything, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), "first"):
				w.WriteHeader(http.StatusInternalServerError)
			case strings.Contains(string(body), "second"):
				w.WriteHeader(http.StatusForbidden)
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		store, signal, admin := hook.store, hook.signal, hook.admin

		var holding []notify.Holds
		for _, step := range []struct{ said, want string }{
			{"first", "500"},
			{"second", "403"},
			{"third", ""},
		} {
			holding = append(holding, notify.Holds{About: step.said, Body: "The " + step.said + " thing."})
			if _, _, err := store.Reconcile(ctx, admin.ID, notify.RiskUnagreed, holding); err != nil {
				t.Fatal(err)
			}
			if _, _, err := signal.Once(ctx); err != nil {
				t.Fatal(err)
			}
			listed, err := store.Destinations(ctx, asks(t, db, admin))
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 {
				t.Fatalf("%d destinations listed", len(listed))
			}
			because := listed[0].Because
			if (step.want == "") != (because == "") || !strings.Contains(because, step.want) {
				t.Errorf("after the %s delivery the reason reads %q, want one naming %q",
					step.said, because, step.want)
			}
		}
	})
}

func TestOneUploadReachesAChannelOnceHoweverManyReadItsProduct(t *testing.T) {
	// The event that says the same sentence to everybody. Keyed on the row,
	// a product with six readers carries one upload to a channel six times,
	// and a night of builds fills the sweep with copies of itself — which is
	// the shape the condition arm above already refuses.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)
		store, first := hook.store, hook.admin
		rights := access.NewStore(db.DB)

		// One upload, told to six people, each of them naming the same thing.
		for i := range 6 {
			who := first
			if i > 0 {
				var err error
				who, err = rights.Ensure(ctx,
					fmt.Sprintf("them-%d@example.com", i), "Them", access.Stated(true), nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Tell(ctx, notify.Telling{
				PersonID: who.ID, Kind: notify.InventoryMoved,
				Body:     "sonic master broadcom: 21 names moved in one upload.",
				Link:     "/products/sonic/streams/master/variants/broadcom/scans/4/changes",
				Together: "one-upload",
			}); err != nil {
				t.Fatal(err)
			}
		}

		if _, _, err := hook.signal.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if requests := hook.saw.count(); requests != 1 {
			t.Errorf("one upload told to six people was sent %d times", requests)
		}

		// And the five that rode on the first one's delivery have left the
		// window, or they hold the front of it for ever.
		left, err := notify.StillToTell(hook.signal, ctx, "chat")
		if err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("%d of the six rows can never be settled", left)
		}
	})
}

func TestTwoUploadsAreTwoThingsToCarry(t *testing.T) {
	// The other side of the same key: what collapses is one upload told to
	// many people, never two uploads. Keyed on the kind alone, the second
	// night of a build that keeps changing would be silently dropped.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		hook := webhookWorld(t, db, "chat", notify.Everything)

		for _, upload := range []string{"scan-4", "scan-5"} {
			if err := hook.store.Tell(ctx, notify.Telling{
				PersonID: hook.admin.ID, Kind: notify.InventoryMoved,
				Body: "sonic master broadcom moved a great deal in " + upload,
				Link: "/scans/" + upload + "/changes", Together: upload,
			}); err != nil {
				t.Fatal(err)
			}
		}

		if _, _, err := hook.signal.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if requests := hook.saw.count(); requests != 2 {
			t.Errorf("two uploads were sent %d times, want one each", requests)
		}
	})
}

// One cycle sends at most one batch of requests across every destination. The
// lease is sized for one batch, so a cycle walking a batch per destination
// outlived it and a second replica took the lease and sent beside the first.
func TestACycleSendsOneBatchAcrossEveryDestination(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()
		store := notify.NewStore(db.DB)
		for _, name := range []string{"one", "two"} {
			if _, err := store.AddDestination(ctx, asks(t, db, who), notify.Destination{
				Name: name, Kind: string(notify.Everything), URL: server.URL, Secret: "a-shared-secret-long-enough",
			}, nil); err != nil {
				t.Fatal(err)
			}
		}
		for i := range notify.SweepBatch {
			if err := store.Tell(ctx, notify.Telling{
				PersonID: who.ID, Kind: notify.Assigned, Body: fmt.Sprintf("backlog %d", i), Link: "/x",
			}); err != nil {
				t.Fatal(err)
			}
		}
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		sent, _, err := signal.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sent != notify.SweepBatch {
			t.Errorf("one cycle over two destinations sent %d, want one batch of %d", sent, notify.SweepBatch)
		}
		// And the next cycle carries on where it stopped.
		if more, _, err := signal.Once(ctx); err != nil || more != notify.SweepBatch {
			t.Errorf("the next cycle sent %d (%v), want the other batch", more, err)
		}
	})
}

// A destination that refuses every request spends its own part of a cycle and
// no more, so a destination configured after it is still served every cycle.
func TestADestinationThatIsDownDoesNotStarveTheOthers(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		down := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer down.Close()
		up := &took{}
		healthy := httptest.NewTLSServer(http.HandlerFunc(up.handle))
		defer healthy.Close()
		store := notify.NewStore(db.DB)
		// The one that is down is configured first, so it is the one a
		// budget spent in table order reaches first.
		for _, to := range []struct{ name, url string }{{"down", down.URL}, {"up", healthy.URL}} {
			if _, err := store.AddDestination(ctx, asks(t, db, who), notify.Destination{
				Name: to.name, Kind: string(notify.Everything), URL: to.url, Secret: sharedSecret,
			}, nil); err != nil {
				t.Fatal(err)
			}
		}
		for i := range notify.SweepBatch {
			if err := store.Tell(ctx, notify.Telling{
				PersonID: who.ID, Kind: notify.Assigned, Body: fmt.Sprintf("backlog %d", i), Link: "/x",
			}); err != nil {
				t.Fatal(err)
			}
		}
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		// Both servers share one certificate authority, so one client
		// trusts either.
		notify.TrustForTest(signal, down.Client())
		for cycle := range 2 {
			before := up.count()
			sent, failed, err := signal.Once(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := up.count() - before; got < notify.SweepBatch/2 {
				t.Errorf("cycle %d sent the healthy destination %d requests (sent %d, failed %d), want at least half of %d",
					cycle, got, sent, failed, notify.SweepBatch)
			}
		}
	})
}

// An attempt still being made is not made again beside it. One that failed,
// or whose sender stopped part way, is taken again.
func TestADeliveryInFlightIsNotSentTwice(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		refusing, requests := true, 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			requests++
			if refusing {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, who), notify.Destination{
			Name: "chat", Kind: string(notify.Everything), URL: server.URL, Secret: "a-shared-secret-long-enough",
		}, nil); err != nil {
			t.Fatal(err)
		}
		if err := store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.Assigned, Body: "one thing", Link: "/x",
		}); err != nil {
			t.Fatal(err)
		}
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		if _, failed, err := signal.Once(ctx); err != nil || failed != 1 {
			t.Fatalf("the first attempt failed %d (%v), want 1", failed, err)
		}
		mu.Lock()
		refusing = false
		mu.Unlock()

		attempt := func(at time.Time) {
			t.Helper()
			if _, err := db.DB.NewUpdate().TableExpr(`"outbound_delivery"`).
				Set("failed = ?", "").Set("attempted_at = ?", at).Where("1 = 1").Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// An attempt begun a moment ago, neither gone nor failed: another
		// sender is making it.
		attempt(time.Now().UTC())
		if sent, _, err := signal.Once(ctx); err != nil || sent != 0 {
			t.Errorf("a delivery being made was made again beside it: sent %d (%v)", sent, err)
		}
		// Begun an hour ago and never settled: its sender stopped.
		attempt(time.Now().UTC().Add(-time.Hour))
		if sent, _, err := signal.Once(ctx); err != nil || sent != 1 {
			t.Errorf("a delivery whose sender stopped was not taken again: sent %d (%v)", sent, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if requests != 2 {
			t.Errorf("the destination was asked %d times, want the failed attempt and the one after the stop", requests)
		}
	})
}
