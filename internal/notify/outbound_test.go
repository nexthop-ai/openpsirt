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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
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

func TestOneSignedRequestCarriesWhatWasSaid(t *testing.T) {
	// One signed request gives a chat channel, a tracker and paging without
	// an adapter for any of them.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		who, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}

		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		const secret = "a-shared-secret-long-enough"
		if _, err := store.AddDestination(ctx, asks(t, db, who), "chat", notify.Everything,
			server.URL, secret); err != nil {
			t.Fatal(err)
		}
		if err := store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.Assigned,
			Body: "CVE-2026-9999 in libnl-3-200 is yours", Link: "/products/x",
		}); err != nil {
			t.Fatal(err)
		}

		// The client refuses anything but https and will not follow a
		// redirect, so the test server's own certificate has to be trusted the
		// way a deployment would trust its destination's.
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())

		sent, failed, err := signal.Once(ctx)
		if err != nil {
			t.Fatalf("signalling: %v", err)
		}
		if sent != 1 || failed != 0 {
			t.Fatalf("sent %d and failed %d, want one sent", sent, failed)
		}
		if saw.requests != 1 {
			t.Fatalf("the destination received %d requests", saw.requests)
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
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(saw.stamped[0]))
		mac.Write([]byte("."))
		mac.Write([]byte(saw.bodies[0]))
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if saw.signed[0] != want {
			t.Errorf("the signature is %q, want %q", saw.signed[0], want)
		}

		// And it goes once. A sweep every minute must not repeat what it has
		// already said.
		if sent, _, err := signal.Once(ctx); err != nil || sent != 0 {
			t.Errorf("a second sweep sent %d (%v)", sent, err)
		}
		if saw.requests != 1 {
			t.Errorf("the destination received %d requests in total", saw.requests)
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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, who), "chat", notify.Everything,
			server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}
		if err := store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.StatementRevised,
			Body: "<!channel> <https://evil.example|security update> & Sons changed a statement " +
				"on [Download the fix](https://evil.example/p)",
			Link: "/issues/CVE-2026-1?from=a&to=b",
		}); err != nil {
			t.Fatal(err)
		}
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		if sent, _, err := signal.Once(ctx); err != nil || sent != 1 {
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
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		who, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		ids, err := finding.NewVulnerabilities(db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "SONIC-2026-7002", Severity: "critical"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := ids["SONIC-2026-7002"]

		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, who), "chat", notify.Everything,
			server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}
		// The shape a disclosure notice takes: every part of what it is about
		// is in the path.
		const where = "/products/sonic/streams/master/variants/broadcom" +
			"/findings/SONIC-2026-7002/components/swss"
		if err := store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.DisclosureDue,
			Body: "SONIC-2026-7002 in swss reached its date",
			Link: where, Private: true,
			ProductID: &product.ID, VulnerabilityID: &issue,
		}); err != nil {
			t.Fatal(err)
		}

		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		if sent, failed, err := signal.Once(ctx); err != nil || sent != 1 || failed != 0 {
			t.Fatalf("signalling sent %d and failed %d (%v)", sent, failed, err)
		}
		if saw.requests != 1 {
			t.Fatalf("the destination received %d requests", saw.requests)
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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		// Paging takes what is worth interrupting somebody for, and nothing
		// else — which is the whole reason a destination names a kind.
		if _, err := store.AddDestination(ctx, asks(t, db, who), "paging", string(notify.CriticalOnRelease),
			server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}
		if err := store.Tell(ctx, notify.Telling{
			PersonID: who.ID, Kind: notify.Assigned, Body: "yours", Link: "/x",
		}); err != nil {
			t.Fatal(err)
		}

		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		if sent, _, err := signal.Once(ctx); err != nil || sent != 0 {
			t.Errorf("a destination took a kind it did not ask for: %d (%v)", sent, err)
		}
		if saw.requests != 0 {
			t.Errorf("it received %d requests", saw.requests)
		}

		// A kind nothing is of is refused rather than stored as a
		// destination that never receives anything. Case is folded first.
		if _, err := store.AddDestination(ctx, asks(t, db, who), "typo", "asigned",
			server.URL, "a-shared-secret-long-enough"); err == nil {
			t.Error("a destination was stored for a kind nothing is of")
		}
		if _, err := store.AddDestination(ctx, asks(t, db, who), "folded", " Assigned ",
			server.URL, "a-shared-secret-long-enough"); err != nil {
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
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		// Refused where it is configured, which is the first of the two.
		if _, err := store.AddDestination(ctx, asks(t, db, who), "plain", notify.Everything,
			server.URL, "a-shared-secret-long-enough"); err == nil {
			t.Fatal("a plain http destination was accepted")
		}
		// And refused again where the request is made, which is the one that
		// holds for a row that reached the table any other way — an upgrade
		// from a build that did not refuse it, or somebody editing the
		// database. The row is written directly here for exactly that reason.
		if _, err := db.DB.NewInsert().Model(&notify.Outbound{
			Name: "plain", Kind: notify.Everything, URL: server.URL,
			Secret: "a-shared-secret-long-enough", CreatedBy: who.ID,
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
		if saw.requests != 0 {
			t.Errorf("something reached a plain http destination: %d", saw.requests)
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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, who), "everything", string(notify.Everything),
			server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}

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
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
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
		dbtest.Reset(t, db)

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
		if _, err := store.AddDestination(ctx, asks(t, db, admin), "chat", notify.Everything,
			"https://chat.example.test/hook", "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}

		// Nothing about a destination is anybody else's to read or to change.
		if _, err := store.Destinations(ctx, asks(t, db, other)); !errors.Is(err, access.ErrDenied) {
			t.Errorf("reading where things go as a non-administrator answered %v", err)
		}
		if _, err := store.AddDestination(ctx, asks(t, db, other), "theirs", notify.Everything,
			"https://elsewhere.example.test/hook", "a-shared-secret-long-enough"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("configuring a destination as a non-administrator answered %v", err)
		}
		if err := store.RetireDestination(ctx, asks(t, db, other), "chat",
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
		if strings.Contains(string(shown), "a-shared-secret-long-enough") {
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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, who), "paging",
			string(notify.CriticalOnRelease), server.URL,
			"a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}

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

		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		sent, _, err := signal.Once(ctx)
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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		first, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, first), "chat",
			notify.Everything, server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}

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

		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		if _, _, err := signal.Once(ctx); err != nil {
			t.Fatal(err)
		}
		// One request, which is the point of keying on what was said.
		saw.mu.Lock()
		requests := saw.requests
		saw.mu.Unlock()
		if requests != 1 {
			t.Errorf("a condition opened for six people was sent %d times", requests)
		}

		// And every one of the six has left the window. Asked of what was
		// sent, six rows still fit inside it and the sweep reaches past them
		// — so the question is put to the predicate, which is what wedges.
		left, err := notify.StillToTell(signal, ctx, "chat")
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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		admin, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, admin), "chat",
			notify.Everything, server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}
		held := []notify.Holds{{
			About: "risk-unagreed", Body: "A claim stands with nobody agreeing.",
			Link: "/reports/rubber-stamp",
		}}
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		requests := func() int {
			saw.mu.Lock()
			defer saw.mu.Unlock()
			return saw.requests
		}

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
			if got := requests(); got != step.want {
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

// A destination's reason is why the last delivery failed, and nothing once one
// has gone since.
func TestADestinationSaysWhyItLastFailed(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		// Answers by what it is sent, so each delivery fails its own way.
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		defer server.Close()

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, admin), "chat",
			notify.Everything, server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}
		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())

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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		first, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, first), "chat",
			notify.Everything, server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}

		// One upload, told to six people, each of them naming the same thing.
		for i := range 6 {
			who := first
			if i > 0 {
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

		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		if _, _, err := signal.Once(ctx); err != nil {
			t.Fatal(err)
		}
		saw.mu.Lock()
		requests := saw.requests
		saw.mu.Unlock()
		if requests != 1 {
			t.Errorf("one upload told to six people was sent %d times", requests)
		}

		// And the five that rode on the first one's delivery have left the
		// window, or they hold the front of it for ever.
		left, err := notify.StillToTell(signal, ctx, "chat")
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
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		who, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, asks(t, db, who), "chat",
			notify.Everything, server.URL, "a-shared-secret-long-enough"); err != nil {
			t.Fatal(err)
		}

		for _, upload := range []string{"scan-4", "scan-5"} {
			if err := store.Tell(ctx, notify.Telling{
				PersonID: who.ID, Kind: notify.InventoryMoved,
				Body: "sonic master broadcom moved a great deal in " + upload,
				Link: "/scans/" + upload + "/changes", Together: upload,
			}); err != nil {
				t.Fatal(err)
			}
		}

		signal := notify.NewSignal(db.DB, "https://openpsirt.example", quiet, "test")
		notify.TrustForTest(signal, server.Client())
		if _, _, err := signal.Once(ctx); err != nil {
			t.Fatal(err)
		}
		saw.mu.Lock()
		requests := saw.requests
		saw.mu.Unlock()
		if requests != 2 {
			t.Errorf("two uploads were sent %d times, want one each", requests)
		}
	})
}
