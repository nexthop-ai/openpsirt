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
	// Nothing left this deployment but mail, so a fix target was a wish
	// and an approver discovered a claim by opening the queue. One signed
	// request gives a chat channel, a tracker and paging without an
	// adapter for any of them.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		who, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
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

// A webhook body is composed by the same code that composes a mail, so the
// no-detail rule reaches it — including the address, which travels in a field
// of its own where a receiver reads it without opening the text.
//
// The address was the half that did not hold: the body was composed with the
// rule applied and the link was then rebuilt from the row beside it, so a
// deployment with one destination configured announced the identifier, the
// product, the stream, the variant and the component to every server the
// request crossed.
func TestNothingUndisclosedTravelsInAWebhookAddress(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		who, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
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

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
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
	})
}

func TestNothingLeavesOverPlainHTTP(t *testing.T) {
	// The body is signed and not encrypted, and what it carries is what
	// somebody is being told about a vulnerability.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
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
	// The window was the oldest two hundred uncleared notifications, and an
	// event row is never cleared — only a condition is. So once two hundred
	// events existed the same two hundred were re-read on every cycle and
	// nothing created afterwards was ever signalled, with no error, no log
	// and no counter. A deployment reaches that in the first two hundred
	// events of its life.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
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
	// These three carried no subject at all, in a package that enforces its
	// own authorization for this table in the same file with the reasoning
	// written out. What kept the signing secret off the wire was one handler
	// copying the fields it wanted by name — a second caller that marshalled
	// what came back would have published a shared secret, and nothing would
	// have said so.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
		if err != nil {
			t.Fatal(err)
		}
		other, err := rights.Ensure(ctx, "bo@example.com", "Bo", nil)
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
	// The kind decided the loop rather than the window: the oldest two
	// hundred were selected whatever kind they were, and a row this
	// destination does not take never gets a delivery row — so it stayed in
	// the window for ever. A paging destination behind two hundred ordinary
	// events was wedged exactly as a destination taking everything was, and
	// the backlog test above never reached it because its destination takes
	// every kind.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
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
	// number, five of those six could never be settled: the duplicate arm
	// returns without writing anything for them, so they answered the
	// predicate for ever and, being the oldest, sat at the front of the
	// window. A few dozen people across the condition kinds is enough to stop
	// the sweep advancing again.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		first, err := rights.Ensure(ctx, "ana@example.com", "Ana", access.Stated(true))
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
					fmt.Sprintf("them-%d@example.com", i), "Them", access.Stated(true))
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
