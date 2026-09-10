package notify_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/schema"
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
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		who, err := rights.Ensure(ctx, "ana@example.com", "Ana", true)
		if err != nil {
			t.Fatal(err)
		}

		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		const secret = "a-shared-secret-long-enough"
		if _, err := store.AddDestination(ctx, "chat", notify.Everything,
			server.URL, secret, who.ID); err != nil {
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

func TestADestinationTakesOnlyItsOwnKind(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", true)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewTLSServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		// Paging takes what is worth interrupting somebody for, and nothing
		// else — which is the whole reason a destination names a kind.
		if _, err := store.AddDestination(ctx, "paging", string(notify.CriticalOnRelease),
			server.URL, "a-shared-secret-long-enough", who.ID); err != nil {
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
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana", true)
		if err != nil {
			t.Fatal(err)
		}
		saw := &took{}
		server := httptest.NewServer(http.HandlerFunc(saw.handle))
		defer server.Close()

		store := notify.NewStore(db.DB)
		if _, err := store.AddDestination(ctx, "plain", notify.Everything,
			server.URL, "a-shared-secret-long-enough", who.ID); err != nil {
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
