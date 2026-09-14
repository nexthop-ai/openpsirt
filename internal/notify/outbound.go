package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// signalTimeout bounds one request to one destination, and is what the sweep's
// lease is sized from.
const signalTimeout = 15 * time.Second

// One signed request out, one shape for every destination.
//
// **Nothing left this deployment but mail**, and every comparable tool reaches
// a chat channel and a tracker. Without one, a fix target is a wish and an
// approver discovers a claim by opening the queue. One signed HTTP request
// gives Slack, Teams, a tracker driven by automation and paging without an
// adapter for any of them — which is what the channel interface was for,
// reached more cheaply than by writing two of them.
//
// **It carries what the channel rules already allow.** The body is composed by
// the same code that composes a mail, so a notification about a
// finding nobody has announced carries the fact that there is something and a
// link, and nothing else — not the issue, not the component, not the build.
// A rule enforced in two places is enforced in one and a half.

// Outbound is a destination this deployment sends to.
type Outbound struct {
	bun.BaseModel `bun:"table:outbound,alias:ob"`

	ID   int64  `bun:"id,pk,autoincrement"`
	Name string `bun:"name,notnull"`
	// Kind is which notifications go here, or "*" for all of them.
	Kind string `bun:"kind,notnull"`
	URL  string `bun:"url,notnull"`
	// Secret signs the request. Recoverable by necessity: it authenticates
	// us to somebody else rather than anybody to us, which is why it is
	// not hashed like every other credential here — and it is never
	// returned by any endpoint.
	Secret    string     `bun:"secret,notnull"`
	CreatedBy int64      `bun:"created_by,notnull"`
	CreatedAt time.Time  `bun:"created_at,notnull"`
	RetiredAt *time.Time `bun:"retired_at"`
}

// Everything is the kind that matches every notification.
const Everything = "*"

// Delivery is what has gone to one destination.
//
// Keyed on the thing said rather than on the notification, because a condition
// is opened once per person who should hear it and a channel wants it once:
// "the kernel team's queue has fourteen pieces of work sitting in it" is one
// thing to say, however many people are told.
type Delivery struct {
	bun.BaseModel `bun:"table:outbound_delivery,alias:od"`

	ID         int64      `bun:"id,pk,autoincrement"`
	OutboundID int64      `bun:"outbound_id,notnull"`
	About      string     `bun:"about,notnull"`
	Attempts   int        `bun:"attempts,notnull"`
	SentAt     *time.Time `bun:"sent_at"`
	Failed     string     `bun:"failed"`
	FirstSeen  time.Time  `bun:"first_seen,notnull"`
}

// SignalLease names the work of carrying messages to configured destinations.
const SignalLease = "notification.signal"

// Signal carries notifications to whatever a deployment configured.
//
// A separate sweep from the one that carries mail, because they answer
// different questions: mail goes to a person and this goes to a destination,
// and what is unsent is tracked per destination rather than per notification —
// one message may go to three of them and fail at one.
type Signal struct {
	db      *bun.DB
	client  *http.Client
	baseURL string
	logger  *slog.Logger
	leases  *queue.Leases
	replica string
	now     func() time.Time
}

// NewSignal returns the sweep over db.
func NewSignal(db *bun.DB, baseURL string, logger *slog.Logger, replica string) *Signal {
	return &Signal{
		db: db, client: outboundClient(), baseURL: baseURL, logger: logger,
		leases: queue.NewLeases(db), replica: replica,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Run sweeps until the context ends.
func (s *Signal) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = betweenPosts
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if sent, failed, err := s.Once(ctx); err != nil {
			s.logger.Error("carrying notifications to their destinations", "error", err)
		} else if sent > 0 || failed > 0 {
			s.logger.Info("notifications signalled", "sent", sent, "failed", failed)
		}
		timer.Reset(interval)
	}
}

// Once carries what has not gone yet.
//
// **Nothing is retried forever.** A destination that refuses five times has
// gone, and a sweep that keeps trying it is a sweep that eventually does
// nothing else. The row stays unsent and stays readable, which is the honest
// end state.
func (s *Signal) Once(ctx context.Context) (sent, failed int, err error) {
	// One replica carries, the rest skip — the same arrangement mail uses, and
	// for the same reason: without it every replica sends the same request and
	// a channel gets one message per replica.
	if s.leases != nil {
		mine, err := s.leases.Take(ctx, SignalLease, s.replica, heldFor(signalTimeout))
		if err != nil || !mine {
			return 0, 0, err
		}
	}

	var destinations []Outbound
	if err := s.db.NewSelect().Model(&destinations).
		Where("retired_at IS NULL").Scan(ctx); err != nil {
		return 0, 0, fmt.Errorf("read where things go: %w", err)
	}
	if len(destinations) == 0 {
		// A deployment that configured nothing is the ordinary case,
		// and the notification area is the channel that always exists.
		return 0, 0, nil
	}

	var rows []Notification
	if err := s.db.NewSelect().Model(&rows).
		// What is worth saying is what is still true or still unread. A
		// cleared condition is not news, and an event nobody has yet been told
		// about outside is.
		Where("nt.cleared_at IS NULL").
		OrderExpr("nt.created_at ASC, nt.id ASC").
		Limit(sweepBatch).
		Scan(ctx, &rows); err != nil {
		return 0, 0, fmt.Errorf("read what there is to say: %w", err)
	}

	for _, destination := range destinations {
		for _, row := range rows {
			if !matches(destination.Kind, string(row.Kind)) {
				continue
			}
			done, err := s.deliver(ctx, destination, row)
			switch {
			case err != nil:
				return sent, failed, err
			case done == delivered:
				sent++
			case done == refused:
				failed++
			}
		}
	}
	return sent, failed, nil
}

// what one attempt came to.
type outcome int

const (
	already outcome = iota
	delivered
	refused
)

// deliver sends one notification to one destination, once.
//
// The claim is staked before the request is made: a row inserted with no
// sent_at is what stops a second replica — or a second pass a minute later —
// sending the same thing twice while the first is still in flight.
func (s *Signal) deliver(ctx context.Context, to Outbound, row Notification) (outcome, error) {
	key := about(row)
	now := s.now().UTC().Truncate(time.Microsecond)

	claim := &Delivery{
		OutboundID: to.ID, About: key, Attempts: 1, FirstSeen: now,
	}
	if _, err := s.db.NewInsert().Model(claim).Exec(ctx); err != nil {
		// **The unique index, and nothing else.** Every other insert in this
		// tree asks which failure this was; here any error at all read as
		// "somebody has this one", so a lost connection or a lock timeout
		// answered "already claimed" and a sweep during a brief outage
		// reported nothing sent and nothing failed — which is what a quiet
		// queue looks like too.
		if !database.IsDuplicate(err) {
			return already, fmt.Errorf("claim a delivery: %w", err)
		}
		// Somebody has this one. Either it has gone, or it is being tried
		// again — and trying again is a decision this pass makes by updating
		// the row rather than by racing for it.
		var held Delivery
		if err := s.db.NewSelect().Model(&held).
			Where("outbound_id = ?", to.ID).Where("about = ?", key).
			Scan(ctx); err != nil {
			// The row the index just refused, and it cannot be read. That is
			// a fault rather than an answer: reported as one, not as a
			// delivery somebody else is handling.
			return already, fmt.Errorf("read who has this delivery: %w", err)
		}
		if held.SentAt != nil || held.Attempts >= tries {
			return already, nil
		}
		if _, err := s.db.NewUpdate().Model((*Delivery)(nil)).
			Set("attempts = attempts + 1").
			Where("id = ?", held.ID).Where("sent_at IS NULL").
			Exec(ctx); err != nil {
			return already, fmt.Errorf("take another attempt at a delivery: %w", err)
		}
		claim.ID = held.ID
	}

	message := Compose(row, s.baseURL)
	body, err := json.Marshal(struct {
		Kind    string `json:"kind"`
		Subject string `json:"subject"`
		Text    string `json:"text"`
		Link    string `json:"link,omitempty"`
		Private bool   `json:"undisclosed,omitempty"`
		At      string `json:"at"`
	}{
		// Compose decides what an address may say, and a private
		// notification gets the front door rather than the finding. Building
		// one here from the row instead would announce the identifier and the
		// component to every server the request crosses, which is the whole of
		// what the composed body was careful about.
		Kind: string(row.Kind), Subject: message.Subject, Text: message.Text,
		Link: message.Link, Private: row.Private,
		At: row.CreatedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return refused, nil
	}

	if err := s.send(ctx, to, body, now); err != nil {
		// Recorded rather than logged and forgotten: a destination that is
		// refusing is a thing an operator has to be able to see, and the last
		// reason is the only part of it that says anything.
		if _, err := s.db.NewUpdate().Model((*Delivery)(nil)).
			Set("failed = ?", trimTo(withoutTheAddress(err, to.URL), 400)).
			Where("id = ?", claim.ID).Exec(ctx); err != nil && s.logger != nil {
			s.logger.Error("could not record why a destination refused", "error", err)
		}
		return refused, nil
	}
	if _, err := s.db.NewUpdate().Model((*Delivery)(nil)).
		Set("sent_at = ?", s.now().UTC().Truncate(time.Microsecond)).
		Set("failed = ?", "").
		Where("id = ?", claim.ID).Exec(ctx); err != nil {
		return delivered, fmt.Errorf("record that it went: %w", err)
	}
	return delivered, nil
}

// send makes the request.
//
// **Signed over the timestamp and the body**, so a receiver can tell a request
// from us apart from one anybody could make, and cannot replay yesterday's.
// The signature covers the timestamp precisely so that the timestamp cannot be
// changed without breaking it.
func (s *Signal) send(ctx context.Context, to Outbound, body []byte, now time.Time) error {
	stamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(to.Secret))
	mac.Write([]byte(stamp))
	mac.Write([]byte("."))
	mac.Write(body)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, to.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build the request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "OpenPSIRT")
	request.Header.Set("X-OpenPSIRT-Timestamp", stamp)
	request.Header.Set("X-OpenPSIRT-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))

	answer, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer answer.Body.Close()
	if answer.StatusCode >= 300 {
		return fmt.Errorf("answered %d", answer.StatusCode)
	}
	return nil
}

// about is the key one thing said is tracked under.
//
// A condition's own identity where it has one, so that a condition opened for
// six people is sent once; the notification's identifier otherwise, because an
// event is a thing that happened to somebody and two of them are two things.
func about(row Notification) string {
	if row.About != "" {
		return row.About
	}
	return "notification-" + strconv.FormatInt(row.ID, 10)
}

// matches says whether a destination takes this kind.
func matches(configured, kind string) bool {
	return configured == Everything || strings.EqualFold(configured, kind)
}

// trimTo bounds what is stored of a failure.
func trimTo(text string, most int) string {
	if len(text) <= most {
		return text
	}
	return text[:most]
}

// outboundClient is how a request leaves here.
//
// **Redirects are refused rather than followed.** A destination is configured,
// and "somewhere else" is exactly what a redirect asks us to send a signed
// request to — a receiver that genuinely moved should be reconfigured, which
// is visible, rather than followed, which is not.
//
// **Https only.** The body is signed and not encrypted, and what it carries is
// what somebody is being told about a vulnerability. A deployment that wants
// to send that in clear text is not a case worth supporting.
//
// **A private address is allowed here**, unlike a sign-in provider's. The
// difference is where the address came from: a provider's endpoints arrive in
// a discovery document from outside, and this one was typed by the operator —
// whose chat server is quite reasonably on their own network.
func outboundClient() *http.Client {
	// No address guard, deliberately, and stated by its absence rather than
	// by a hook that returns nil. A hook in exactly the position a reviewer
	// looks for one reads as a control that is present, and the paragraph
	// above is what says the permission is intended.
	dialer := &net.Dialer{Timeout: signalTimeout}
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("refused a redirect to %s: a destination is configured, not followed",
				req.URL.Host)
		},
		Transport: &outboundGuard{inner: &http.Transport{DialContext: dialer.DialContext}},
	}
}

// outboundGuard refuses anything but https.
type outboundGuard struct{ inner http.RoundTripper }

func (g *outboundGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("refused a request to %s: a destination is reached over https",
			req.URL.Scheme+"://"+req.URL.Host)
	}
	return g.inner.RoundTrip(req)
}

// Configured is one destination and whether it is working.
type Configured struct {
	Outbound
	// Sent is how many things have gone there, and Failing how many are being
	// retried or have been given up on. An operator's question about a
	// destination is whether it works, and nothing else answers it.
	Sent, Failing int
	Because       string
}

// Destinations lists what is configured, with how each is doing.
func (s *Store) Destinations(ctx context.Context) ([]Configured, error) {
	var rows []Outbound
	if err := s.db.NewSelect().Model(&rows).
		Where("retired_at IS NULL").Order("name", "kind").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read where things go: %w", err)
	}
	out := make([]Configured, 0, len(rows))
	for _, row := range rows {
		one := Configured{Outbound: row}
		var counts []struct {
			Sent    int    `bun:"sent"`
			Failing int    `bun:"failing"`
			Because string `bun:"because"`
		}
		if err := s.db.NewSelect().Model((*Delivery)(nil)).
			ColumnExpr(`SUM(CASE WHEN od.sent_at IS NOT NULL THEN 1 ELSE 0 END) AS "sent"`).
			ColumnExpr(`SUM(CASE WHEN od.sent_at IS NULL THEN 1 ELSE 0 END) AS "failing"`).
			ColumnExpr(`MAX(COALESCE(od.failed, '')) AS "because"`).
			Where("od.outbound_id = ?", row.ID).
			Scan(ctx, &counts); err != nil {
			return nil, fmt.Errorf("read how it is doing: %w", err)
		}
		if len(counts) > 0 {
			one.Sent, one.Failing, one.Because = counts[0].Sent, counts[0].Failing, counts[0].Because
		}
		out = append(out, one)
	}
	return out, nil
}

// AddDestination records where a kind of notification goes.
//
// A name and kind that was retired is taken up again rather than refused. The
// row stays when a destination is retired, because what went there is kept,
// and the name is unique across retired rows too — so inserting a second under
// the same pair fails on a row nothing lists, with a message about a
// destination nobody can see.
func (s *Store) AddDestination(ctx context.Context, name, kind, url, secret string,
	by int64) (*Outbound, error) {

	row := &Outbound{
		Name: strings.TrimSpace(name), Kind: strings.TrimSpace(kind),
		URL: strings.TrimSpace(url), Secret: secret,
		CreatedBy: by, CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if row.Name == "" || row.Kind == "" || row.URL == "" {
		return nil, fmt.Errorf("a destination needs a name, a kind and an address")
	}
	res, err := s.db.NewUpdate().Model((*Outbound)(nil)).
		Set("retired_at = ?", nil).
		Set("url = ?", row.URL).
		Set("secret = ?", row.Secret).
		Set("created_by = ?", row.CreatedBy).
		Set("created_at = ?", row.CreatedAt).
		Where("name = ?", row.Name).
		Where("kind = ?", row.Kind).
		Where("retired_at IS NOT NULL").
		Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("take that destination up again: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return nil, fmt.Errorf("take that destination up again: %w", err)
	}
	if n > 0 {
		if err := s.db.NewSelect().Model(row).
			Where("name = ?", row.Name).Where("kind = ?", row.Kind).
			Limit(1).Scan(ctx); err != nil {
			return nil, fmt.Errorf("read that destination back: %w", err)
		}
		return row, nil
	}
	if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record that destination: %w", err)
	}
	return row, nil
}

// RetireDestination takes one out of use, keeping what went there.
func (s *Store) RetireDestination(ctx context.Context, name, kind string) error {
	if _, err := s.db.NewUpdate().Model((*Outbound)(nil)).
		Set("retired_at = ?", time.Now().UTC().Truncate(time.Microsecond)).
		Where("name = ?", strings.TrimSpace(name)).
		Where("kind = ?", strings.TrimSpace(kind)).
		Where("retired_at IS NULL").Exec(ctx); err != nil {
		return fmt.Errorf("retire that destination: %w", err)
	}
	return nil
}

// TrustForTest points the sweep at a client that trusts a test server's
// certificate.
//
// Exported for tests only, and doing nothing else: the guard that refuses
// anything but https and refuses a redirect is what is being tested around,
// not switched off — a test server speaks https with a certificate nothing
// else trusts, and the alternative is testing the delivery over plain http,
// which is the one thing this refuses to do.
func TrustForTest(s *Signal, client *http.Client) {
	client.CheckRedirect = s.client.CheckRedirect
	client.Transport = &outboundGuard{inner: client.Transport}
	s.client = client
}

// withoutTheAddress is why a delivery failed, with the destination taken out.
//
// The standard library wraps a failed request in an error whose text embeds
// the whole URL, redacting only a password in the userinfo — so the path
// survives, and for Slack and for Teams the path is the credential. That text
// is stored on the delivery and answered back by the endpoint that lists
// destinations, so the first failure re-published the secret the address field
// is careful not to return.
//
// The host is left in place. An operator reading "why is this failing" needs to
// know which destination it is about, and the host is the part that says so
// without being the part that authenticates.
func withoutTheAddress(err error, address string) string {
	said := err.Error()
	if address == "" {
		return said
	}
	// The host is put back in place of the whole address. An operator reading
	// "why is this failing" needs to know which destination it is about, and
	// the host is the part that says so without being the part that
	// authenticates.
	host := "the destination"
	if parsed, bad := url.Parse(address); bad == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
		if path := parsed.RequestURI(); path != "" && path != "/" {
			said = strings.ReplaceAll(said, path, "")
		}
	}
	return strings.ReplaceAll(said, address, host)
}
