package access

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Session is somebody's signed-in state.
//
// It holds no roles. What a session establishes is who is asking; what they
// may reach is read at the moment they ask, so a role withdrawn — by an admin,
// or by a group membership that went away — takes effect on the next request
// rather than at the next sign-in.
type Session struct {
	bun.BaseModel `bun:"table:session,alias:se"`

	ID         int64      `bun:"id,pk,autoincrement"`
	TokenHash  string     `bun:"token_hash,notnull"`
	CSRFToken  string     `bun:"csrf_token,notnull"`
	PersonID   int64      `bun:"person_id,notnull"`
	CreatedAt  time.Time  `bun:"created_at,notnull"`
	ExpiresAt  time.Time  `bun:"expires_at,notnull"`
	LastUsedAt *time.Time `bun:"last_used_at"`
}

// Issued is a session and the two secrets handed to the browser with it. The
// stored row keeps only a digest of the first, so this is the one moment
// either can be read.
type Issued struct {
	Session *Session
	// Token goes in the session cookie, which the browser sends by itself.
	Token string
	// CSRF is read by our own page and echoed in a header, which a hostile
	// page cannot do.
	CSRF string
}

// DefaultSessionLifetime bounds how long a sign-in lasts when an administrator
// has not said otherwise.
//
// It has to have an end. Group membership is read at sign-in and never again ,
// so the lifetime is exactly the window in which somebody moved out of a team
// still holds what the team gave them. Twelve hours puts that inside a working
// day without asking somebody to sign in over lunch.
const DefaultSessionLifetime = 12 * time.Hour

// MaxSessionLifetime is the ceiling on a sign-in.
//
// Group membership is read at sign-in and never again, so a session's lifetime
// *is* the window in which somebody removed from a privileged provider group
// still holds what that group gave them. Unbounded, that window was whatever an
// administrator typed: a lifetime of 8760h made every browser sign-in last a
// year, and the setting took it without comment.
//
// Thirty days is long enough for the case the default argues for and short
// enough that a group membership cannot outlive a month. A personal token, the
// other thing somebody holds for a long time, has had two ceilings all along.
const MaxSessionLifetime = 30 * 24 * time.Hour

// StartSession signs somebody in for a bounded time.
//
// Nothing here decides whether they should be here. That is settled before
// this is called, which is what keeps no account created automatically true on
// every sign-in path: this records a session for somebody already known, and
// cannot bring an account into being.
func (s *Store) StartSession(ctx context.Context, personID int64, lifetime time.Duration) (*Issued, error) {
	if lifetime <= 0 {
		lifetime = DefaultSessionLifetime
	}
	// Refused rather than quietly clamped, so an administrator who asked for a
	// year is told the limit instead of discovering it at the next sign-in.
	if lifetime > MaxSessionLifetime {
		return nil, fmt.Errorf("a sign-in may last at most %s, and this asks for %s",
			MaxSessionLifetime, lifetime)
	}
	token, err := secret()
	if err != nil {
		return nil, err
	}
	csrf, err := secret()
	if err != nil {
		return nil, err
	}

	now := s.now().Truncate(time.Microsecond)
	session := &Session{
		TokenHash: hashSecret(token), CSRFToken: csrf, PersonID: personID,
		CreatedAt: now, ExpiresAt: now.Add(lifetime).Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(session).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a session: %w", err)
	}
	return &Issued{Session: session, Token: token, CSRF: csrf}, nil
}

// ResolveSession turns a session token into the subject it stands for.
//
// An expired session is refused and not deleted here. Reading is not the place
// to write, and a request arriving on an expired session is the ordinary case
// rather than something to clean up in the middle of answering it.
func (s *Store) ResolveSession(ctx context.Context, token string) (Subject, *Session, error) {
	if token == "" {
		return Subject{}, nil, ErrDenied
	}
	session := new(Session)
	if err := s.db.NewSelect().Model(session).
		Where("token_hash = ?", hashSecret(token)).Scan(ctx); err != nil {
		return Subject{}, nil, ErrDenied
	}
	if !s.now().Before(session.ExpiresAt) {
		return Subject{}, nil, ErrDenied
	}

	person := new(Account)
	if err := s.db.NewSelect().Model(person).Where("id = ?", session.PersonID).Scan(ctx); err != nil {
		return Subject{}, nil, ErrDenied
	}

	// Resolved by identity, the same path every other sign-in takes, so that
	// what a session reaches is read now rather than remembered from when it
	// was issued.
	subject, err := s.Resolve(ctx, person.Identity)
	if err != nil {
		return Subject{}, nil, err
	}

	// Coarse, for the same reason a person's own row is: every request on this
	// session comes through here, and writing each time makes the row a
	// contention point that a cluster then has to certify on every parallel
	// request from one browser.
	if used := s.now().Truncate(time.Microsecond); staleEnough(session.LastUsedAt, used) {
		if _, err := s.db.NewUpdate().Model((*Session)(nil)).
			Set("last_used_at = ?", used).Where("id = ?", session.ID).Exec(ctx); err != nil {
			return Subject{}, nil, fmt.Errorf("record that a session was used: %w", err)
		}
		session.LastUsedAt = &used
	}
	return subject, session, nil
}

// MatchesCSRF reports whether the value a request echoed belongs to this
// session, compared in constant time.
func (session *Session) MatchesCSRF(presented string) bool {
	// A session holding no value matches nothing. Two empty strings compare
	// equal, so without this a session that somehow carries none would accept
	// a request that echoed nothing — which is every request a hostile page
	// makes.
	if session.CSRFToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(presented)) == 1
}

// EndSession signs one session out.
func (s *Store) EndSession(ctx context.Context, id int64) error {
	if _, err := s.db.NewDelete().Model((*Session)(nil)).Where("id = ?", id).Exec(ctx); err != nil {
		return fmt.Errorf("end a session: %w", err)
	}
	return nil
}

// EndSessionsFor signs somebody out everywhere, which is what cutting access
// off at once means for a person rather than for a browser.
func (s *Store) EndSessionsFor(ctx context.Context, personID int64) error {
	if _, err := s.db.NewDelete().Model((*Session)(nil)).
		Where("person_id = ?", personID).Exec(ctx); err != nil {
		return fmt.Errorf("end the sessions of a person: %w", err)
	}
	return nil
}

// PurgeExpiredSessions clears what has run out, and reports how much it
// cleared. Sessions are the one table here that grows with use rather than
// with what is being tracked.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	result, err := s.db.NewDelete().Model((*Session)(nil)).
		Where("expires_at <= ?", s.now()).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("clear expired sessions: %w", err)
	}
	cleared, err := database.Affected(result)
	if err != nil {
		// The delete committed; what cannot be read is how much it took. That
		// is worth reporting rather than answering "nothing expired", which is
		// a number nobody counted and reads as a quiet sweep.
		return 0, fmt.Errorf("clear expired sessions: %w", err)
	}
	return cleared, nil
}

// secret generates one of the values a session is held by.
func secret() (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate a session: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
