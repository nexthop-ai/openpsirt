package patchbranch

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/uptrace/bun"
)

// NewLocalPass is a pass that fetches from directories rather than hosts, with
// no lease, so a test drives it directly.
func NewLocalPass(db bun.IDB, dir string, quota int64, excluded Excluded, locate func(string) string) *Pass {
	return &Pass{
		db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		git:      git{excluded: excluded, transport: "file", locate: locate},
		copies:   copies{root: dir, quota: quota, now: time.Now, poll: 10 * time.Millisecond},
		excluded: excluded,
		Now:      time.Now,
	}
}

// Held reports whether the pass keeps a copy of a repository.
func (p *Pass) Held(repository string) bool { return p.copies.has(repository) }

// OpenGuard starts the proxy git reaches out through, for one host, and
// answers its address and how to stop it.
func OpenGuard(host string, excluded Excluded) (string, func(), error) {
	door, err := openGuard(host, excluded)
	if err != nil {
		return "", nil, err
	}
	return door.address(), door.close, nil
}

// VersionLess is the order branch names are listed in.
var VersionLess = versionLess

// NewRemotePass is a pass that fetches over https through the guard, with no
// database, for a test about what reaching out does.
func NewRemotePass(dir string, excluded Excluded) *Pass {
	return &Pass{
		git:      git{excluded: excluded, transport: "https"},
		copies:   copies{root: dir, quota: DefaultQuota, now: time.Now, poll: time.Second},
		excluded: excluded,
		Now:      time.Now,
	}
}

// Fetch brings a repository's copy up to date, making it where there is none.
func (p *Pass) Fetch(ctx context.Context, repository string) error {
	_, err := p.copies.ensure(ctx, p.git, repository)
	return err
}

// NewLeasedPass is a pass holding leases as replica, at the interval the
// server passes, which is none.
func NewLeasedPass(db *bun.DB, replica string) *Pass {
	return NewPass(db, slog.New(slog.NewTextHandler(io.Discard, nil)), replica, Options{Dir: "unused"})
}

// StillMine is the check a visit makes as it goes.
func (p *Pass) StillMine(ctx context.Context) error { return p.stillMine(ctx) }

// Unpolled stops the pass measuring a copy while it arrives, so what is
// removed is decided after each visit alone.
func (p *Pass) Unpolled() *Pass {
	p.copies.poll = time.Hour
	return p
}
