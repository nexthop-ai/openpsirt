//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package migrate

import (
	"context"
	"fmt"
	"time"
)

// lockFile has no implementation on this platform.
//
// The advisory locking the other file uses is not available everywhere, and
// there is no portable stand-in worth having: a lock file written and removed
// by hand goes stale on a crash, and every start afterwards refuses for a
// reason that stopped being true.
//
// Refusing rather than returning a lock that locks nothing. SQLite is for
// development and a single-pod trial, so a platform without this can run one
// process against a file — and the way to say that is to fail when a second
// one arrives, not to let both through while a comment claims they are
// excluded.
func lockFile(context.Context, string, time.Duration) (unlock, error) {
	return nil, fmt.Errorf(
		"migrating a SQLite database is not excluded between processes on this platform: " +
			"use one of the server engines, or run one process at a time")
}
