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
// Refusing rather than returning a lock that locks nothing. Nothing here can
// exclude a second process on this platform, and there is no way to find out
// whether one exists — so migrating a SQLite database is refused outright
// rather than proceeding under a comment claiming an exclusion nobody holds.
func lockFile(context.Context, string, time.Duration) (unlock, error) {
	return nil, fmt.Errorf(
		"this platform has no advisory file locking, so a SQLite database cannot be " +
			"migrated safely here: use one of the server engines")
}
