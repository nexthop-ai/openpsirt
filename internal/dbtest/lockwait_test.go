// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

func TestAHarnessURLBoundsItsLockWaitUnlessItSetsOne(t *testing.T) {
	for _, c := range []struct {
		what, raw, want string
	}{
		{
			"a URL with no query",
			"mysql://u:p@127.0.0.1:3306/db",
			"mysql://u:p@127.0.0.1:3306/db?lock_wait_timeout=60",
		},
		{
			"a URL whose query is kept as written",
			"mariadb://u:p@127.0.0.1:3307/db?tls=false&x=a%2Cb",
			"mariadb://u:p@127.0.0.1:3307/db?tls=false&x=a%2Cb&lock_wait_timeout=60",
		},
		{
			"a URL whose escaped password is kept as written",
			"mysql://u:p%21x@127.0.0.1:3306/db",
			"mysql://u:p%21x@127.0.0.1:3306/db?lock_wait_timeout=60",
		},
		{
			"a URL that sets its own",
			"mysql://u:p@127.0.0.1:3306/db?lock_wait_timeout=5",
			"mysql://u:p@127.0.0.1:3306/db?lock_wait_timeout=5",
		},
	} {
		if got := boundLockWait(c.raw); got != c.want {
			t.Errorf("%s: %q, want %q", c.what, got, c.want)
		}
	}
}

func TestAServerSessionWaitsForAMetadataLockABoundedTime(t *testing.T) {
	// A server wedged on a lock it never grants hangs every statement needing
	// it; bounded, the statement fails and is named. The two engines with
	// the setting carry it on every connection the harness opens.
	Each(t, func(t *testing.T, db *database.DB) {
		if db.Server.Engine != database.MySQL && db.Server.Engine != database.MariaDB {
			t.Skip("lock_wait_timeout is a MySQL and MariaDB session variable")
		}
		var seconds int
		if err := db.QueryRowContext(t.Context(), "SELECT @@SESSION.lock_wait_timeout").Scan(&seconds); err != nil {
			t.Fatal(err)
		}
		// A URL setting its own bound keeps it.
		want := int(lockWait.Seconds())
		env := MySQLURLEnv
		if db.Server.Engine == database.MariaDB {
			env = MariaDBURLEnv
		}
		if u, err := url.Parse(os.Getenv(env)); err == nil && u.Query().Has("lock_wait_timeout") {
			if want, err = strconv.Atoi(u.Query().Get("lock_wait_timeout")); err != nil {
				t.Fatalf("%s sets lock_wait_timeout to %q", env, u.Query().Get("lock_wait_timeout"))
			}
		}
		if seconds != want {
			t.Errorf("a harness session waits %d seconds for a metadata lock, want %d", seconds, want)
		}
	})
}
