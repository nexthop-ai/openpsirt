package database

import (
	"context"
	"time"
)

// Pool settings.
//
// The failure these exist to prevent is a connection whose far end has gone
// without a FIN or an RST — a firewall dropping an idle flow, a load balancer
// timing out, a database failing over. Our side still believes the socket is
// fine. The pool hands it out, the query writes into nothing, and the read
// blocks until TCP retransmission gives up, which on common defaults is about
// fifteen minutes. Nothing is logged and the goroutine is simply stuck.
//
// Go's pool cannot help here on its own. It never validates a connection
// before handing it out. The two driver hooks it does call — one before
// pooling a connection, one before reusing it — only inspect local state in
// the drivers we use, so neither notices a half-open socket.
//
// So the defense is to make sure a connection is never idle long enough to be
// killed behind our back, rather than to detect it afterwards.
type Pool struct {
	// MaxOpen caps concurrent connections. Unbounded, a burst opens more than
	// the server permits — and PostgreSQL is expensive per connection.
	MaxOpen int
	// MaxIdle is how many stay pooled. Go's own default is 2, which is low
	// enough that moderate load churns connections open and closed
	// continuously; matching MaxOpen avoids that.
	MaxIdle int
	// IdleTimeout closes a connection that has sat unused.
	//
	// Note the floor: Go runs its cleaner on a timer that never ticks faster
	// than once a second, however short this is set. A value below a second
	// therefore reaps no faster than one second — a setting that looks
	// aggressive and is not.
	//
	// This is the setting that matters. It must be shorter than the shortest
	// idle timeout anywhere in the path — firewall, load balancer, or the
	// server's own — so that a connection is closed by us before it is killed
	// behind our back. A minute sits under the common ones by a wide margin.
	IdleTimeout time.Duration
	// Lifetime recycles a connection regardless of use. It bounds how long a
	// connection can be pinned to one server, which is what lets connections
	// redistribute after a failover instead of all holding on to the machine
	// that is no longer primary.
	Lifetime time.Duration
}

// DefaultPool is tuned for the common deployment: a database reached over a
// network with something stateful in between.
func DefaultPool() Pool {
	return Pool{
		MaxOpen:     25,
		MaxIdle:     25,
		IdleTimeout: time.Minute,
		Lifetime:    30 * time.Minute,
	}
}

// apply sets the pool on an open database.
func (p Pool) apply(db *DB) {
	if db.Server.Engine == SQLite {
		// SQLite has one writer. More connections add contention rather than
		// concurrency: transactions on different connections collide instead
		// of queueing. Nothing else here applies to a local file.
		db.SetMaxOpenConns(1)
		return
	}
	db.SetMaxOpenConns(p.MaxOpen)
	db.SetMaxIdleConns(p.MaxIdle)
	db.SetConnMaxIdleTime(p.IdleTimeout)
	db.SetConnMaxLifetime(p.Lifetime)
}

// validateTimeout bounds a liveness check. Deliberately short: this asks
// whether the connection answers at all, not whether the server is quick.
const validateTimeout = 3 * time.Second

// Validate checks that the database answers, and answers promptly.
//
// It is not automatic. Go offers no hook to validate a connection as it leaves
// the pool, so checking means an extra round trip on every use — worth it
// where a caller would otherwise block for a long time on a dead connection,
// wrong as a blanket default.
//
// Note what this does and does not tell you. It says a connection was alive a
// moment ago. It cannot promise the one you are handed next is the one that
// was checked, nor that it stays alive for the query after this.
func (db *DB) Validate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()
	return db.PingContext(ctx)
}
