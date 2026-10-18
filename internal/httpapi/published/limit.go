// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package published

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// mostClients is how many clients the limiter remembers at once.
//
// A client is remembered while it has spent part of its allowance, and one that
// has waited long enough to have all of it back is forgotten as room is
// needed. A flood of addresses each asking once fills the table with clients
// holding nearly all of theirs, so past this many the table starts again
// rather than growing.
const mostClients = 10000

// limiter bounds how fast one client may ask, as a bucket per client that
// fills at the rate allowed and holds a minute's worth.
//
// Per replica. The bound is on the work one client can make one process do,
// and a deployment of three replicas behind one address allows a client up to
// three times this, which is still a bound.
type limiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	clients map[string]*bucket
	now     func() time.Time
}

// bucket is one client's allowance: what was left when it last asked, and
// when that was.
type bucket struct {
	left float64
	at   time.Time
}

// newLimiter allows perMinute requests a minute to each client.
func newLimiter(perMinute int, now func() time.Time) *limiter {
	return &limiter{
		perSec: float64(perMinute) / 60, burst: float64(perMinute),
		clients: map[string]*bucket{}, now: now,
	}
}

// allow takes one request from a client's allowance, or answers how long until
// one is there.
func (l *limiter) allow(client string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	held, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= mostClients {
			l.forget(now)
		}
		held = &bucket{left: l.burst, at: now}
		l.clients[client] = held
	}
	held.left += now.Sub(held.at).Seconds() * l.perSec
	if held.left > l.burst {
		held.left = l.burst
	}
	held.at = now
	if held.left < 1 {
		return time.Duration((1 - held.left) / l.perSec * float64(time.Second)), false
	}
	held.left--
	return 0, true
}

// forget drops every client whose allowance is whole again, and starts again
// where that leaves the table full.
func (l *limiter) forget(now time.Time) {
	for client, held := range l.clients {
		if held.left+now.Sub(held.at).Seconds()*l.perSec >= l.burst {
			delete(l.clients, client)
		}
	}
	if len(l.clients) >= mostClients {
		l.clients = map[string]*bucket{}
	}
}

// clientOf is who is asking, by the address the connection came from.
//
// The connection's own address, and never a header naming another. A header
// is whatever the client wrote, so trusting one lets any client be every
// client. Behind a proxy every reader arriving through it shares one
// allowance.
func clientOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
