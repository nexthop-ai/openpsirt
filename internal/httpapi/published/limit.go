// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package published

import (
	"net"
	"sort"
	"sync"
	"time"
)

// mostClients is how many clients the limiter remembers at once.
//
// A client is remembered while it has spent part of its allowance, and one that
// has waited long enough to have all of it back is forgotten as room is
// needed. Past this many, the half holding the most of their allowance are
// forgotten too: a flood of addresses each asking once holds nearly all of
// theirs, and a client being held back holds little and is kept.
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
func (l *limiter) allow(address string) (time.Duration, bool) {
	client := clientKey(address)
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

// forget drops every client whose allowance is whole again, and where that
// leaves the table full, the half holding the most of theirs.
func (l *limiter) forget(now time.Time) {
	type holding struct {
		client string
		left   float64
	}
	held := make([]holding, 0, len(l.clients))
	for client, one := range l.clients {
		left := one.left + now.Sub(one.at).Seconds()*l.perSec
		if left >= l.burst {
			delete(l.clients, client)
			continue
		}
		held = append(held, holding{client, left})
	}
	if len(l.clients) < mostClients {
		return
	}
	sort.Slice(held, func(i, j int) bool { return held[i].left > held[j].left })
	for _, one := range held[:len(held)/2] {
		delete(l.clients, one.client)
	}
}

// clientKey is what a client's allowance is kept under: its address, and for
// IPv6 the /64 it sits in. One host is handed a /64 and may rotate through it,
// so counted per address it would hold a fresh allowance for every address.
func clientKey(address string) string {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() != nil {
		return address
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
