// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package published

import (
	"fmt"
	"testing"
	"time"
)

// An IPv6 client is counted by the /64 it sits in, so rotating through the
// addresses one host is handed buys no fresh allowance.
func TestAnIPv6ClientIsCountedByItsSlash64(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newLimiter(2, func() time.Time { return at })
	for i := range 2 {
		if _, ok := l.allow(fmt.Sprintf("2001:db8::%x", i+1)); !ok {
			t.Fatalf("address %d inside the allowance was refused", i+1)
		}
	}
	if _, ok := l.allow("2001:db8::ffff"); ok {
		t.Error("a third address in the same /64 was given a fresh allowance")
	}
	if _, ok := l.allow("2001:db8:0:1::1"); !ok {
		t.Error("an address in another /64 was refused")
	}
}

// A full table forgets the clients holding the most of their allowance, and
// keeps a client that is being held back.
func TestAFullTableKeepsTheClientsHeldBack(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newLimiter(60, func() time.Time { return at })
	for range 60 {
		l.allow("198.51.100.7")
	}
	if _, ok := l.allow("198.51.100.7"); ok {
		t.Fatal("the client past its allowance was answered")
	}
	for i := range mostClients {
		l.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if _, ok := l.allow("198.51.100.7"); ok {
		t.Error("a flood of other addresses gave the held-back client its allowance back")
	}
}

// A full table forgets first every client whose allowance is whole again, and
// where that makes room, nobody else: two clients being held back by
// different amounts are both kept, and so is what each has left.
func TestAFullTableForgetsTheClientsWhoseAllowanceIsWhole(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newLimiter(60, func() time.Time { return at })
	const spent, halfSpent = "198.51.100.7", "198.51.100.8"
	for range 60 {
		l.allow(spent)
	}
	for range 30 {
		l.allow(halfSpent)
	}
	for i := range mostClients - 2 {
		l.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	// A second later every client that asked once has its allowance whole
	// again, and the two held back have one more request each.
	at = at.Add(time.Second)
	if _, ok := l.allow("203.0.113.1"); !ok {
		t.Fatal("a new client was refused")
	}
	if len(l.clients) != 3 {
		t.Errorf("the table holds %d clients, want the two held back and the new one", len(l.clients))
	}
	for client, left := range map[string]int{spent: 1, halfSpent: 31} {
		for i := range left {
			if _, ok := l.allow(client); !ok {
				t.Fatalf("%s was refused request %d of the %d it has left", client, i+1, left)
			}
		}
		if _, ok := l.allow(client); ok {
			t.Errorf("%s was answered past the %d it had left, so it was forgotten", client, left)
		}
	}
}
