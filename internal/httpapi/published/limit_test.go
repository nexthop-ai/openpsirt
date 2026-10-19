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
