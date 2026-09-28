// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package refusal

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

// A refusal is found however deeply a caller wraps it, and a sentinel declared
// as one is still matched by identity through a sentence that wraps it.
func TestARefusalIsFoundThroughWrappingAndKeepsItsSentinel(t *testing.T) {
	sentinel := New("nothing named here is open")
	said := Errorf("%w against that component", sentinel)
	wrapped := fmt.Errorf("record the claim: %w", said)

	if !In(wrapped) {
		t.Error("a refusal wrapped in context is not found")
	}
	if !errors.Is(wrapped, sentinel) {
		t.Error("a sentinel inside a refusal is not matched")
	}
	if wrapped.Error() != "record the claim: nothing named here is open against that component" {
		t.Errorf("the sentence reads %q", wrapped.Error())
	}
}

// A type of its own that says it is a sentence for the caller is found as a
// refusal is, through wrapping.
func TestASentenceTypeIsFoundAsARefusal(t *testing.T) {
	if !In(fmt.Errorf("record the link: %w", said{"ms-msdt: is not a link"})) {
		t.Error("a sentence type wrapped in context is not found")
	}
}

type said struct{ text string }

func (s said) Error() string { return s.text }
func (s said) Refused()      {}

// A fault is never a refusal, whatever it says and however it is wrapped, so
// its text is not published.
func TestAFaultIsNotARefusal(t *testing.T) {
	fault := fmt.Errorf("read the claim: %w",
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")})
	if In(fault) {
		t.Error("a connection failure reads as a refusal")
	}
	if In(nil) {
		t.Error("no error reads as a refusal")
	}
}
