// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// A 404 built from an error's own text asserts that a name reaches nothing and
// publishes whatever the error carried — for a store read, the driver's
// message, which names the host and the port. This gate finds them, and had no
// test: its only consumer is an exit code, and an exit code cannot tell a check
// that found nothing from one that looked at nothing.

func TestWhatCountsAsA404BuiltFromAnError(t *testing.T) {
	for _, c := range []struct {
		what string
		line string
		want bool
	}{
		{
			"the shape itself",
			`		return nil, huma.Error404NotFound(err.Error())`, true,
		},
		{
			"the same under another name",
			`	return huma.Error404NotFound(cause.Error())`, true,
		},
		{
			"and another",
			`	return huma.Error404NotFound(failure.Error())`, true,
		},
		{
			"with a sentence in front of it, which publishes the text just the same",
			`	return huma.Error404NotFound("cannot read that: " + err.Error())`, true,
		},

		{
			"a sentence the code chose",
			`	return huma.Error404NotFound("no product is declared by that name")`, false,
		},
		{
			// The refusal names what was asked for rather than what went
			// wrong, which is the shape this gate exists to leave alone.
			"a sentence naming what the caller asked for",
			`	return huma.Error404NotFound(fmt.Sprintf("no product called %q", name))`, false,
		},
		{
			"another status carrying an error, which is a different question",
			`	return huma.Error422UnprocessableEntity(err.Error())`, false,
		},
		{
			"a 404 with nothing in it",
			`	return huma.Error404NotFound("")`, false,
		},
		{
			"ordinary code",
			`	if err != nil { return err }`, false,
		},
	} {
		if got := built.MatchString(c.line); got != c.want {
			t.Errorf("%s: reported=%v, want %v: %s", c.what, got, c.want, c.line)
		}
	}
}

func TestTheOnePlaceA404MayPublishAnErrorsTextSaysWhy(t *testing.T) {
	// An exemption is where a gate stops looking, so it is named rather than
	// inferred — and a reason is what stops the list growing by habit.
	if len(allowed) == 0 {
		t.Fatal("nothing is exempt, so the exemption list checks nothing")
	}
	for path, why := range allowed {
		if why == "" {
			t.Errorf("%s is exempt and says nothing about why", path)
		}
		if !strings.HasSuffix(path, ".go") {
			t.Errorf("%q is exempt and is not a Go file, so it matches by accident", path)
		}
	}
}
