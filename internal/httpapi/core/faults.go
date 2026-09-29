// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"
	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// WentWrong reports a fault to the caller without describing it to them.
//
// The framework serializes an error passed alongside the message, so handing
// it one hands the caller the query text and whatever the driver put in its
// message — which for a connection failure is the address and the user it
// tried. Whoever operates this deployment needs that; whoever is asking does
// not.
//
// The cause travels with the refusal and is not part of it. An act is a
// transaction, and the helper that opened it asks whether what came back is
// worth going again — a deadlock on one engine, a lost race on another.
// Answered with a refusal built fresh, that question is asked of an error
// wrapping nothing, so a mid-transaction deadlock is reported to an
// administrator instead of taken again.
func WentWrong(logger *slog.Logger, what string, err error) error {
	if logger != nil {
		logger.Error(what, "error", err)
	}
	return carried{said: huma.Error500InternalServerError(what), cause: err}
}

// carried is a refusal that remembers what caused it.
//
// The refusal is what a caller is told and is the whole of what they are told:
// the framework resolves a returned error to the first status error it finds,
// which is the refusal inside this, so nothing a driver wrote reaches a
// response. The cause is there for the retry helper, which reads the driver's
// own types through the wrapping.
type carried struct {
	said  error
	cause error
}

// Error is the refusal alone. It is what a log line and a text comparison see,
// and the cause is logged beside it where it is wrapped.
func (c carried) Error() string { return c.said.Error() }

// Unwrap gives both, so that a walk for the status error and a walk for the
// driver's type each find what they are looking for.
func (c carried) Unwrap() []error { return []error{c.said, c.cause} }

// Asked is the answer when a store refused what the caller asked for.
//
// A store returns two kinds of error through one return: a sentence written
// for a person — a decision already standing here, a version that is not a
// version, a threshold crossed — and a query that failed, which carries the
// statement text and whatever the driver put in its message. Answered the same
// way, as a 422 with the message in it, a lost connection reaches whoever
// asked as a bad request carrying the address the driver tried.
//
// A store's sentences are refusals, and only a refusal's text is published.
// Everything else is a fault, logged and answered in fixed words, so a failure
// nobody classified — a connection that dropped, an object store that did not
// answer — never reaches the caller as text.
func Asked(logger *slog.Logger, err error) error {
	// An authorization refusal is not somebody having asked for the
	// impossible. Without this arm it falls to the sentence below and comes
	// back 422 carrying the store's own words — which name the product
	// identifier the refusal exists to withhold. `add-alias` is the live
	// case: recording another name asks for triage in every product the issue
	// is open in, and the route guard can only authorize the one in the path.
	if errors.Is(err, access.ErrDenied) {
		return huma.Error403Forbidden("not authorized")
	}
	// A lost race is a fault that carries its cause: the transaction around
	// the act reads the cause and takes it again, and a caller with no
	// transaction around it, or one out of attempts, is answered 500 in words
	// of our own and logged. Answered as a refusal it is a 422 telling the
	// caller to go again, and the retry helper never sees it.
	if errors.Is(err, database.ErrGoAgain) || database.FromEngine(err) {
		return WentWrong(logger, "that could not be recorded", err)
	}
	// Writing the policy refused, a detail per fault, each naming its line.
	var faults markdown.Faults
	if errors.As(err, &faults) {
		return RefusedText(faults)
	}
	if refusal.In(err) {
		return huma.Error422UnprocessableEntity(err.Error())
	}
	return WentWrong(logger, "that could not be recorded", err)
}

// NoDatabase is the answer when this process has no database behind it.
//
// One sentence for every handler. Each guards against it, because a nil
// pointer inside one is worse than a refusal, and a guard that words it for
// itself reads as many conditions where there is one. Logged, because
// otherwise the only trace of a deployment wired up wrong is a 500 with a
// sentence in it.
//
// It says nothing about what the caller asked for, because the caller did not
// cause it and cannot fix it: this is a process that came up without the thing
// it exists to read.
func NoDatabase(logger *slog.Logger) error {
	if logger != nil {
		logger.Error("this process has no database behind it, so it can answer nothing")
	}
	return huma.Error500InternalServerError("this deployment is not fully configured")
}
