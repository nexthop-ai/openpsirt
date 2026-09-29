// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

// The subject a handler is answering, and the reach that alone gives.
//
// These four are the primitives every operation's declaration is enforced
// against (see rights.go). Kept here rather than in the catalog file where the
// first caller is: a declaration in one file and the primitive that enforces
// it in another with nothing to do with it is what makes the ladder hard to
// audit.

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Reading is the subject a handler is answering, where the answer is something
// to read.
//
// A pipeline is refused rather than shown an empty list. A key may send scans
// and nothing else, and answering "here is nothing" is a different statement
// from "you cannot ask" — the first invites a caller to believe the list is
// empty.
func Reading(ctx context.Context) (access.Subject, error) {
	subject, err := Requester(ctx)
	if err != nil {
		return access.Subject{}, err
	}
	if subject.Kind != access.Person {
		return access.Subject{}, huma.Error403Forbidden("not authorized")
	}
	return subject, nil
}

// Requester is the subject a handler is answering, resolved once before it
// runs.
//
// Nothing here reaches for a request or a header: resolution happens in one
// place for every route, so a handler cannot answer for everybody by
// forgetting to ask.
func Requester(ctx context.Context) (access.Subject, error) {
	subject, err := access.From(ctx)
	if err != nil {
		// Nobody is attached, which for a route behind the resolver means
		// nobody was recognized. The same answer whoever they are.
		return access.Subject{}, huma.Error401Unauthorized("not authorized")
	}
	return subject, nil
}

// Administrating refuses anybody who is not an administrator.
//
// Declaring what exists is administration: it decides what scans may be filed
// against and what every later grant is written in terms of. A pipeline cannot
// do it at all, and neither can somebody who merely reads — a role on a
// product says what they may see in it, not that they may invent another.
func Administrating(ctx context.Context) error {
	subject, err := Requester(ctx)
	if err != nil {
		return err
	}
	if !subject.Admin {
		return huma.Error403Forbidden("not authorized")
	}
	return nil
}

// ReadingTheDeployment refuses anybody who may read neither the deployment's
// own records nor administer it.
//
// The two are different capabilities and either satisfies this: an
// administrator can grant themselves anything, so asking them to hold the
// audit permission as well would be a checkbox rather than a control.
//
// It is not a way into any product. It opens the settings, the grants and the
// change record — records about the deployment rather than about anything
// scanned. An auditor who reads one product goes on reading one product.
func ReadingTheDeployment(ctx context.Context) error {
	subject, err := Requester(ctx)
	if err != nil {
		return err
	}
	if !subject.ReadsTheDeployment() {
		return huma.Error403Forbidden("not authorized")
	}
	return nil
}

// MintingCredentials is administrating, for the two acts that create a
// credential outliving whoever asked.
//
// A credential may not mint another. A personal token issuing a token is
// refused, and the way round it is what an administrator's token can make
// instead: recording a person — an administrator, even — and creating a
// pipeline key. Both outlive the token and neither is bounded by it, so the
// narrow credential can always ask for a wide one.
//
// Only these two. The rest of administration is reversible by another
// administrator and leaves the record every change here leaves; creating a
// credential is the one that hands out a new way in.
func MintingCredentials(ctx context.Context) error {
	if err := Administrating(ctx); err != nil {
		return err
	}
	subject, err := Requester(ctx)
	if err != nil {
		return err
	}
	if subject.Delegated() {
		return huma.Error403Forbidden(
			"a credential cannot create another — sign in to record a person or create a key")
	}
	return nil
}
