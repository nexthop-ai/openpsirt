// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// ChangeView is one administrative change as every reader states it: the
// list, the file and a person's page. An absent value is told from an empty
// one by Unset and Cleared.
type ChangeView struct {
	At, Actor, By, ByName, Kind, About, Was, Became string
	Unset, Cleared                                  bool
}

// ChangeViews states a page of changes, naming who made each by the identity
// they sign in under with their display name beside it, read once for the
// page.
//
// One builder, so the screen and the file cannot come to state one change
// differently.
func ChangeViews(ctx context.Context, db bun.IDB, changes []trail.Change) ([]ChangeView, error) {
	who := make([]int64, 0, len(changes))
	for _, change := range changes {
		if person := change.Person(); person != 0 {
			who = append(who, person)
		}
	}
	people, err := WhoSigned(ctx, db, who)
	if err != nil {
		return nil, err
	}
	out := make([]ChangeView, 0, len(changes))
	for _, change := range changes {
		out = append(out, ChangeView{
			At: Stamp(change.At), Actor: string(change.Actor),
			By: people.Identity(change.Person()), ByName: people.Label(change.Person()),
			Kind: string(change.Kind), About: change.Name,
			Was: OrBlank(change.Was), Became: OrBlank(change.Became),
			Unset: change.Was == nil, Cleared: change.Became == nil,
		})
	}
	return out, nil
}
