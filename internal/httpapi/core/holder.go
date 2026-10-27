// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import "github.com/nexthop-ai/openpsirt/internal/access"

// HolderBody names who is dealing with a code finding, embedded in the answers that
// show one.
type HolderBody struct {
	AssignedTo   string `json:"assigned_to,omitempty" doc:"Who is dealing with it: a person by sign-in identity, or a team by name. Absent where nobody is"`
	AssignedName string `json:"assigned_to_name,omitempty" doc:"Their display name, where it differs from the name above"`
	AssignedTeam bool   `json:"assigned_team,omitempty" doc:"Whether it is a team's queue rather than one person's work: unheld until somebody on the team takes it"`
}

// HolderOf is a party as an answer names it.
func HolderOf(held access.Held) HolderBody {
	return HolderBody{
		AssignedTo: held.Address, AssignedName: LabelBeside(held.Name, held.Address),
		AssignedTeam: held.Team,
	}
}
