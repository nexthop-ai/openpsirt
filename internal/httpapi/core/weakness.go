// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import "github.com/nexthop-ai/openpsirt/internal/weakness"

// WeaknessBody is one kind of flaw, under both of the names it has.
//
// Both, and the screen chooses: the catalog's name is what an advisory
// states and what a reader hovering wants, and the short one is what a row
// can hold.
type WeaknessBody struct {
	ID    string `json:"id" doc:"The identifier, such as CWE-787, or the word a feed uses for no classification"`
	Name  string `json:"name,omitempty" doc:"The name the CWE catalog assigns. Absent where the catalog does not assign the identifier"`
	Short string `json:"short,omitempty" doc:"A name of a few words, where the weakness is a common one. Absent for every other"`
}

// Weaknesses names each identifier, in the order given.
func Weaknesses(ids []string) []WeaknessBody {
	if len(ids) == 0 {
		return nil
	}
	out := make([]WeaknessBody, 0, len(ids))
	for _, id := range ids {
		out = append(out, WeaknessOf(weakness.Of(id)))
	}
	return out
}

// WeaknessOf is one named weakness as a response carries it.
func WeaknessOf(named weakness.Named) WeaknessBody {
	return WeaknessBody{ID: named.ID, Name: named.Name, Short: named.Short}
}
