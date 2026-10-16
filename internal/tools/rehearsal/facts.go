// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Counts is how many rows each table holds.
type Counts map[string]int64

// Movement is what an upgrade may do to a table's count from the rows the
// release held: fill a new table, merge rows of one away, or add rows to one or
// take rows from one, by at least Least rows and at most Most.
type Movement struct {
	Kind        MovementKind
	Least, Most int64
}

// MovementKind is which of the four a movement is.
type MovementKind int

const (
	// Fills is a new table the upgrade writes from rows the release held.
	Fills MovementKind = iota + 1
	// Merges is a table the upgrade merges rows of, which may hold fewer.
	Merges
	// Gains is a table the upgrade adds rows to.
	Gains
	// Loses is a table the upgrade takes rows from.
	Loses
)

// exactly is a movement of one size.
func exactly(kind MovementKind, n int64) Movement { return Movement{Kind: kind, Least: n, Most: n} }

// imagesByName is the migration that identifies a container image by its
// name: it merges the components, nodes and edges a release made per version
// of one image, and records each version a build stated from those nodes.
const imagesByName = 43

// Images is the rows a release held for container images, counted before the
// upgrade: what the merge may remove at most, and what it may fill from.
type Images struct {
	Components, Nodes, Edges int64
}

// Moved is what the upgrade from a release whose last migration is given may
// do to each table's count, beyond keeping it. The merge removes no more than
// the rows the release held for images, and records no more versions than it
// held image nodes.
func Moved(fromLast int64, images Images) map[string]Movement {
	moved := map[string]Movement{}
	if fromLast < imagesByName {
		moved["image_version"] = Movement{Kind: Fills, Most: images.Nodes}
		moved["component"] = Movement{Kind: Merges, Most: images.Components}
		moved["graph_node"] = Movement{Kind: Merges, Most: images.Nodes}
		moved["graph_edge"] = Movement{Kind: Merges, Most: images.Edges}
	}
	return moved
}

// Compare reports every table whose count moved across an upgrade. before is
// what the release held, after is what the upgrade left. A table both sides
// hold keeps its count, and a table only the upgrade holds starts empty,
// except as moved says.
func Compare(before, after Counts, moved map[string]Movement) []string {
	var faults []string
	names := map[string]bool{}
	for name := range before {
		names[name] = true
	}
	for name := range after {
		names[name] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	slices.Sort(ordered)

	for _, name := range ordered {
		was, held := before[name]
		is, holds := after[name]
		switch {
		case held && !holds:
			faults = append(faults, fmt.Sprintf("%s held %d rows and is gone, and nothing says where they went", name, was))
		case held && moved[name].Kind == Merges && is <= was && was-is <= moved[name].Most:
		case held && moved[name].Kind == Gains && moved[name].within(is-was):
		case held && moved[name].Kind == Loses && moved[name].within(was-is):
		case held && moved[name].Kind == Gains:
			faults = append(faults, fmt.Sprintf("%s held %d rows and holds %d, and the upgrade adds %s",
				name, was, is, moved[name].size()))
		case held && moved[name].Kind == Loses:
			faults = append(faults, fmt.Sprintf("%s held %d rows and holds %d, and the upgrade takes away %s",
				name, was, is, moved[name].size()))
		case held && is != was:
			faults = append(faults, fmt.Sprintf("%s held %d rows and holds %d", name, was, is))
		case !held && moved[name].Kind == Fills && moved[name].within(is):
		case !held && moved[name].Kind == Fills:
			faults = append(faults, fmt.Sprintf("%s is new and holds %d rows, and the upgrade fills %s",
				name, is, moved[name].size()))
		case !held && is != 0:
			faults = append(faults, fmt.Sprintf("%s is new and holds %d rows, and nothing the release held fills it", name, is))
		}
	}
	return faults
}

// within is whether n rows is a size the movement allows.
func (m Movement) within(n int64) bool { return n >= m.Least && n <= m.Most }

// size is the rows a movement allows, as a fault names them.
func (m Movement) size() string {
	if m.Least == m.Most {
		return fmt.Sprintf("%d", m.Most)
	}
	return fmt.Sprintf("%d to %d", m.Least, m.Most)
}

// wordsAndRatings is the migration that stores the reasoning of a claim and of
// a supplier's statement once, and takes the rating a flaw was recorded at off
// the issue row into the recording product's own.
const wordsAndRatings = 43

// mostWords is the bound the upgrade cuts reasoning to, in bytes.
const mostWords = 64 << 10

// KeptWords is reasoning as the upgrade stores it: valid UTF-8, without NUL,
// and cut to the bound on a character boundary. Written apart from the
// upgrade's own copy, so the count it gives checks that copy rather than
// repeating it.
func KeptWords(said string) string {
	kept := strings.ReplaceAll(strings.ToValidUTF8(said, "\uFFFD"), "\x00", "")
	if len(kept) <= mostWords {
		return kept
	}
	cut := mostWords
	for cut > 0 && !utf8.RuneStart(kept[cut]) {
		cut--
	}
	return kept[:cut]
}

// Words is what the release held that the reasoning is stored from: the
// distinct reasoning, byte for byte as KeptWords keeps it, across every claim
// and every supplier statement. Each is stored once.
type Words struct {
	Distinct int64
}

// Ratings is what the rating move reads and writes, counted on one side of
// the upgrade.
type Ratings struct {
	// Unsourced is each issue's ratings that name no publisher.
	Unsourced map[int64]int64
	// Sourced is the ratings that name one, across every issue.
	Sourced int64
	// InForce is each issue and product a word is in force for.
	InForce map[Pair]bool
	// Recorded is each issue and product a recorded rating is held for, and
	// whether it holds a word. Read after the upgrade.
	Recorded map[Pair]bool
	// Plain is the issues and products the release held a recorded flaw for,
	// on an issue rated by a word or an unsourced score, other than a scanned
	// issue kept in a merge. Each one is moved. Read before the upgrade.
	Plain int64
	// Kept is the issues and products the release held a recorded flaw for,
	// on an issue holding a scanned finding that absorbed another in a merge.
	// Each one may be moved, as the issues the merge brought together say.
	// Read before the upgrade.
	Kept int64
}

// Pair is an issue and a product.
type Pair struct{ Issue, Product int64 }

// Restated is what the upgrade from a release whose last migration is given
// may do to the tables it stores reasoning and ratings in, and what it did to
// one that no count can show.
//
// The reasoning fills a table with one row per distinct text. The recorded
// ratings fill a table with one row per moved flaw. A recorded word is put in
// force where none was, so the words in force gain exactly the recorded words
// whose issue and product held none. An unsourced rating is taken away only
// from an issue that now holds a recorded rating, so the ratings lose exactly
// what those issues lost, and nothing else moves: no sourced rating, no other
// issue's, and no word that was in force.
func Restated(fromLast int64, words Words, before, after Ratings) (map[string]Movement, []string) {
	moved := map[string]Movement{}
	if fromLast >= wordsAndRatings {
		return moved, nil
	}
	var faults []string
	moved["statement_text"] = exactly(Fills, words.Distinct)
	moved["recorded_rating"] = Movement{Kind: Fills, Least: before.Plain, Most: before.Plain + before.Kept}

	var gained int64
	for pair, worded := range after.Recorded {
		if worded && !before.InForce[pair] {
			gained++
		}
	}
	for pair := range before.InForce {
		if !after.InForce[pair] {
			faults = append(faults, fmt.Sprintf("issue_rating: the word in force for issue %d in product %d is gone",
				pair.Issue, pair.Product))
		}
	}
	moved["issue_rating"] = exactly(Gains, gained)

	recorded := map[int64]bool{}
	for pair := range after.Recorded {
		recorded[pair.Issue] = true
	}
	issues := map[int64]bool{}
	for issue := range before.Unsourced {
		issues[issue] = true
	}
	for issue := range after.Unsourced {
		issues[issue] = true
	}
	var lost int64
	for issue := range issues {
		was, is := before.Unsourced[issue], after.Unsourced[issue]
		switch {
		case is > was:
			faults = append(faults, fmt.Sprintf("vulnerability_rating: issue %d held %d unsourced ratings and holds %d",
				issue, was, is))
		case is < was && !recorded[issue]:
			faults = append(faults, fmt.Sprintf("vulnerability_rating: issue %d lost %d unsourced ratings and holds "+
				"no recorded rating", issue, was-is))
		default:
			lost += was - is
		}
	}
	if before.Sourced != after.Sourced {
		faults = append(faults, fmt.Sprintf("vulnerability_rating: %d ratings named a publisher and %d do",
			before.Sourced, after.Sourced))
	}
	moved["vulnerability_rating"] = exactly(Loses, lost)
	slices.Sort(faults)
	return moved, faults
}

// Totals is a number the interface shows for each build, keyed on the build.
type Totals map[string]int64

// CompareTotals reports every build whose total moved, and every build one
// side names and the other does not.
func CompareTotals(what string, before, after Totals) []string {
	var faults []string
	keys := make([]string, 0, len(before)+len(after))
	for key := range before {
		keys = append(keys, key)
	}
	for key := range after {
		if _, ok := before[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		was, held := before[key]
		is, holds := after[key]
		switch {
		case !holds:
			faults = append(faults, fmt.Sprintf("%s: %s read %d before and is not answered after", what, key, was))
		case !held:
			faults = append(faults, fmt.Sprintf("%s: %s is answered after and was not before", what, key))
		case was != is:
			faults = append(faults, fmt.Sprintf("%s: %s read %d before and %d after", what, key, was, is))
		}
	}
	return faults
}
