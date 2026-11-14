// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import "sort"

// How a result was paired with a code finding, as the code finding's result records it. A
// pairing on the whole key is strong; on the function or the nearest line it
// is probable.
const (
	onKey      = "key"
	onFunction = "function"
	onLine     = "line"
	// onUnprinted is a fingerprint change's pairing on the whole key without its
	// fingerprint, where one result and one code finding hold it.
	onUnprinted = "unprinted"
)

// strong is whether a pairing on this layer is strong.
func strong(on string) bool { return on == onKey || on == onUnprinted }

// candidate is a code finding a result may be paired with, as its newest sighting
// described it.
type candidate struct {
	findingID   int64
	occurrence  string
	key         string
	unprinted   string
	functionKey string
	lineKey     string
	line        int
	spot
	// told is whether its key is held twice, by two results or by two
	// occurrences, so its spot was read and tells it from the others.
	told bool
	// absent is whether the last comparable run did not see it.
	absent bool
}

// spot is where on its line a code finding was last seen and what it said,
// which tell apart code findings sharing a key.
type spot struct {
	column  int
	message string
}

// spotOf is a spot as stored, a column of nothing being none.
func spotOf(column *int, message string) spot {
	s := spot{message: message}
	if column != nil {
		s.column = *column
	}
	return s
}

// spotKey is a key and a spot within it.
type spotKey struct {
	key string
	spot
}

// bySpot indexes items by key and spot, in their order, keeping those keep
// admits: where results sharing a key look for the one at their spot.
func bySpot[T any](items []T, keep func(T) bool, at func(T) spotKey) map[spotKey][]T {
	out := map[spotKey][]T{}
	for _, it := range items {
		if keep(it) {
			k := at(it)
			out[k] = append(out[k], it)
		}
	}
	return out
}

// before is whether one spot sorts before another: by column, then message.
func (s spot) before(o spot) bool {
	if s.column != o.column {
		return s.column < o.column
	}
	return s.message < o.message
}

// byRank pairs results with code findings sharing their key by the rank of
// their spots, each list sorted by spot and paired in turn. The code findings
// taking part are the first of theirs, in their order, as many as there are
// results; the results taking part are the first by spot, as many as there
// are code findings.
func byRank[R, C any](results []R, codeFindings []C, spotR func(R) spot, spotC func(C) spot) []ranked[R, C] {
	n := min(len(results), len(codeFindings))
	rs := append([]R(nil), results...)
	sort.SliceStable(rs, func(i, j int) bool { return spotR(rs[i]).before(spotR(rs[j])) })
	cs := append([]C(nil), codeFindings[:n]...)
	sort.SliceStable(cs, func(i, j int) bool { return spotC(cs[i]).before(spotC(cs[j])) })
	out := make([]ranked[R, C], n)
	for i := range n {
		out[i] = ranked[R, C]{rs[i], cs[i]}
	}
	return out
}

// ranked is a result and the code finding byRank paired it with.
type ranked[R, C any] struct {
	result      R
	codeFinding C
}

// heldTwice is the keys two results hold, or two occurrences: those where a
// result is told from another by its column and message.
func heldTwice(keys []string, holders map[string]map[string]bool) map[string]bool {
	seen := make(map[string]bool, len(keys))
	shared := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			shared[k] = true
		}
		seen[k] = true
	}
	for k, occurrences := range holders {
		if len(occurrences) > 1 {
			shared[k] = true
		}
	}
	return shared
}

// holding records that an occurrence holds a key.
func holding(holders map[string]map[string]bool, key, occurrence string) {
	if holders[key] == nil {
		holders[key] = map[string]bool{}
	}
	holders[key][occurrence] = true
}

// candidatesHeldTwice is heldTwice over candidates.
func candidatesHeldTwice(candidates []candidate, results []Keyed) map[string]bool {
	holders := map[string]map[string]bool{}
	for _, c := range candidates {
		holding(holders, c.key, c.occurrence)
	}
	return heldTwice(keysOf(results), holders)
}

// keysOf is the whole keys of results.
func keysOf(results []Keyed) []string {
	out := make([]string, len(results))
	for i, k := range results {
		out[i] = k.Key
	}
	return out
}

// nearest is how many candidates sharing a result's line key, nearest it
// first, the line layer offers it.
const nearest = 8

// pairing is one result paired with one candidate, and the layer that paired
// them.
type pairing struct {
	result, candidate int
	on                string
}

// pair pairs results with candidates one to one, a layer at a time, each
// layer pairing what the layers before it left: the whole key, then the
// function, then the nearest line. Between candidates a layer cannot tell
// apart, one the last comparable run saw comes before one it missed, and then
// the older code finding.
func pair(candidates []candidate, results []Keyed) []pairing {
	return layered(candidates, results, false)
}

// pairAcross is pair for a fingerprint change. After the whole key, a result and a
// code finding holding the whole key without its fingerprint are paired strongly
// where they are the only result and the only code finding holding it; the rest fall
// to the probable layers. A rotated salt changes every fingerprint and nothing
// else, so a key nothing else holds is the same result.
func pairAcross(candidates []candidate, results []Keyed) []pairing {
	return layered(candidates, results, true)
}

func layered(candidates []candidate, results []Keyed, printsChanged bool) []pairing {
	takenC := make([]bool, len(candidates))
	takenR := make([]bool, len(results))
	var out []pairing

	order := make([]int, len(candidates))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := candidates[order[i]], candidates[order[j]]
		if a.absent != b.absent {
			return !a.absent
		}
		return a.findingID < b.findingID
	})

	for _, layer := range []struct {
		on  string
		ofC func(candidate) string
		ofR func(Keyed) string
	}{
		{onKey, func(c candidate) string { return c.key }, func(k Keyed) string { return k.Key }},
		{onFunction, func(c candidate) string { return c.functionKey }, func(k Keyed) string { return k.FunctionKey }},
	} {
		// A fingerprint change's unique keys come after the whole key and before
		// anything probable.
		if layer.on == onFunction && printsChanged {
			unique(candidates, results, takenC, takenR, &out)
		}
		// Where a key is held twice, results under it are told apart by
		// where they sit first, so each keeps the code finding it was paired
		// with whatever order a run lists them in, or after a line moves them
		// all: on the whole key by column and message, where those were read,
		// and on the function by column.
		var shared map[string]bool
		var spotC func(candidate) spot
		var spotR func(Keyed) spot
		if layer.on == onKey {
			shared = map[string]bool{}
			for _, c := range candidates {
				if c.told {
					shared[c.key] = true
				}
			}
			spotC = func(c candidate) spot { return c.spot }
			spotR = func(k Keyed) spot { return spot{k.StartColumn, k.Message} }
		} else {
			holders := map[string]map[string]bool{}
			for _, c := range order {
				if !takenC[c] && candidates[c].functionKey != "" {
					holding(holders, candidates[c].functionKey, candidates[c].occurrence)
				}
			}
			var keys []string
			for r, res := range results {
				if !takenR[r] {
					keys = append(keys, res.FunctionKey)
				}
			}
			shared = heldTwice(keys, holders)
			spotC = func(c candidate) spot { return spot{column: c.column} }
			spotR = func(k Keyed) spot { return spot{column: k.StartColumn} }
		}
		at := bySpot(order, func(c int) bool { return !takenC[c] && shared[layer.ofC(candidates[c])] },
			func(c int) spotKey { return spotKey{layer.ofC(candidates[c]), spotC(candidates[c])} })
		for r, res := range results {
			k := layer.ofR(res)
			if takenR[r] || k == "" || !shared[k] {
				continue
			}
			sk := spotKey{k, spotR(res)}
			if cs := at[sk]; len(cs) > 0 {
				c := cs[0]
				at[sk] = cs[1:]
				takenC[c], takenR[r] = true, true
				out = append(out, pairing{result: r, candidate: c, on: layer.on})
			}
		}
		waiting := map[string][]int{}
		for _, c := range order {
			if k := layer.ofC(candidates[c]); !takenC[c] && k != "" {
				waiting[k] = append(waiting[k], c)
			}
		}
		left := map[string][]int{}
		for r, res := range results {
			k := layer.ofR(res)
			if takenR[r] || k == "" || len(waiting[k]) == 0 {
				continue
			}
			if shared[k] {
				left[k] = append(left[k], r)
				continue
			}
			c := waiting[k][0]
			waiting[k] = waiting[k][1:]
			takenC[c], takenR[r] = true, true
			out = append(out, pairing{result: r, candidate: c, on: layer.on})
		}
		// Under a key held twice, what no spot paired is paired in the order
		// of its spots, so a shift moving every result on a line keeps each
		// with its own, whatever order the run lists them in.
		for k, rs := range left {
			cs := waiting[k]
			for _, p := range byRank(rs, cs,
				func(r int) spot { return spotR(results[r]) }, func(c int) spot { return spotC(candidates[c]) }) {
				takenC[p.codeFinding], takenR[p.result] = true, true
				out = append(out, pairing{result: p.result, candidate: p.codeFinding, on: layer.on})
			}
		}
	}

	// The nearest line: for each result, the candidates sharing its line key
	// nearest to it, closest pairs first. A file repeating one message holds
	// many results under one line key, so each result is offered its nearest
	// few rather than all of them.
	rank := make(map[int]int, len(order))
	byKey := map[string][]int{}
	for i, c := range order {
		rank[c] = i
		if !takenC[c] {
			byKey[candidates[c].lineKey] = append(byKey[candidates[c].lineKey], c)
		}
	}
	for k := range byKey {
		group := byKey[k]
		sort.SliceStable(group, func(i, j int) bool { return candidates[group[i]].line < candidates[group[j]].line })
	}
	type near struct {
		distance, moved, rank, result, candidate int
	}
	var pairs []near
	for r, res := range results {
		group := byKey[res.LineKey]
		if takenR[r] || len(group) == 0 {
			continue
		}
		at := sort.Search(len(group), func(i int) bool { return candidates[group[i]].line >= res.StartLine })
		lo, hi := at-1, at
		for n := 0; n < nearest && (lo >= 0 || hi < len(group)); n++ {
			var c int
			switch {
			case lo < 0:
				c, hi = group[hi], hi+1
			case hi >= len(group):
				c, lo = group[lo], lo-1
			case res.StartLine-candidates[group[lo]].line <= candidates[group[hi]].line-res.StartLine:
				c, lo = group[lo], lo-1
			default:
				c, hi = group[hi], hi+1
			}
			d := res.StartLine - candidates[c].line
			if d < 0 {
				d = -d
			}
			// At one distance, the candidate nearest the result's column comes
			// first, so results on one line keep theirs when a line moves
			// them, and when a shift of indent moves them all too.
			moved := res.StartColumn - candidates[c].column
			if moved < 0 {
				moved = -moved
			}
			pairs = append(pairs, near{distance: d, moved: moved, rank: rank[c], result: r, candidate: c})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		a, b := pairs[i], pairs[j]
		switch {
		case a.distance != b.distance:
			return a.distance < b.distance
		case a.moved != b.moved:
			return a.moved < b.moved
		case a.rank != b.rank:
			return a.rank < b.rank
		}
		return a.result < b.result
	})
	for _, p := range pairs {
		if takenR[p.result] || takenC[p.candidate] {
			continue
		}
		takenC[p.candidate], takenR[p.result] = true, true
		out = append(out, pairing{result: p.result, candidate: p.candidate, on: onLine})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].result < out[j].result })
	return out
}

// unique pairs, strongly, each result and code finding left untaken that are the only
// result and the only code finding holding their whole key without its fingerprint.
func unique(candidates []candidate, results []Keyed, takenC, takenR []bool, out *[]pairing) {
	codeFindings := map[string][]int{}
	for c, cand := range candidates {
		if !takenC[c] && cand.unprinted != "" {
			codeFindings[cand.unprinted] = append(codeFindings[cand.unprinted], c)
		}
	}
	held := map[string][]int{}
	for r, res := range results {
		if !takenR[r] && res.UnprintedKey != "" {
			held[res.UnprintedKey] = append(held[res.UnprintedKey], r)
		}
	}
	for k, rs := range held {
		if len(rs) != 1 || len(codeFindings[k]) != 1 {
			continue
		}
		r, c := rs[0], codeFindings[k][0]
		takenC[c], takenR[r] = true, true
		*out = append(*out, pairing{result: r, candidate: c, on: onUnprinted})
	}
}
