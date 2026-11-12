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

// heldTwice is the keys two results hold, or two occurrences: those where a
// result is told from another by its column and message.
func heldTwice(results []Keyed, holders map[string]map[string]bool) map[string]bool {
	seen := make(map[string]bool, len(results))
	shared := map[string]bool{}
	for _, k := range results {
		if seen[k.Key] {
			shared[k.Key] = true
		}
		seen[k.Key] = true
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
	return heldTwice(results, holders)
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
		waiting := map[string][]int{}
		for _, c := range order {
			if k := layer.ofC(candidates[c]); !takenC[c] && k != "" {
				waiting[k] = append(waiting[k], c)
			}
		}
		// Where a key is held twice, by two results or by two occurrences,
		// they are told apart by column and message first, so each keeps the
		// code finding it was paired with whatever order a run lists them in.
		if layer.on == onKey {
			shared := map[string]bool{}
			for _, c := range candidates {
				if c.told {
					shared[c.key] = true
				}
			}
			at := map[spotKey][]int{}
			for _, c := range order {
				if k := candidates[c].key; !takenC[c] && shared[k] {
					at[spotKey{k, candidates[c].spot}] = append(at[spotKey{k, candidates[c].spot}], c)
				}
			}
			for r, res := range results {
				if takenR[r] || !shared[res.Key] {
					continue
				}
				sk := spotKey{res.Key, spot{res.StartColumn, res.Message}}
				if cs := at[sk]; len(cs) > 0 {
					c := cs[0]
					at[sk] = cs[1:]
					takenC[c], takenR[r] = true, true
					out = append(out, pairing{result: r, candidate: c, on: layer.on})
				}
			}
		}
		for r, res := range results {
			k := layer.ofR(res)
			for len(waiting[k]) > 0 && takenC[waiting[k][0]] {
				waiting[k] = waiting[k][1:]
			}
			if takenR[r] || k == "" || len(waiting[k]) == 0 {
				continue
			}
			c := waiting[k][0]
			waiting[k] = waiting[k][1:]
			takenC[c], takenR[r] = true, true
			out = append(out, pairing{result: r, candidate: c, on: layer.on})
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
		distance, rank, result, candidate int
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
			pairs = append(pairs, near{distance: d, rank: rank[c], result: r, candidate: c})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		a, b := pairs[i], pairs[j]
		switch {
		case a.distance != b.distance:
			return a.distance < b.distance
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
