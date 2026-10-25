// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import "sort"

// How a result was paired with a lead, as the lead's result records it. A
// pairing on the whole key is strong; on the function or the nearest line it
// is probable.
const (
	onKey      = "key"
	onFunction = "function"
	onLine     = "line"
)

// strong is whether a pairing on this layer is strong.
func strong(on string) bool { return on == onKey }

// candidate is a lead a result may be paired with, as its newest sighting
// described it.
type candidate struct {
	findingID   int64
	key         string
	functionKey string
	lineKey     string
	line        int
	// absent is whether the last comparable run did not see it.
	absent bool
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
// the older lead.
func pair(candidates []candidate, results []Keyed) []pairing {
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
		waiting := map[string][]int{}
		for _, c := range order {
			if k := layer.ofC(candidates[c]); !takenC[c] && k != "" {
				waiting[k] = append(waiting[k], c)
			}
		}
		for r, res := range results {
			k := layer.ofR(res)
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
