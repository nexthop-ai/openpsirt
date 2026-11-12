// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"encoding/json"
	"strconv"
)

// obj is one JSON object of a SARIF document, held generically so that a
// forwarded document keeps every member this client does not touch.
type obj = map[string]any

// list is one JSON array.
type list = []any

// child is the object at key, or nil where there is none.
func child(o obj, key string) obj {
	if o == nil {
		return nil
	}
	c, _ := o[key].(obj)
	return c
}

// ensure is the object at key, made where there is none.
func ensure(o obj, key string) obj {
	if c := child(o, key); c != nil {
		return c
	}
	c := obj{}
	o[key] = c
	return c
}

// items is the array at key, or nil.
func items(o obj, key string) list {
	if o == nil {
		return nil
	}
	l, _ := o[key].(list)
	return l
}

// objects is the objects of the array at key, in order. A member that is not
// an object is skipped.
func objects(o obj, key string) []obj {
	var out []obj
	for _, v := range items(o, key) {
		if c, ok := v.(obj); ok {
			out = append(out, c)
		}
	}
	return out
}

// str is the string at key, or empty.
func str(o obj, key string) string {
	if o == nil {
		return ""
	}
	s, _ := o[key].(string)
	return s
}

// num is the whole number at key, and whether there is one.
func num(o obj, key string) (int, bool) {
	if o == nil {
		return 0, false
	}
	switch v := o[key].(type) {
	case json.Number:
		n, err := strconv.Atoi(v.String())
		return n, err == nil
	case int:
		return v, true
	case float64:
		return int(v), v == float64(int(v))
	}
	return 0, false
}

// eachLocation calls fn with every location object under v, at any depth: a
// result's locations, related locations and flow steps, which are what a
// pruned run holds. A location holds no location below it, so the walk stops
// at one.
func eachLocation(v any, fn func(loc obj)) {
	switch t := v.(type) {
	case obj:
		if _, ok := t["physicalLocation"].(obj); ok {
			fn(t)
			return
		}
		for _, member := range t {
			eachLocation(member, fn)
		}
	case list:
		for _, member := range t {
			eachLocation(member, fn)
		}
	}
}

// stripSnippets removes the snippet of every region and context region of a
// physical location under v, at any depth, and counts them. A member named
// snippet anywhere else is a key a producer chose, such as a message string's
// identifier, and stays.
func stripSnippets(v any) int {
	n := 0
	switch t := v.(type) {
	case obj:
		if physical, ok := t["physicalLocation"].(obj); ok {
			for _, part := range []string{"region", "contextRegion"} {
				if region, ok := physical[part].(obj); ok {
					if _, ok := region["snippet"]; ok {
						delete(region, "snippet")
						n++
					}
				}
			}
		}
		for _, member := range t {
			n += stripSnippets(member)
		}
	case list:
		for _, member := range t {
			n += stripSnippets(member)
		}
	}
	return n
}

// eachMessage calls fn with every object under v, at any depth, holding
// markdown as a string: a message, or a rule's description.
func eachMessage(v any, fn func(m obj)) {
	switch t := v.(type) {
	case obj:
		if _, ok := t["markdown"].(string); ok {
			fn(t)
		}
		for _, member := range t {
			eachMessage(member, fn)
		}
	case list:
		for _, member := range t {
			eachMessage(member, fn)
		}
	}
}
