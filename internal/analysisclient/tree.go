// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysisclient

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

// eachLocation calls fn with every location object a result names: its
// locations, its related locations, every step of every flow, and every frame
// of every stack.
func eachLocation(result obj, fn func(loc obj)) {
	for _, loc := range objects(result, "locations") {
		fn(loc)
	}
	for _, loc := range objects(result, "relatedLocations") {
		fn(loc)
	}
	for _, stack := range objects(result, "stacks") {
		for _, frame := range objects(stack, "frames") {
			if loc := child(frame, "location"); loc != nil {
				fn(loc)
			}
		}
	}
	for _, flow := range objects(result, "codeFlows") {
		for _, thread := range objects(flow, "threadFlows") {
			for _, step := range objects(thread, "locations") {
				if loc := child(step, "location"); loc != nil {
					fn(loc)
				}
			}
		}
	}
}

// eachRunLocation calls fn with every location object a run names outside its
// results: the flow steps it lists once for its results to cite, and the
// places each notification of each invocation names.
func eachRunLocation(run obj, fn func(loc obj)) {
	for _, step := range objects(run, "threadFlowLocations") {
		if loc := child(step, "location"); loc != nil {
			fn(loc)
		}
	}
	for _, inv := range objects(run, "invocations") {
		for _, key := range []string{"toolExecutionNotifications", "toolConfigurationNotifications"} {
			for _, note := range objects(inv, key) {
				for _, loc := range objects(note, "locations") {
					fn(loc)
				}
			}
		}
	}
}
