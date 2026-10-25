// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// A NUL character is refused in every typed input: a query parameter, a path
// value, a form field and a string in a JSON body. On PostgreSQL and SQLite the
// query builder refuses a string holding one, so the request would fail where
// nothing could say why; on MySQL and MariaDB it drops one, so the same request
// would be answered differently by engine. An uploaded file is not typed input
// and keeps its own handling.

// HoldsNUL reports whether s carries a NUL character.
func HoldsNUL(s string) bool { return strings.IndexByte(s, 0) >= 0 }

// RefusalOfNUL is the refusal of an input holding a NUL, naming the input.
func RefusalOfNUL(input string) string {
	return input + " holds a NUL character, which no input may carry: send it without one"
}

// NULInValues names the first of a set of named values holding a NUL, the
// names taken in order so the same request is refused naming the same input
// every time.
func NULInValues(kind string, values map[string][]string) (string, bool) {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if HoldsNUL(name) {
			return "a " + kind + " name", true
		}
		for _, value := range values[name] {
			if HoldsNUL(value) {
				return kind + " " + name, true
			}
		}
	}
	return "", false
}

// RefusingNUL is a JSON format whose reading refuses a body holding a NUL in
// any string, a key included, naming where it is. The framework reports a
// body it cannot read as a 400 located at the body.
func RefusingNUL(inner huma.Format) huma.Format {
	return huma.Format{
		Marshal: inner.Marshal,
		Unmarshal: func(data []byte, v any) error {
			if err := inner.Unmarshal(data, v); err != nil {
				return err
			}
			read, generic := v.(*any)
			if !generic {
				var parsed any
				if err := json.Unmarshal(data, &parsed); err != nil {
					return err
				}
				read = &parsed
			}
			if at, found := nulIn(*read, "body"); found {
				return fmt.Errorf("%s", RefusalOfNUL(at))
			}
			return nil
		},
	}
}

// nulIn names the first place in a decoded JSON value holding a NUL, keys in
// order.
func nulIn(v any, at string) (string, bool) {
	switch value := v.(type) {
	case string:
		return at, HoldsNUL(value)
	case []any:
		for i, each := range value {
			if place, found := nulIn(each, fmt.Sprintf("%s[%d]", at, i)); found {
				return place, true
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if HoldsNUL(key) {
				return "a key in " + at, true
			}
			if place, found := nulIn(value[key], at+"."+key); found {
				return place, true
			}
		}
	}
	return "", false
}
