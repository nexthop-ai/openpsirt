// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package bound

import (
	"reflect"
	"slices"
	"strings"
)

// Text is another program's bytes as text every engine stores: each run of
// invalid bytes read as one U+FFFD and each NUL dropped. PostgreSQL refuses both in a text
// column and MySQL and MariaDB refuse invalid UTF-8 in strict mode. On
// PostgreSQL and SQLite the query builder fails a statement handed a string
// holding a NUL, and on MySQL and MariaDB it drops the NUL.
func Text(s string) string {
	if strings.IndexByte(s, 0) < 0 && !hasInvalid(s) {
		return s
	}
	return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "")
}

func hasInvalid(s string) bool { return strings.ToValidUTF8(s, "") != s }

// TextIn makes every string reachable from v, which is a pointer, what Text
// makes it: the fields of a struct, the elements of a slice or an array, the
// keys and values of a map and what a pointer or an interface holds. For a
// document decoded from another program's output, whose every string may
// reach the database.
//
// Two keys that repair to one string are one key. A key already valid keeps
// its value; among keys that were not, the last in byte order wins.
func TextIn(v any) {
	text(reflect.ValueOf(v))
}

func text(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		inner := v.Elem()
		if v.Kind() == reflect.Interface {
			// What an interface holds cannot be set in place, so a copy is
			// repaired and put back.
			if inner.Kind() == reflect.String {
				if v.CanSet() {
					v.Set(reflect.ValueOf(Text(inner.String())).Convert(inner.Type()))
				}
				return
			}
			if inner.Kind() != reflect.Pointer && inner.Kind() != reflect.Map && inner.Kind() != reflect.Slice {
				return
			}
		}
		text(inner)
	case reflect.String:
		if v.CanSet() {
			v.SetString(Text(v.String()))
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				text(v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			text(v.Index(i))
		}
	case reflect.Map:
		keys := v.MapKeys()
		if v.Type().Key().Kind() == reflect.String {
			// Sorted, so which of two keys repairing alike wins does not
			// depend on the order a map happens to be walked in.
			slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
		}
		for _, key := range keys {
			value := repaired(v.MapIndex(key))
			if key.Kind() != reflect.String || Text(key.String()) == key.String() {
				v.SetMapIndex(key, value)
				continue
			}
			// A key read the way its value is, or a repaired value no longer
			// finds the entry a lookup by it should.
			v.SetMapIndex(key, reflect.Value{})
			fixed := reflect.ValueOf(Text(key.String())).Convert(key.Type())
			if original(keys, fixed) {
				continue
			}
			v.SetMapIndex(fixed, value)
		}
	}
}

// repaired is a map's value with Text applied to what it holds. A map's values
// cannot be set in place, so a copy is repaired.
func repaired(value reflect.Value) reflect.Value {
	if value.Kind() == reflect.String {
		return reflect.ValueOf(Text(value.String())).Convert(value.Type())
	}
	if value.Kind() == reflect.Interface && !value.IsNil() && value.Elem().Kind() == reflect.String {
		return reflect.ValueOf(Text(value.Elem().String()))
	}
	copied := reflect.New(value.Type()).Elem()
	copied.Set(value)
	text(copied)
	return copied
}

// original says whether key was among the keys a map held before any was
// repaired. A repaired key is valid, so one that was there already was valid
// and keeps its own value.
func original(keys []reflect.Value, key reflect.Value) bool {
	for _, k := range keys {
		if k.String() == key.String() {
			return true
		}
	}
	return false
}
