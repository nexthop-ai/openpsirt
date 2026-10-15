// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package bound

import (
	"reflect"
	"strings"
)

// Text is another program's bytes as text every engine stores: each invalid
// byte read as U+FFFD and each NUL dropped. PostgreSQL refuses both in a text
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
// values of a map and what a pointer or an interface holds. For a document
// decoded from another program's output, whose every string may reach the
// database.
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
		for _, key := range v.MapKeys() {
			value := v.MapIndex(key)
			if value.Kind() == reflect.String {
				v.SetMapIndex(key, reflect.ValueOf(Text(value.String())).Convert(value.Type()))
				continue
			}
			if value.Kind() == reflect.Interface && !value.IsNil() && value.Elem().Kind() == reflect.String {
				v.SetMapIndex(key, reflect.ValueOf(Text(value.Elem().String())))
				continue
			}
			// A map's values cannot be set in place: a copy is repaired and
			// put back.
			copied := reflect.New(value.Type()).Elem()
			copied.Set(value)
			text(copied)
			v.SetMapIndex(key, copied)
		}
	}
}
