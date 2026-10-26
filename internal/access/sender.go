// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"strconv"
	"strings"
)

// Sender is how a scan records who sent it: the kind of subject and its
// identifier, so a key and a person are never the same sender.
//
// Not the name. A key's name is unique only among keys in force, so a new key
// may hold a withdrawn one's name, and a key may share a name with a person;
// recorded by name, either would read back uploads it never sent. The
// identifier also outlives a rename.
func Sender(subject Subject) string {
	switch subject.Kind {
	case Pipeline:
		return "key:" + strconv.FormatInt(subject.ID, 10)
	case Person:
		return "person:" + strconv.FormatInt(subject.ID, 10)
	}
	return ""
}

// SenderOf reads back who Sender spelled: a key or a person, and its
// identifier. It reports false for anything Sender does not write.
func SenderOf(credential string) (Kind, int64, bool) {
	for _, each := range []struct {
		prefix string
		kind   Kind
	}{{"key:", Pipeline}, {"person:", Person}} {
		if rest, found := strings.CutPrefix(credential, each.prefix); found {
			id, err := strconv.ParseInt(rest, 10, 64)
			return each.kind, id, err == nil && id > 0
		}
	}
	return "", 0, false
}
