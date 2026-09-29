// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package refusaltest_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/refusaltest"
)

func TestTheDetectorFindsARefusalMapper(t *testing.T) {
	got, err := refusaltest.MappersIn(`package p
func mapped(logger any, err error, what string) error { return err }
func unrelated(what string) error { return nil }
func (s *store) method(err error) error { return err }`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "mapped" {
		t.Errorf("the mappers found were %v, want [mapped]", got)
	}
}
