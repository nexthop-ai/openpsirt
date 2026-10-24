// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// kindsOf is the condition keeping the finding under one alias to the kinds a
// consumer includes, with the values it binds, for a statement written as
// text: a join's ON clause or a correlated subquery.
func kindsOf(consumer kind.Consumer, alias string) (string, []any) {
	return consumer.Where(`"` + alias + `"."kind"`)
}

// ofKinds is kindsOf as a step a chained statement applies.
func ofKinds(consumer kind.Consumer, alias string) func(*bun.SelectQuery) *bun.SelectQuery {
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		where, args := kindsOf(consumer, alias)
		return q.Where(where, args...)
	}
}
