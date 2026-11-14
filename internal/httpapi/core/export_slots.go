// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"net/http"
	"sync"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// streamSlots bounds how many exports hold a connection at once.
//
// A fifth of the pool, and at least one: the rest of the pool is left for
// every other request. A pool of one connection has one slot, and it is the
// whole of the pool for as long as the stream runs, which exportCeiling
// bounds.
type streamSlots chan struct{}

// exportStreams is the number of slots where the pool states no size.
const exportStreams = 5

// streams holds each database's slots for the life of the process. The slots
// are a share of one pool, so they belong to the pool rather than to a server
// built over it.
var streams = struct {
	sync.Mutex
	of map[*database.DB]streamSlots
}{of: map[*database.DB]streamSlots{}}

// streamSlotsFor is the slots of db's pool.
func streamSlotsFor(db *database.DB) streamSlots {
	streams.Lock()
	defer streams.Unlock()
	slots, ok := streams.of[db]
	if !ok {
		slots = newStreamSlots(db)
		streams.of[db] = slots
	}
	return slots
}

func newStreamSlots(db *database.DB) streamSlots {
	n := exportStreams
	if db != nil {
		if open := db.DB.DB.Stats().MaxOpenConnections; open > 0 {
			n = max(1, open/5)
		}
	}
	return make(streamSlots, n)
}

// ExportsBusy is what an export that reads as it writes says about the slots
// it waits for, in its published description.
const ExportsBusy = "Answers 503 with `Retry-After` when the deployment is already writing as many " +
	"files as it takes at once; ask again after that many seconds."

// take claims a slot, or refuses with a time to ask again. The release is
// called once the stream has finished writing.
func (s streamSlots) take() (func(), error) {
	select {
	case s <- struct{}{}:
		return func() { <-s }, nil
	default:
		return nil, huma.ErrorWithHeaders(
			huma.Error503ServiceUnavailable("too many exports are being written at once; ask again shortly"),
			http.Header{"Retry-After": []string{"30"}})
	}
}
