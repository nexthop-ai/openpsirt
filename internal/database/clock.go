// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"fmt"
	"math"
	"time"
)

// ServerTime is the database server's own clock, at the moment of asking.
//
// Read as seconds since the epoch, since each engine's timestamp follows the
// session's time zone and its own text form, and a count of seconds follows
// neither. The statement differs by engine, so it is spelled here.
func (d *DB) ServerTime(ctx context.Context) (time.Time, error) {
	var query string
	switch d.Server.Engine {
	case Postgres:
		query = `SELECT EXTRACT(EPOCH FROM CLOCK_TIMESTAMP())::float8`
	case MySQL, MariaDB:
		// UTC_TIMESTAMP and a difference of two datetimes follow no session
		// time zone, where UNIX_TIMESTAMP(NOW()) is ambiguous in the hour a
		// zone's clocks go back.
		query = `SELECT TIMESTAMPDIFF(MICROSECOND, '1970-01-01 00:00:00', UTC_TIMESTAMP(6)) / 1000000`
	case SQLite:
		query = `SELECT (julianday('now') - 2440587.5) * 86400.0`
	default:
		return time.Time{}, fmt.Errorf("no clock reading for %s", d.Server.Engine)
	}
	var seconds float64
	if err := d.DB.NewRaw(query).Scan(ctx, &seconds); err != nil {
		return time.Time{}, fmt.Errorf("read the database's clock: %w", err)
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*1e9)).UTC(), nil
}
