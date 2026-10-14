// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

// EncryptionAsAsked is the refusal a deployment's stated transport produces,
// for the test.
//
// Exported for the test alone. What it decides is a comparison between what
// the deployment asked for and what the connection answered, and a test
// against a live server would be a test of whichever transport that server
// happened to negotiate — which passes for the wrong reason on one engine and
// says nothing on another.
func EncryptionAsAsked(server Server, target Target) error {
	return encryptionAsAsked(server, target)
}

// MandatoryTransport is the connection string a deployment that requires
// encryption opens every connection with, for the test: what it decides is a
// rewrite of text, and a server that negotiates encryption either way would
// pass for the wrong reason.
func MandatoryTransport(target Target, getenv func(string) string) (string, error) {
	return mandatoryTransport(target, getenv)
}

// ValidateTimeout is how long a liveness check waits, for the test.
const ValidateTimeout = validateTimeout

// Unanswering is a PostgreSQL handle on an address that accepts a connection
// and never says anything, for the test.
//
// Built here because opening one through Open waits on the same silence before
// it returns, so a test of the bound on a check would be a test of Open's.
func Unanswering(address string) (*DB, error) {
	config, err := pgx.ParseConfig("postgres://u:p@" + address + "/db?sslmode=disable")
	if err != nil {
		return nil, err
	}
	return &DB{DB: bun.NewDB(stdlib.OpenDB(*config), pgdialect.New())}, nil
}
