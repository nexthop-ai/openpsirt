// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package signingtest makes OpenPGP signing keys for tests, each made for the
// test that asks and never committed.
package signingtest

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Made is the moment Key's keys are created at when a test names none, so two
// keys made by one test differ only by their key material.
var Made = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Key is an armored, unprotected private signing key created at the moment
// given and valid for lifetime seconds from it; a lifetime of zero never
// expires.
func Key(t testing.TB, created time.Time, lifetime uint32) string {
	t.Helper()
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created },
		KeyLifetimeSecs: lifetime}
	entity, err := openpgp.NewEntity("Example PSIRT", "", "psirt@example.test", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(writer, cfg); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
