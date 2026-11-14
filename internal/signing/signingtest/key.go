// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package signingtest makes OpenPGP signing keys for tests, each made for the
// test that asks and never committed.
package signingtest

import (
	"bytes"
	"crypto"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Made is a creation time tests share, so two keys made at it differ only by
// their key material.
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
	return armored(t, entity, cfg)
}

// Resigned is one key twice: as made at created, and after its name was
// signed again at resigned with its expiry extended, which moves when it
// became valid while keeping its fingerprint.
func Resigned(t testing.TB, created, resigned time.Time) (before, after string) {
	t.Helper()
	cfg := func(at time.Time) *packet.Config {
		return &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return at }}
	}
	entity, err := openpgp.NewEntity("Example PSIRT", "", "psirt@example.test", cfg(created))
	if err != nil {
		t.Fatal(err)
	}
	before = armored(t, entity, cfg(created))
	ident := entity.PrimaryIdentity()
	primary, lifetime := true, uint32(5*365*24*3600)
	extended := &packet.Signature{
		Version: entity.PrimaryKey.Version, SigType: packet.SigTypePositiveCert,
		PubKeyAlgo: entity.PrimaryKey.PubKeyAlgo, Hash: crypto.SHA256, CreationTime: resigned,
		IssuerKeyId: &entity.PrimaryKey.KeyId, IssuerFingerprint: entity.PrimaryKey.Fingerprint,
		IsPrimaryId: &primary, FlagsValid: true, FlagSign: true, FlagCertify: true,
		KeyLifetimeSecs: &lifetime,
	}
	if err := extended.SignUserId(ident.UserId.Id, entity.PrimaryKey, entity.PrivateKey, cfg(resigned)); err != nil {
		t.Fatal(err)
	}
	ident.SelfSignature = extended
	ident.Signatures = append(ident.Signatures, extended)
	return before, armored(t, entity, cfg(resigned))
}

// armored is the private key of entity, armored and unprotected. Serializing
// signs its identities again, at the moment cfg names.
func armored(t testing.TB, entity *openpgp.Entity, cfg *packet.Config) string {
	t.Helper()
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
