// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// publicKey is a public key made for one test, armored alone, and its
// fingerprint.
func publicKey(t *testing.T) (string, string) {
	t.Helper()
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	entity, err := openpgp.NewEntity("SONiC PSIRT", "", "psirt@sonic.example.test", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String(), hex.EncodeToString(entity.PrimaryKey.Fingerprint)
}

// Keys fetched from their own addresses, each armored alone, are read as one
// set: a rotation is trusted with both.
func TestKeysArmoredOneByOneAreReadAsASet(t *testing.T) {
	first, a := publicKey(t)
	second, b := publicKey(t)
	keyring, fingerprint, err := keyringOf(strings.Join([]string{first, second}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := FingerprintOf(a + "," + b); fingerprint != want || len(keyring) != 2 {
		t.Errorf("read %d keys as %s, want both as %s", len(keyring), fingerprint, want)
	}

	var many []string
	for range MostKeys + 1 {
		one, _ := publicKey(t)
		many = append(many, one)
	}
	if _, _, err := keyringOf(strings.Join(many, "\n")); err == nil {
		t.Errorf("%d keys were read, past the %d an upstream signs with", len(many), MostKeys)
	}
}
