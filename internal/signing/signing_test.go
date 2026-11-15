// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signing_test

import (
	"bytes"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/nexthop-ai/openpsirt/internal/signing"
	"github.com/nexthop-ai/openpsirt/internal/signing/signingtest"
)

// A document released before the key was last re-signed — its expiry
// extended, a name added — still gets a signature that verifies: the signature
// is dated no earlier than the newest self-signature vouching for the key.
func TestADocumentOlderThanTheKeysLastSelfSignatureStillVerifies(t *testing.T) {
	// The operator extends the key's expiry, which signs its name again.
	_, extended := signingtest.Resigned(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	signer, err := signing.Read(extended, "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"document":"released in March"}`)
	signature, err := signer.Sign(body, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("a document released before the key was re-signed could not be signed: %v", err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(signer.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(body),
		bytes.NewReader(signature), nil); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
}

// at is a key configuration whose clock reads the moment given.
func at(moment time.Time) *packet.Config {
	return &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return moment }}
}

// entityAt is a new key made at the moment given.
func entityAt(t *testing.T, made time.Time) *openpgp.Entity {
	t.Helper()
	entity, err := openpgp.NewEntity("Example PSIRT", "", "psirt@example.test", at(made))
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

// armoredAs is entities armored as a block of the type given, the private
// halves where private is set, with every signature as it was made.
func armoredAs(t *testing.T, blockType string, private bool, entities ...*openpgp.Entity) string {
	t.Helper()
	var out bytes.Buffer
	writer, err := armor.Encode(&out, blockType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, entity := range entities {
		if private {
			err = entity.SerializePrivateWithoutSigning(writer, nil)
		} else {
			err = entity.Serialize(writer)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// resign signs the entity's name again at the moment given, with the flags
// given, so that signature is the one vouching for the primary key.
func resign(t *testing.T, entity *openpgp.Entity, moment time.Time, sign bool) {
	t.Helper()
	ident := entity.PrimaryIdentity()
	primary := true
	again := &packet.Signature{
		Version: entity.PrimaryKey.Version, SigType: packet.SigTypePositiveCert,
		PubKeyAlgo: entity.PrimaryKey.PubKeyAlgo, Hash: crypto.SHA256, CreationTime: moment,
		IssuerKeyId: &entity.PrimaryKey.KeyId, IssuerFingerprint: entity.PrimaryKey.Fingerprint,
		IsPrimaryId: &primary, FlagsValid: true, FlagSign: sign, FlagCertify: true,
	}
	if err := again.SignUserId(ident.UserId.Id, entity.PrimaryKey, entity.PrivateKey, at(moment)); err != nil {
		t.Fatal(err)
	}
	ident.SelfSignature = again
	ident.Signatures = append(ident.Signatures, again)
}

// Each key a deployment could start with and then sign nothing is refused
// when it is read, naming why.
func TestAKeyThatCannotSignIsRefusedWhenRead(t *testing.T) {
	made := time.Now().Add(-48 * time.Hour)
	revoked := entityAt(t, made)
	if err := revoked.RevokeKey(packet.KeyCompromised, "", at(made.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	notForSigning := entityAt(t, made)
	resign(t, notForSigning, made.Add(time.Hour), false)
	for _, c := range []struct{ what, armored, names string }{
		{"two keys", armoredAs(t, openpgp.PrivateKeyType, true, entityAt(t, made), entityAt(t, made)),
			"holds 2 keys, where one signs"},
		{"a public key alone", armoredAs(t, openpgp.PublicKeyType, false, entityAt(t, made)),
			"holds a public key only"},
		{"an expired key", signingtest.Key(t, made, 3600), "has no key able to sign now"},
		{"a revoked key", armoredAs(t, openpgp.PrivateKeyType, true, revoked), "has no key able to sign now"},
		{"a key not for signing", armoredAs(t, openpgp.PrivateKeyType, true, notForSigning),
			"has no key able to sign now"},
	} {
		if _, err := signing.Read(c.armored, ""); err == nil || !strings.Contains(err.Error(), c.names) {
			t.Errorf("%s answered %v, want it refused as %q", c.what, err, c.names)
		}
	}
}

// A signing subkey is valid from no earlier than the newest signature
// vouching for the primary key above it, so a document dated before the
// primary key was last re-signed carries a signature dated at it, which
// verifies.
func TestASubkeySignsFromThePrimaryKeysLastSelfSignature(t *testing.T) {
	made := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	bound := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	resigned := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	entity := entityAt(t, made)
	if err := entity.AddSigningSubkey(at(bound)); err != nil {
		t.Fatal(err)
	}
	resign(t, entity, resigned, true)
	signer, err := signing.Read(armoredAs(t, openpgp.PrivateKeyType, true, entity), "")
	if err != nil {
		t.Fatal(err)
	}
	if !signer.From().Equal(resigned) {
		t.Errorf("the key signs from %s, want the primary key's re-signature at %s", signer.From(), resigned)
	}
	body := []byte(`{"document":"released in March"}`)
	signature, err := signer.Sign(body, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(signer.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(body),
		bytes.NewReader(signature), nil); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
}
