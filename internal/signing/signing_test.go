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
)

// A document released before the key was last re-signed — its expiry
// extended, a name added — still gets a signature that verifies: the signature
// is dated no earlier than the newest self-signature vouching for the key.
func TestADocumentOlderThanTheKeysLastSelfSignatureStillVerifies(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	resigned := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cfg := func(at time.Time) *packet.Config {
		return &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return at }}
	}
	entity, err := openpgp.NewEntity("Example PSIRT", "", "psirt@example.test", cfg(created))
	if err != nil {
		t.Fatal(err)
	}
	// The operator extends the key's expiry, which signs its name again.
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
	var armored strings.Builder
	w, err := armor.Encode(&armored, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	signer, err := signing.Read(armored.String(), "")
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
