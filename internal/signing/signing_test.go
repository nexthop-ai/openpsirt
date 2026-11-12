// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signing_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

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
