// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package signing signs the documents this deployment publishes with the
// OpenPGP key an operator supplied, and hands out the public half of it.
//
// A key is optional. Without one the documents go out with their digests
// beside them and nothing else, which is what the standard's provider role
// asks for; with one each carries a detached signature, which is what its
// trusted provider role adds.
package signing

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Signer is one private key, unlocked, and what is published about it.
type Signer struct {
	entity *openpgp.Entity
	// from is when the key that signs became valid. A signature dated before
	// it is one a reader's tooling refuses.
	from        time.Time
	fingerprint string
	public      []byte
}

// Read takes an armored private key and the passphrase it is locked with,
// which is empty for a key that is not.
//
// Refused, naming what is wrong, where the text holds no key or more than one,
// holds a public key alone, cannot be unlocked with what was given, or has no
// key able to sign now. Each is a deployment that would start and then sign
// nothing, which nothing outside it would report until a reader noticed.
func Read(armored, passphrase string) (*Signer, error) {
	keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, errors.New("not an armored OpenPGP key")
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("holds %d keys, where one signs", len(keys))
	}
	entity := keys[0]
	if entity.PrivateKey == nil {
		return nil, errors.New("holds a public key only, which signs nothing")
	}
	if locked(entity) {
		if passphrase == "" {
			return nil, errors.New("is locked with a passphrase, and none was given")
		}
		if err := entity.DecryptPrivateKeys([]byte(passphrase)); err != nil {
			return nil, errors.New("could not be unlocked with the passphrase given")
		}
	} else if passphrase != "" {
		return nil, errors.New("is not locked, so the passphrase given unlocks nothing")
	}
	key, ok := entity.SigningKey(time.Now())
	if !ok || key.PrivateKey == nil || key.PrivateKey.Encrypted {
		return nil, errors.New("has no key able to sign now: every one has expired, been " +
			"revoked or is not for signing")
	}

	var public bytes.Buffer
	writer, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("write the public key: %w", err)
	}
	if err := entity.Serialize(writer); err != nil {
		return nil, fmt.Errorf("write the public key: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("write the public key: %w", err)
	}
	public.WriteByte('\n')
	// Valid from the latest of the key's creation and the self-signatures
	// that vouch for it now: a signature dated before the newest of those is
	// refused by the reader's library as by this one, and an operator
	// extending a key's expiry or adding a name re-signs it.
	from := key.PublicKey.CreationTime
	if key.SelfSignature != nil && key.SelfSignature.CreationTime.After(from) {
		from = key.SelfSignature.CreationTime
	}
	if primary, _ := entity.PrimarySelfSignature(); primary != nil && primary.CreationTime.After(from) {
		from = primary.CreationTime
	}
	return &Signer{
		entity: entity, from: from.UTC(),
		fingerprint: strings.ToUpper(fmt.Sprintf("%x", entity.PrimaryKey.Fingerprint)),
		public:      public.Bytes(),
	}, nil
}

// locked reports whether any private key the entity holds is locked.
func locked(entity *openpgp.Entity) bool {
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		return true
	}
	for _, sub := range entity.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			return true
		}
	}
	return false
}

// Fingerprint is the primary key's fingerprint in upper-case hexadecimal,
// which is how the provider description names it.
func (s *Signer) Fingerprint() string { return s.fingerprint }

// From is when the key that signs became valid.
func (s *Signer) From() time.Time { return s.from }

// PublicKey is the armored public key, which a reader verifies signatures
// with.
func (s *Signer) PublicKey() []byte { return s.public }

// Sign is an armored detached signature over body, dated at.
//
// Dated by what the document says rather than by the clock, and never before
// the key that signs became valid, so every signature over one revision says
// the same moment. The signature itself carries a random salt, the library's
// default: it keeps a fault during signing from leaking the key, at the cost of
// two signatures over the same bytes differing. Each verifies, which is the
// whole of what a reader asks of one.
func (s *Signer) Sign(body []byte, at time.Time) ([]byte, error) {
	if at.Before(s.from) {
		at = s.from
	}
	var out bytes.Buffer
	config := &packet.Config{Time: func() time.Time { return at }}
	if err := openpgp.ArmoredDetachSign(&out, s.entity, bytes.NewReader(body), config); err != nil {
		return nil, fmt.Errorf("sign the document: %w", err)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
