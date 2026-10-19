// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/csaf"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// The bounds on what an upstream serves. Each is far past what a provider
// writes and far short of what would hurt to hold.
const (
	// mostDescriptionBytes bounds a provider description.
	mostDescriptionBytes = 1 << 20
	// mostListingBytes bounds a feed or a list of changes.
	mostListingBytes = 64 << 20
	// mostDocumentBytes bounds one document. The largest this deployment
	// publishes for a full-size switch image is under two kilobytes.
	mostDocumentBytes = 32 << 20
	// mostSumBytes bounds a digest file: a digest and a file name.
	mostSumBytes = 4 << 10
	// mostSignatureBytes bounds a detached signature.
	mostSignatureBytes = 64 << 10
	// mostKeyBytes bounds a public key.
	mostKeyBytes = 1 << 20
)

// unreadable is a document refused the same way every time it is asked for,
// as opposed to an upstream that could not be reached.
type unreadable struct{ err error }

func (u unreadable) Error() string { return u.err.Error() }
func (u unreadable) Unwrap() error { return u.err }

// fetch reads one address, bounded, and answers what came back. validator, where
// given, is sent as the entity tag and date the address last answered with, and
// an answer that nothing moved comes back as notModified.
func fetch(ctx context.Context, client *http.Client, address string, most int64,
	validator *cached) ([]byte, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, unreadable{err: err}
	}
	if validator != nil {
		if validator.Tag != "" {
			req.Header.Set("If-None-Match", validator.Tag)
		}
		if validator.Modified != "" {
			req.Header.Set("If-Modified-Since", validator.Modified)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	switch {
	case res.StatusCode == http.StatusNotModified && validator != nil:
		return nil, errNotModified
	case res.StatusCode == http.StatusNotFound, res.StatusCode == http.StatusGone:
		return nil, unreadable{err: fmt.Errorf("%w: %s answered %s", errGone, address, bound.Text(res.Status))}
	case res.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w: %s answered %s", errForbidden, address, bound.Text(res.Status))
	case res.StatusCode != http.StatusOK:
		return nil, refusal.Errorf("%s answered %s", address, bound.Text(res.Status))
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, most+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > most {
		return nil, unreadable{err: refusal.Errorf("%s is larger than the %d bytes this reads", address, most)}
	}
	if validator != nil {
		validator.Tag = bound.HeadRunes(bound.Text(res.Header.Get("ETag")), mostValidator)
		validator.Modified = bound.HeadRunes(bound.Text(res.Header.Get("Last-Modified")), mostValidator)
	}
	return body, nil
}

// mostValidator bounds an entity tag or a date kept to ask with again.
const mostValidator = 200

// errForbidden says an address answered 403.
var errForbidden = refusal.New("refused")

// errGone says an address answered that nothing is published there.
var errGone = refusal.New("nothing is published there")

// errNotModified says an address answered that nothing moved since it was
// last read.
var errNotModified = errors.New("not modified")

// algorithms are the digests served beside a document, by the suffix the
// standard gives each file, in the order they are asked for.
var algorithms = []struct {
	suffix string
	sum    func() hash.Hash
}{
	{".sha256", sha256.New},
	{".sha512", sha512.New},
}

// errNoDigest says no digest is served beside a document.
var errNoDigest = unreadable{err: refusal.New("no digest is served beside that document")}

// errMismatched says a document does not match the digest served beside it.
var errMismatched = unreadable{err: refusal.New("that document does not match the digest served beside it")}

// checkDigest compares a document against the digest served beside it.
//
// Required. A document whose digest is missing or disagrees is not what the
// upstream published, whether a transfer was cut or a file was replaced, and
// recorded it would stand as the upstream's word.
func checkDigest(ctx context.Context, client *http.Client, address string, body []byte) error {
	for _, kind := range algorithms {
		served, err := fetch(ctx, client, address+kind.suffix, mostSumBytes, nil)
		var refused unreadable
		switch {
		case errors.As(err, &refused), errors.Is(err, errForbidden):
			// Not served: a store answering 403 for an object it does not
			// hold is as common as 404.
			continue
		case err != nil:
			return err
		}
		sum := kind.sum()
		want, held := csaf.DigestIn(served, sum.Size())
		if !held {
			// A page in place of a digest is no digest.
			continue
		}
		sum.Write(body)
		if !bytes.Equal(sum.Sum(nil), want) {
			return errMismatched
		}
		return nil
	}
	return errNoDigest
}

// errUnsigned says a document of an upstream whose key is trusted carries no
// signature that key made.
var errUnsigned = unreadable{err: refusal.New("that document carries no signature the trusted key made")}

// checkSignature verifies the detached signature served beside a document
// against the trusted key.
func checkSignature(ctx context.Context, client *http.Client, address string, body []byte,
	keyring openpgp.EntityList) error {

	signature, err := fetch(ctx, client, address+".asc", mostSignatureBytes, nil)
	var refused unreadable
	switch {
	case errors.As(err, &refused):
		return errUnsigned
	case err != nil:
		return err
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(body),
		bytes.NewReader(signature), nil); err != nil {
		return errUnsigned
	}
	return nil
}

// keyringOf reads the armored public keys an upstream signs with and answers
// them with their fingerprints as a set.
func keyringOf(armored string) (openpgp.EntityList, string, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, "", refusal.Errorf("those public keys do not read: %v", err)
	}
	if len(keyring) == 0 || len(keyring) > MostKeys {
		return nil, "", refusal.Errorf("an upstream signs with one to %d keys, and this names %d",
			MostKeys, len(keyring))
	}
	fingerprints := make([]string, 0, len(keyring))
	for _, key := range keyring {
		fingerprints = append(fingerprints, hex.EncodeToString(key.PrimaryKey.Fingerprint))
	}
	return keyring, FingerprintOf(strings.Join(fingerprints, ",")), nil
}

// MostKeys is how many keys an upstream may sign with at once: one, and the
// one it is rotating to, with room to spare.
const MostKeys = 4

// FingerprintOf is a set of fingerprints as it is compared: each in
// upper-case hexadecimal without spaces, in order, separated by commas. A
// provider description and a person typing one each space it their own way.
func FingerprintOf(said string) string {
	var out []string
	for _, one := range strings.Split(said, ",") {
		if fingerprint := strings.ToUpper(strings.Join(strings.Fields(one), "")); fingerprint != "" {
			out = append(out, fingerprint)
		}
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), ",")
}

// errKeyMoved says an upstream names a key other than the one trusted.
var errKeyMoved = refusal.New("the upstream names a signing key other than the one trusted; " +
	"nothing is read from it until an administrator trusts it again")

// describe says what a key moving means, for the record of a pass.
func describe(offered, trusted string) error {
	switch {
	case offered == "":
		return fmt.Errorf("%w: it names no key, and %s was trusted", errKeyMoved, trusted)
	case trusted == "":
		return fmt.Errorf("%w: it names %s, and no key was trusted", errKeyMoved, offered)
	}
	return fmt.Errorf("%w: it names %s, and %s was trusted", errKeyMoved, offered, trusted)
}
