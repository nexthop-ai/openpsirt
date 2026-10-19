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
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/nexthop-ai/openpsirt/internal/bound"
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
		case errors.As(err, &refused):
			continue
		case err != nil:
			return err
		}
		fields := strings.Fields(string(served))
		if len(fields) == 0 {
			continue
		}
		want, err := hex.DecodeString(fields[0])
		sum := kind.sum()
		sum.Write(body)
		if err != nil || !bytes.Equal(sum.Sum(nil), want) {
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

// keyringOf reads an armored public key and answers it with its fingerprint,
// in upper-case hexadecimal.
func keyringOf(armored string) (openpgp.EntityList, string, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, "", refusal.Errorf("that public key does not read: %v", err)
	}
	if len(keyring) != 1 {
		return nil, "", refusal.Errorf("a public key file holds one key, and this holds %d", len(keyring))
	}
	return keyring, FingerprintOf(hex.EncodeToString(keyring[0].PrimaryKey.Fingerprint)), nil
}

// FingerprintOf is a fingerprint as it is compared: upper-case hexadecimal,
// without spaces. A provider description and a person typing one each space
// it their own way.
func FingerprintOf(said string) string {
	return strings.ToUpper(strings.Join(strings.Fields(said), ""))
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
