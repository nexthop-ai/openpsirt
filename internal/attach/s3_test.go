// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// An endpoint reached in the clear is refused unless it reaches no further than
// this machine, or an operator has said which network they accept it on.
//
// The rule exists because an attachment is delivered as a redirect to a signed
// address, so the address is a bearer token that travels to a browser. Nothing
// here asks a store anything: what is being pinned is which configurations are
// allowed to exist at all, which is decided before a request is ever made.
func TestPlaintextEndpointNeedsSayingSo(t *testing.T) {
	for _, each := range []struct {
		name     string
		endpoint string
		allow    bool
		refused  bool
		clear    bool
	}{
		{name: "https is the ordinary case", endpoint: "https://objects.example.com"},
		{name: "https is unaffected by the allowance", endpoint: "https://objects.example.com",
			allow: true},
		{name: "plain http across a network is refused",
			endpoint: "http://objects.example.com", refused: true},
		{name: "plain http to a private address is refused too",
			endpoint: "http://10.4.1.9:9000", refused: true},
		{name: "loopback needs no allowance", endpoint: "http://127.0.0.1:9000", clear: false},
		{name: "loopback by name needs none either", endpoint: "http://localhost:9000"},
		// Loopback is the whole of 127.0.0.0/8 and the IPv6 forms. Giving a
		// local store its own loopback address is ordinary.
		{name: "a local store on its own loopback address", endpoint: "http://127.0.0.2:9000"},
		{name: "loopback written as IPv6", endpoint: "http://[::1]:9000"},
		{name: "loopback written as an IPv4-mapped IPv6 literal",
			endpoint: "http://[::ffff:127.0.0.1]:9000"},
		// And the addresses this is actually about are still refused: a
		// private address is somebody else's network, not this machine.
		{name: "a private address is not loopback",
			endpoint: "http://192.168.1.10:9000", refused: true},
		{name: "another private range is not loopback either",
			endpoint: "http://172.16.4.2:9000", refused: true},
		{name: "the allowance is what admits a network",
			endpoint: "http://objects.example.com", allow: true, clear: true},
		{name: "no endpoint at all is a cloud provider", endpoint: ""},
	} {
		t.Run(each.name, func(t *testing.T) {
			bucket, err := NewBucket(context.Background(), BucketConfig{
				Endpoint:  each.endpoint,
				Bucket:    "attachments",
				Region:    "us-east-1",
				Key:       "key",
				Secret:    "secret",
				AllowHTTP: each.allow,
			})
			if each.refused {
				if err == nil {
					t.Fatalf("%q was accepted, and it crosses a network in the clear", each.endpoint)
				}
				if !strings.Contains(err.Error(), "must be https") {
					t.Fatalf("refused for the wrong reason: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q was refused: %v", each.endpoint, err)
			}
			if bucket == nil {
				t.Fatal("no store was built")
			}
			if bucket.InTheClear() != each.clear {
				t.Fatalf("reported in the clear as %v, wanted %v", bucket.InTheClear(), each.clear)
			}
		})
	}
}

// The names the directory store is configured by.
var directoryNames = SettingNames{ //nolint:gosec // G101: the names of settings, not their values
	AllowHTTP: "OPENPSIRT_DIRECTORY_ALLOW_HTTP", Key: "OPENPSIRT_DIRECTORY_KEY",
	Secret: "OPENPSIRT_DIRECTORY_SECRET", Token: "OPENPSIRT_DIRECTORY_SESSION_TOKEN",
}

// Credentials configured by halves are refused, naming the store's own
// settings, rather than dropped in favor of whatever identity the environment
// offers.
func TestHalfACredentialIsRefused(t *testing.T) {
	for _, each := range []struct {
		name                     string
		endpoint                 string
		key, secret, token, says string
	}{
		{name: "a key alone", key: "key", says: "OPENPSIRT_DIRECTORY_KEY and OPENPSIRT_DIRECTORY_SECRET"},
		{name: "a secret alone", secret: "secret", says: "OPENPSIRT_DIRECTORY_KEY and OPENPSIRT_DIRECTORY_SECRET"},
		{name: "a key and a blank secret", key: "key", secret: "  ",
			says: "OPENPSIRT_DIRECTORY_KEY and OPENPSIRT_DIRECTORY_SECRET"},
		{name: "a token alone", token: "token", says: "OPENPSIRT_DIRECTORY_SESSION_TOKEN is set without"},
		{name: "a whole pair", key: "key", secret: "secret"},
		{name: "a whole pair and a token", key: "key", secret: "secret", token: "token"},
		{name: "a token beside a name in the endpoint", token: "token",
			endpoint: (&url.URL{Scheme: "http", User: url.UserPassword("name", "word"), Host: "127.0.0.1:9000"}).String()},
		{name: "nothing, which is the environment's identity"},
	} {
		t.Run(each.name, func(t *testing.T) {
			_, err := NewBucket(context.Background(), BucketConfig{
				Endpoint: each.endpoint, Bucket: "advisories", Region: "us-east-1",
				Key: each.key, Secret: each.secret, Token: each.token,
				Names: directoryNames,
			})
			if each.says == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted, and the configured credential would go unused")
			}
			if !strings.Contains(err.Error(), each.says) {
				t.Fatalf("the refusal does not name the settings: %v", err)
			}
		})
	}
}

// The refusal of a plaintext endpoint names the allowance of the store it is
// about, since the attachment and directory stores are allowed separately.
func TestThePlaintextRefusalNamesItsOwnStore(t *testing.T) {
	_, err := NewBucket(context.Background(), BucketConfig{
		Endpoint: "http://objects.example.com", Bucket: "advisories", Region: "us-east-1",
		Names: directoryNames,
	})
	if err == nil || !strings.Contains(err.Error(), "set OPENPSIRT_DIRECTORY_ALLOW_HTTP") {
		t.Fatalf("refused as %v", err)
	}
}

// Naming no bucket turns attachments off rather than building a store that
// cannot answer.
func TestNoBucketIsNoStore(t *testing.T) {
	bucket, err := NewBucket(context.Background(), BucketConfig{Bucket: "  "})
	if err != nil {
		t.Fatalf("naming no bucket is not an error: %v", err)
	}
	if bucket != nil {
		t.Fatal("a store was built for no bucket")
	}
}

// A plaintext store takes a body it cannot rewind.
//
// An upload is streamed through two digests on its way in, so what reaches the
// client is a reader with no Seek. Over https the request carries a trailing
// checksum, which a stream satisfies; over http the client hashes the body
// before sending it unless told the payload is unsigned. The server here is on
// a loopback address, which is the development store.
func TestAPlaintextStoreTakesAStreamedBody(t *testing.T) {
	held := map[string][]byte{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			held[r.URL.Path] = body
		case http.MethodGet:
			body, ok := held[r.URL.Path]
			if !ok {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
				return
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			delete(held, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	bucket, err := NewBucket(ctx, BucketConfig{
		Endpoint: server.URL, Bucket: "attachments", Region: "us-east-1",
		Key: "key", Secret: "secret", PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	const key, content = "attachments/ab/cd/abcd", "the bytes of a file"
	// No Seek: the shape the upload path hands over.
	streamed := io.MultiReader(strings.NewReader(content))
	if err := bucket.Put(ctx, key, streamed, int64(len(content)), "text/plain"); err != nil {
		t.Fatalf("a streamed body was refused: %v", err)
	}
	read, err := bucket.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(read)
	_ = read.Close()
	if err != nil || string(got) != content {
		t.Fatalf("read back %q, %v", got, err)
	}
	link, err := bucket.URLFor(ctx, key, time.Minute, `attachment; filename="a"`, "text/plain")
	if err != nil || !strings.HasPrefix(link, server.URL+"/attachments/"+key+"?") {
		t.Fatalf("signed %q, %v", link, err)
	}
	if err := bucket.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := bucket.Open(ctx, key); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("a removed object read back as %v", err)
	}
	if err := bucket.Reachable(ctx); err != nil {
		t.Fatal(err)
	}
	// Exactly the declared length, as Storage.Put says.
	for body, declared := range map[string]int64{"abc": 4, "abcde": 4} {
		if err := bucket.Put(ctx, "wrong-length", io.MultiReader(strings.NewReader(body)),
			declared, "text/plain"); err == nil {
			t.Fatalf("%d bytes were stored where %d were declared", len(body), declared)
		}
	}
}
