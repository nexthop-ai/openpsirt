package attach

import (
	"context"
	"strings"
	"testing"
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
