package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/attach"
)

// An endpoint carrying credentials, which is what an operator may write and
// what neither a refusal nor a notice may repeat. Assembled rather than
// written out, so that a scanner looking for secrets in this tree does not
// find one here and a reader is not taught to ignore it where it does.
const password = "hunter2"

var withPassword = "http://minio:" + password + "@minio.internal:9000"

// What a plaintext store costs is said at every start.
//
// The refusal that governs which endpoints may exist is pinned where it is
// made. This pins the other half: a deployment that lifted the refusal is told
// so, and told without the password that reaching the store may have needed.
func TestAPlaintextStoreSaysSoAtEveryStart(t *testing.T) {
	for _, each := range []struct {
		name     string
		endpoint string
		allow    bool
		warned   bool
		says     string
		omits    string
	}{
		{name: "https says nothing", endpoint: "https://objects.example.com"},
		{name: "loopback says nothing", endpoint: "http://127.0.0.1:9000"},
		{name: "a cloud provider says nothing", endpoint: ""},
		{
			name: "an allowed network is named", endpoint: "http://minio.internal:9000",
			allow: true, warned: true, says: "minio.internal:9000",
		},
		{
			// An operator may write the credentials into the endpoint, and a
			// warning at every start would otherwise write them to the log at
			// every start.
			name: "the password in an endpoint is not logged", allow: true, warned: true,
			endpoint: withPassword, says: "minio.internal:9000", omits: password,
		},
	} {
		t.Run(each.name, func(t *testing.T) {
			bucket, err := attach.NewBucket(context.Background(), attach.BucketConfig{
				Endpoint:  each.endpoint,
				Bucket:    "attachments",
				Region:    "us-east-1",
				Key:       "key",
				Secret:    "secret",
				AllowHTTP: each.allow,
			})
			if err != nil {
				t.Fatalf("%q was refused: %v", each.endpoint, err)
			}
			var said bytes.Buffer
			noteStoreInTheClear(bucket, slog.New(slog.NewTextHandler(&said, nil)))
			warned := strings.Contains(said.String(), "cross the network in the clear")
			if warned != each.warned {
				t.Fatalf("warned %v, wanted %v: %s", warned, each.warned, said.String())
			}
			if each.says != "" && !strings.Contains(said.String(), each.says) {
				t.Fatalf("the warning does not name the store: %s", said.String())
			}
			if each.omits != "" && strings.Contains(said.String(), each.omits) {
				t.Fatalf("the warning carries a password: %s", said.String())
			}
		})
	}
}

// A refusal names the setting that accepts the endpoint it refused, and names
// it the way somebody sets it. Whoever meets this is the operator a plaintext
// store was allowed for, and a refusal saying only what is forbidden leaves
// them to find the way through by reading the source.
func TestTheRefusalNamesTheWayThrough(t *testing.T) {
	_, err := attach.NewBucket(context.Background(), attach.BucketConfig{
		Endpoint: withPassword,
		Bucket:   "attachments",
		Region:   "us-east-1",
	})
	if err == nil {
		t.Fatal("a plaintext endpoint across a network was accepted")
	}
	if !strings.Contains(err.Error(), "OPENPSIRT_ATTACHMENT_ALLOW_HTTP") {
		t.Fatalf("the refusal does not name the setting: %v", err)
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("the refusal carries a password: %v", err)
	}
}
