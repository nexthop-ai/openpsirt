// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach_test

import (
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
)

// An object store serves a downloaded file itself, through a signed address
// that carries the disposition and type this application decided. The store
// would otherwise serve the bytes under whatever the object says, and an
// uploaded page served inline from it runs as a page. An inline image is
// carried from here, and a redacted file is given no address at all.
func TestAnObjectStoreServesADownloadAsAnAttachmentByASignedAddress(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		bucket, served := attach.ObjectStore(t)
		store := attach.NewStore(f.db.DB, bucket)
		who := f.who(t, access.PublicTriage)
		upload := func(name string, body []byte) *attach.Attachment {
			t.Helper()
			row, err := store.Upload(ctx, who, attach.Against{ProductID: f.product, VulnerabilityID: f.issue},
				name, strings.NewReader(string(body)), int64(len(body)), roomy, plenty, plenty, false)
			if err != nil {
				t.Fatalf("upload %s: %v", name, err)
			}
			return row
		}

		logged := upload(`crash "dump".log`, []byte("a log somebody attached"))
		row, address, body, err := store.Fetch(ctx, who, logged.Token, time.Minute)
		if err != nil {
			t.Fatalf("fetch a download: %v", err)
		}
		if body != nil {
			_ = body.Close()
			t.Error("a download from an object store was carried from here")
		}
		if !strings.HasPrefix(address, served+"/") {
			t.Fatalf("a download was sent to %q, which is not the store", address)
		}
		signed, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}
		query := signed.Query()
		if got, want := query.Get("response-content-disposition"),
			`attachment; filename="`+attach.SafeName(logged.Filename)+`"`; got != want {
			t.Errorf("the signed address says disposition %q, want %q", got, want)
		}
		if got := query.Get("response-content-type"); got == "" || got != row.ContentType {
			t.Errorf("the signed address says type %q, and the file is %q", got, row.ContentType)
		}

		image := upload("diagram.png", onePixelPNG)
		row, address, body, err = store.Fetch(ctx, who, image.Token, time.Minute)
		if err != nil {
			t.Fatalf("fetch an image: %v", err)
		}
		if address != "" {
			t.Errorf("an image shown in the page was sent to %q", address)
		}
		if body == nil {
			t.Fatal("an image shown in the page came back with nothing to serve")
		}
		got, err := io.ReadAll(body)
		_ = body.Close()
		if err != nil || string(got) != string(onePixelPNG) {
			t.Errorf("an image was served as %d bytes, %v", len(got), err)
		}
		if disposition := attach.Disposition(row); !strings.HasPrefix(disposition, "inline;") {
			t.Errorf("an image is served with disposition %q", disposition)
		}

		redacted := upload("a-credential.log", []byte("removed on purpose"))
		if err := store.Redact(ctx, f.admin(t), redacted.Token, "a credential"); err != nil {
			t.Fatalf("redact: %v", err)
		}
		_, address, body, err = store.Fetch(ctx, who, redacted.Token, time.Minute)
		if !errors.Is(err, attach.ErrGone) || address != "" || body != nil {
			t.Errorf("a redacted file was fetched as address %q, body %v, %v", address, body != nil, err)
		}
	})
}
