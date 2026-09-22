package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// Which names one upload moved. The counts on the receipt say how much and
// this says what, and an alert about a build that changed sharply is an alarm
// pointing at nothing without it.

// moved asks what one upload changed, as whoever holds secret.
func moved(t *testing.T, f *ingestFixture, secret, path string) (int, httpapi.ListedInventoryChanges) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	var out httpapi.ListedInventoryChanges
	if rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.Body); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

// reading runs the reader over whatever is queued, the way the deployment
// does after an upload is taken.
func reading(t *testing.T, f *ingestFixture) {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	reader := ingest.NewReader(f.db, f.queue, sbom.Limits{}, quiet, "test")
	if _, err := reader.Once(t.Context()); err != nil {
		t.Fatalf("reading: %v", err)
	}
}

// twoUploads files an inventory and then a second one against the same build,
// and answers which scan the second was.
func twoUploads(t *testing.T, f *ingestFixture, first, second map[string]string) int64 {
	t.Helper()
	built := nowish()
	if code, _ := f.send(t, upload(t, f.path, carrying(built, first))); code != http.StatusAccepted {
		t.Fatal("the first upload was not taken")
	}
	reading(t, f)

	code, result := f.send(t, upload(t, f.path, carrying(built.Add(time.Minute), second)))
	if code != http.StatusAccepted {
		t.Fatal("the second upload was not taken")
	}
	reading(t, f)
	return result.ScanID
}

func TestAnUploadSaysWhichNamesItMoved(t *testing.T) {
	// The count says a build moved seven names and this says which seven. A
	// removal is the row worth reading first: a build that stopped describing
	// a dependency looks exactly like one that stopped shipping it.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		scanID := twoUploads(t, f,
			map[string]string{"libc6": "2.41", "zlib1g": "1.3"},
			map[string]string{"libc6": "2.41", "curl": "8.4.0"})

		code, out := moved(t, f, f.key, f.path+"/"+strconv.FormatInt(scanID, 10)+"/changes")
		if code != http.StatusOK {
			t.Fatalf("reading what the upload changed returned %d", code)
		}
		if out.Body.Total != 2 || len(out.Body.Items) != 2 {
			t.Fatalf("got %d rows (total %d), want 2: %+v",
				len(out.Body.Items), out.Body.Total, out.Body.Items)
		}
		gone := out.Body.Items[0]
		if gone.Name != "zlib1g" || gone.Change != "removed" ||
			strings.Join(gone.Before, ",") != "1.3" || len(gone.After) != 0 {
			t.Errorf("the first row is %+v, want zlib1g removed at 1.3", gone)
		}
		came := out.Body.Items[1]
		if came.Name != "curl" || came.Change != "added" ||
			len(came.Before) != 0 || strings.Join(came.After, ",") != "8.4.0" {
			t.Errorf("the second row is %+v, want curl arriving at 8.4.0", came)
		}
	})
}

func TestTheListingAndTheReceiptSayTheSameThing(t *testing.T) {
	// One comparison read twice. A screen that disagreed with the number
	// beside it leaves a reader with two answers and no way to tell which is
	// the build's.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		scanID := twoUploads(t, f,
			map[string]string{"libc6": "2.41", "zlib1g": "1.3", "curl": "8.4.0"},
			map[string]string{"libc6": "2.42", "zlib1g": "1.4", "openssl": "3.0.11"})

		_, listed := moved(t, f, f.key, f.path+"/"+strconv.FormatInt(scanID, 10)+"/changes")
		counted := map[string]int{}
		for _, row := range listed.Body.Items {
			counted[row.Change]++
		}

		_, receipt := receipts(t, f, f.key, f.path)
		if len(receipt.Body.Items) == 0 || receipt.Body.Items[0].Inventory == nil {
			t.Fatalf("the receipt says nothing about what the upload changed: %+v", receipt.Body.Items)
		}
		says := *receipt.Body.Items[0].Inventory
		if counted["added"] != says.Added || counted["removed"] != says.Removed ||
			counted["changed"] != says.Changed {
			t.Errorf("the listing is %v and the receipt says %+v", counted, says)
		}
	})
}

func TestOneKindOfChangeIsAskableOnItsOwn(t *testing.T) {
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		scanID := twoUploads(t, f,
			map[string]string{"libc6": "2.41", "zlib1g": "1.3"},
			map[string]string{"libc6": "2.42", "curl": "8.4.0"})

		at := f.path + "/" + strconv.FormatInt(scanID, 10) + "/changes"
		code, out := moved(t, f, f.key, at+"?change=changed")
		if code != http.StatusOK {
			t.Fatalf("asking for one kind returned %d", code)
		}
		if out.Body.Total != 1 || len(out.Body.Items) != 1 ||
			out.Body.Items[0].Name != "libc6" || out.Body.Items[0].Change != "changed" {
			t.Errorf("asked for what moved version, got %+v (total %d)",
				out.Body.Items, out.Body.Total)
		}
	})
}

func TestTheFirstUploadChangedNothingToList(t *testing.T) {
	// It is the first picture of a build rather than a change to one, so the
	// answer is nothing rather than every name in it.
	eachIngest(t, queue.DefaultOptions(), func(t *testing.T, f *ingestFixture) {
		code, result := f.send(t, upload(t, f.path, carrying(nowish(),
			map[string]string{"libc6": "2.41", "zlib1g": "1.3"})))
		if code != http.StatusAccepted {
			t.Fatal("the upload was not taken")
		}
		reading(t, f)

		code, out := moved(t, f, f.key,
			f.path+"/"+strconv.FormatInt(result.ScanID, 10)+"/changes")
		if code != http.StatusOK {
			t.Fatalf("reading the first upload returned %d", code)
		}
		if out.Body.Total != 0 || len(out.Body.Items) != 0 {
			t.Errorf("the first upload listed %+v", out.Body.Items)
		}
	})
}
