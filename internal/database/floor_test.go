package database_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// TooOldURLEnv points at a server deliberately older than the floor, so the
// refusal is proved against a real server rather than against arithmetic.
const TooOldURLEnv = "OPENPSIRT_TEST_TOO_OLD_URL"

func TestOpenRefusesAServerBelowTheFloor(t *testing.T) {
	url := os.Getenv(TooOldURLEnv)
	if url == "" {
		t.Skipf("%s is not set, so the refusal is untested here", TooOldURLEnv)
	}
	target, err := database.ParseURL(url)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	db, err := database.Open(context.Background(), target)
	if err == nil {
		_ = db.Close()
		t.Fatalf("an unsupported server was accepted: %s %s", db.Server.Engine, db.Server.Version)
	}
	// The message has to say what is wrong and what would be acceptable, or an
	// operator is left guessing at an unexplained startup failure.
	for _, want := range []string{"too old", "required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	t.Logf("refused as intended: %v", err)
}
