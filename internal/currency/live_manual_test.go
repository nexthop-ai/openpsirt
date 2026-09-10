package currency_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/currency"
)

// TestAgainstTheRealIndexes is the only thing here that reaches the network,
// and it is skipped unless somebody asks for it.
//
// Run with OPENPSIRT_CURRENCY_LIVE=1. It exists because the shape of what an
// index returns is not something to assume: crates.io refuses a request that
// does not say who is asking, the module proxy escapes uppercase letters, and
// PyPI dates a release by its files rather than by itself. None of that is
// visible from a specification.
func TestAgainstTheRealIndexes(t *testing.T) {
	if os.Getenv("OPENPSIRT_CURRENCY_LIVE") == "" {
		t.Skip("set OPENPSIRT_CURRENCY_LIVE=1 to ask the real indexes")
	}
	client := currency.New()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	for _, each := range []struct {
		ecosystem, name string
		wantVersion     bool
		wantDate        bool
	}{
		{"golang", "golang.org/x/net", true, true},
		// An uppercase letter in the path, which the proxy escapes.
		{"golang", "github.com/Masterminds/semver", true, true},
		{"npm", "lodash", true, true},
		{"npm", "@types/node", true, true},
		{"pypi", "requests", true, true},
		{"cargo", "serde", true, true},
	} {
		asker := client.For(each.ecosystem)
		if asker == nil {
			t.Errorf("%s has no index", each.ecosystem)
			continue
		}
		latest, err := asker.Latest(ctx, each.name)
		if err != nil {
			t.Errorf("%s %s: %v", each.ecosystem, each.name, err)
			continue
		}
		if each.wantVersion && latest.Version == "" {
			t.Errorf("%s %s: no version", each.ecosystem, each.name)
		}
		if each.wantDate && latest.Released.IsZero() {
			t.Errorf("%s %s: no date for %s", each.ecosystem, each.name, latest.Version)
		}
		t.Logf("%-6s %-30s %-24s %s", each.ecosystem, each.name, latest.Version,
			latest.Released.Format("2006-01-02"))
	}

	// Something no index has heard of is not a fault: a private module and a
	// vendored fork both look like this.
	if _, err := client.For("golang").Latest(ctx, "example.invalid/nothing/here"); err == nil {
		t.Error("a module nothing has heard of was reported as found")
	}
}
