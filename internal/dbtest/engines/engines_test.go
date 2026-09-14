package engines

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A name no engine answers to used to narrow the run to nothing, and nothing
// told the two apart.
//
// The wanted set is intersected with the engines a test can reach, so
// "postgress" or "sqllite" intersects with nothing: every database test skips
// with a message that reads like a deliberate narrowing, and the process exits
// 0 having touched no database at all. The one distinction the harness does
// make — nothing configured at all is a failure — is exactly the one that does
// not fire, because something *was* configured.
func TestAnEngineNameNothingAnswersToIsRefused(t *testing.T) {
	for _, name := range []string{"postgress", "sqllite", "maria", "mysql,postgres,typo"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(Env, name)
			defer func() {
				said, panicked := recover().(string)
				if !panicked {
					t.Fatalf("%s=%q was accepted, so every engine is excluded "+
						"and every database test skips green", Env, name)
				}
				if !strings.Contains(said, Env) {
					t.Errorf("the refusal does not name %s: %s", Env, said)
				}
				for _, engine := range database.Engines() {
					if !strings.Contains(said, engine.String()) {
						t.Errorf("the refusal does not say %s is legal: %s", engine, said)
					}
				}
			}()
			Selected()
		})
	}
}

// Every engine's own name is accepted, in any capitalization and with spaces
// around it, which is what the refusal above must not catch.
func TestEveryEngineNameIsAccepted(t *testing.T) {
	for _, engine := range database.Engines() {
		t.Run(engine.String(), func(t *testing.T) {
			t.Setenv(Env, " "+strings.ToUpper(engine.String())+" ")
			wanted := Selected()
			if !wanted[engine] {
				t.Errorf("%s names %s and it was not selected: %v", Env, engine, wanted)
			}
			if len(wanted) != 1 {
				t.Errorf("%s names %s alone and %v were selected", Env, engine, wanted)
			}
		})
	}
}

// Unset means every engine that is configured, which is a different answer
// from "these engines" and has to stay distinguishable from it.
func TestNothingNamedSelectsEveryEngine(t *testing.T) {
	t.Setenv(Env, "")
	if wanted := Selected(); wanted != nil {
		t.Errorf("%s is unset and Selected answered %v rather than every engine", Env, wanted)
	}
}
