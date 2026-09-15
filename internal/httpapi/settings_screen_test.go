package httpapi

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// What a value is, said once.
//
// It was five tables keyed on setting names — the server's own, and three in
// `Settings.tsx` — and a setting added to one and not the others rendered as a
// raw text field somebody typed a refused value into: 26214400 by hand, where
// the mistake available is a factor of a thousand, which is the reason the
// composing exists. The pairing test that stood here checked the copies
// against each other, which is the shape a rule takes when it has two homes.
//
// The kind is served now, so the screen has nothing to key on a name. What is
// left to hold is that it stays that way.
func TestTheScreenTakesWhatAValueIsFromTheServer(t *testing.T) {
	screen, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "screens", "Settings.tsx"))
	if err != nil {
		t.Skipf("the interface is not in this checkout: %v", err)
	}
	body := string(screen)

	// It reads the kind rather than deciding it.
	if !strings.Contains(body, "setting.kind") {
		t.Error("the settings screen does not read the kind the server serves")
	}

	// And it holds no collection keyed on setting names, which is the shape
	// the three tables took. **Naming a setting is not the same thing**: the
	// screen groups settings into cards and gives them labels, and which card
	// a setting is drawn in is a judgment about the screen. What must not come
	// back is a *lookup* that answers what a value is.
	for _, shape := range []*regexp.Regexp{
		regexp.MustCompile(`new Set\(\[[^]]*"[a-z][a-z0-9]*[.-]`),
		regexp.MustCompile(`Record<string, string\[\]>`),
	} {
		if at := shape.FindString(body); at != "" {
			t.Errorf("the settings screen declares %q, which is a table keyed on a setting "+
				"name coming back — the server serves what the value is", at)
		}
	}
	// It reads the words a word setting takes rather than listing them, for
	// the same reason: an offered word the write path refuses is what a second
	// copy produces.
	if !strings.Contains(body, "setting.words") && !strings.Contains(body, "words") {
		t.Error("the settings screen does not read the words a word setting takes")
	}

	// The sanity check that this read the right file at all.
	if !strings.Contains(body, "settings") {
		t.Fatal("the file read does not look like the settings screen")
	}
}

// A setting that calls itself a whole number is checked as one.
//
// The description and the kind are two statements about one setting, written
// in different places by different people. Disagreeing, a whole number was
// validated as a length of time with the suite green and every value an
// operator typed refused.
//
// One direction only. A description that says "a whole number" is a promise to
// an operator and has to hold; a count described without that phrase is prose
// somebody chose, and requiring the phrase would be a rule about wording.
func TestASettingThatCallsItselfANumberIsCheckedAsOne(t *testing.T) {
	said := 0
	for _, each := range settable {
		if !strings.Contains(each.means, "A whole number") {
			continue
		}
		said++
		if each.kind != aCount && each.kind != aSize {
			t.Errorf("%s is offered as a whole number and checked as %q, so every "+
				"number an operator types is refused", each.name, each.kind)
		}
	}
	if said == 0 {
		t.Error("no setting describes itself as a whole number, so this checked nothing")
	}
}

// TestEverySettingOfferedReportsWhatIsInForce is the guard that stops the
// twenty-eighth setting being added without a default.
//
// `shipped()` was a 22-arm switch with a bare `return ""`, beside a list of 27
// names — so the three disclosure settings reported blank on the administration
// screen while 90 days, 30 days and 14 days were what the deployment enforced.
// An operator reading the blank as "unset" read it as "nothing applies".
func TestEverySettingOfferedReportsWhatIsInForce(t *testing.T) {
	if len(settable) < 20 {
		t.Fatalf("%d settings are offered, so this checked almost nothing", len(settable))
	}
	for _, each := range settable {
		if each.shipped == nil {
			t.Errorf("%s is offered with nothing to report where nobody has set it", each.name)
			continue
		}
		// The environment is what a sign-in's length falls back to before the
		// built-in, so the row is asked with one that has it set.
		value := each.shipped(Ingest{SessionLifetime: 5 * time.Hour})
		if strings.TrimSpace(value) == "" {
			t.Errorf("%s reports an empty shipped value, which reads as nothing applying",
				each.name)
		}
		// And it is the kind the write path will check it as, or an operator
		// pressing the value back is refused their own deployment's default.
		switch each.kind {
		case aDuration:
			if d, err := time.ParseDuration(value); err != nil || d <= 0 {
				t.Errorf("%s ships %q, which the write path refuses as a length of time",
					each.name, value)
			}
		case aCount, aSize:
			if n, err := strconv.Atoi(value); err != nil || n <= 0 {
				t.Errorf("%s ships %q, which the write path refuses as a count",
					each.name, value)
			}
		case aWord:
			if !slices.Contains(theFloor, value) {
				t.Errorf("%s ships %q, which is not one of the words it takes", each.name, value)
			}
		case aSwitch:
			if !slices.Contains(theSwitch, value) {
				t.Errorf("%s ships %q, which is neither on nor off", each.name, value)
			}
		default:
			t.Errorf("%s is of kind %q, which nothing checks", each.name, each.kind)
		}
	}
}

func TestASignInsLengthReportsWhatTheDeploymentSet(t *testing.T) {
	// It reported the built-in twelve hours whatever the environment said, so
	// the screen contradicted the deployment about its own configuration.
	row, found := settingRow(setting.SessionLifetime)
	if !found {
		t.Fatal("a sign-in's length is not offered")
	}
	if got := settable[row].shipped(Ingest{SessionLifetime: 5 * time.Hour}); got != "5h0m0s" {
		t.Errorf("with the environment set to 5h, the screen reports %q", got)
	}
	if got := settable[row].shipped(Ingest{}); got != access.DefaultSessionLifetime.String() {
		t.Errorf("with nothing set, the screen reports %q rather than the built-in", got)
	}
}
