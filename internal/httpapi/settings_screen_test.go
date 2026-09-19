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
// Five tables keyed on setting names — the server's own, and three in
// `Settings.tsx` — render a setting added to one and not the others as a raw
// text field somebody types a refused value into: 26214400 by hand, where the
// mistake available is a factor of a thousand. A test pairing the copies
// against each other is the shape a rule takes when it has two homes.
//
// The kind is served, so the screen has nothing to key on a name. What is left
// to hold is that it stays that way.
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
	// the three tables took. Naming a setting is not the same thing: the
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
	if !strings.Contains(body, "setting.words") {
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

func TestAWordSettingOffersTheListItIsCheckedAgainst(t *testing.T) {
	// The offered list and the accepted list were two tables keyed on the
	// setting's name, so the second word setting anybody adds is offered
	// nothing and then checked against the triage floor's words.
	said := 0
	for _, each := range settable {
		switch each.kind {
		case aWord, aSwitch:
			said++
			if len(each.words) == 0 {
				t.Errorf("%s takes one of a few words and offers none", each.name)
			}
			// The shipped value has to be one of them, or an operator
			// pressing their own default back is refused it.
			if !slices.Contains(each.words, each.shipped(Ingest{})) {
				t.Errorf("%s ships %q, which is not one of %v",
					each.name, each.shipped(Ingest{}), each.words)
			}
		default:
			if len(each.words) != 0 {
				t.Errorf("%s is a %s and offers words, which nothing checks against",
					each.name, each.kind)
			}
		}
	}
	if said < 2 {
		t.Errorf("%d settings take a word, so this checked almost nothing", said)
	}
}

func TestEverySettingNameThePackageDeclaresIsOfferedOrExempt(t *testing.T) {
	// The three disclosure settings were read by the application and could not
	// be set, and nothing caught it because the test named them by hand — so
	// the twenty-eighth would have gone the same way.
	//
	// Read out of the package that declares them, the way the rollback test in
	// this same branch reads `dbtest.Tables()`: a name added there and left out
	// of `settable` fails this rather than waiting for somebody to notice.
	source, err := os.ReadFile(filepath.Join("..", "setting", "setting.go"))
	if err != nil {
		t.Fatal(err)
	}
	// A name, not a value: every setting is named in dotted parts, and the
	// only constants here that are not are `on` and `off` — what a switch
	// setting may be set to rather than a setting.
	declared := map[string]bool{}
	for _, found := range regexp.MustCompile(`\n\t([A-Z][A-Za-z]*)\s*=\s*"([a-z0-9-]+(?:\.[a-z0-9-]+)+)"`).
		FindAllStringSubmatch(string(source), -1) {
		declared[found[2]] = true
	}
	if len(declared) < 20 {
		t.Fatalf("%d setting names were read out of the package, so this checked almost nothing",
			len(declared))
	}

	// The two an operator does not set here, each for a reason.
	exempt := map[string]string{
		"roles.mode": "set through /v1/roles/mode, which refuses a mode nothing " +
			"can derive roles in — a plain value write cannot ask that",
		"signin.key": "generated and rotated by the deployment; an operator " +
			"setting one would be choosing this deployment's signing key",
	}
	offered := map[string]bool{}
	for _, each := range settable {
		offered[each.name] = true
	}
	for name := range declared {
		if offered[name] || exempt[name] != "" {
			continue
		}
		t.Errorf("%s is declared as a setting and is neither offered nor exempt: "+
			"add it to settable with its kind and shipped value, or say here why not", name)
	}
	for name, why := range exempt {
		if !declared[name] {
			t.Errorf("%s is exempt (%s) and no longer declared", name, why)
		}
		if offered[name] {
			t.Errorf("%s is exempt (%s) and is offered anyway", name, why)
		}
	}
}
