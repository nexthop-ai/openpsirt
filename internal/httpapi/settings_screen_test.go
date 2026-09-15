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

// A setting checked here as a number is one the screen composes as a number.
//
// The two are the same fact in two languages. Everything else here is a
// duration, which the screen composes without being told — so a setting that
// is a count or a size and is not named on that side renders as a raw field:
// 26214400 typed by hand, where the mistake available is a factor of a
// thousand, which is the reason the composing exists.
//
// Both settings this branch added were missing on the screen's side, so this
// checks the pair rather than either list. The card *heading* is not checked:
// which group a setting is drawn in is a judgment about the screen, and a
// proxy for it here would be a rule about nothing.
func TestASettingCheckedAsANumberIsComposedAsOne(t *testing.T) {
	screen, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "screens", "Settings.tsx"))
	if err != nil {
		t.Skipf("the interface is not in this checkout: %v", err)
	}
	body := string(screen)

	named := func(declaration string) map[string]bool {
		at := strings.Index(body, declaration)
		if at < 0 {
			t.Fatalf("the screen no longer declares %q, so this checks nothing", declaration)
		}
		end := strings.Index(body[at:], ";")
		if end < 0 {
			t.Fatalf("%q is not a declaration this can read", declaration)
		}
		out := map[string]bool{}
		for _, quoted := range regexp.MustCompile(`"([a-z0-9.-]+)"`).
			FindAllStringSubmatch(body[at:at+end], -1) {
			out[quoted[1]] = true
		}
		return out
	}
	composed := named("const counts = new Set(")
	for name := range named("const sizes = new Set(") {
		composed[name] = true
	}

	// A setting absent from both lists passes the pairing below, because the
	// pairing only sees disagreement. That is how a whole number came to be
	// validated as a length of time with the suite green and every value an
	// operator typed refused, so the description is read as well: a setting
	// that calls itself a whole number is checked as one.
	for _, each := range settable {
		if strings.Contains(each.means, "A whole number") && each.kind != aCount {
			t.Errorf("%s is offered as a whole number and the write path checks it as a "+
				"length of time, so every number an operator types is refused", each.name)
		}
	}

	for _, each := range settable {
		if each.kind == aCount && !composed[each.name] {
			t.Errorf("%s is checked as a number here and the screen draws it as a raw text "+
				"field, which is where a factor of a thousand comes from", each.name)
		}
		if each.kind != aCount && composed[each.name] {
			t.Errorf("%s is composed as a number on the screen and checked as something else "+
				"here, so what the screen offers is refused", each.name)
		}
	}
	// And nothing the screen composes is a name this deployment does not
	// offer at all, which would be a rule about nothing.
	offered := map[string]bool{}
	for _, each := range settable {
		offered[each.name] = true
	}
	for name := range composed {
		if !offered[name] {
			t.Errorf("the screen composes %q as a number and no setting of that name is offered", name)
		}
	}
	// The sanity check that this is reading the right file at all.
	if !composed[setting.TogetherCap] {
		t.Fatal("the screen composes no count at all, so this read the wrong thing")
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
		case aCount:
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
