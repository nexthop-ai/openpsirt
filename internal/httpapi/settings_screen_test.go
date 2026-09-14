package httpapi

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
		if strings.Contains(each.means, "A whole number") && !aCount(each.name) {
			t.Errorf("%s is offered as a whole number and the write path checks it as a "+
				"length of time, so every number an operator types is refused", each.name)
		}
	}

	for _, each := range settable {
		if aCount(each.name) && !composed[each.name] {
			t.Errorf("%s is checked as a number here and the screen draws it as a raw text "+
				"field, which is where a factor of a thousand comes from", each.name)
		}
		if !aCount(each.name) && composed[each.name] {
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
