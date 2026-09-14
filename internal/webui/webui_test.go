package webui_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/webui"
)

// Whether this binary carries an interface, said rather than inferred.
//
// Both answers used to be nil, returned from two different failures and
// written nowhere: the caller passed it straight into the server unchecked, so
// a build whose interface could not be read at all was indistinguishable from
// an API-only build, and both were silent.
//
// Which of the two this binary is depends on whether the frontend was built
// before the tests ran, so the test asserts the pair rather than one of them:
// either there is a filesystem and no error, or there is an error saying
// which state it is and no filesystem.
func TestTheInterfaceIsEitherThereOrSaysWhyNot(t *testing.T) {
	pages, err := webui.Files()
	switch {
	case err == nil:
		if pages == nil {
			t.Fatal("no error and no filesystem, which is the state that used to be silent")
		}
		if _, err := pages.Open("index.html"); err != nil {
			t.Errorf("the interface was answered and has no page to serve: %v", err)
		}
	case errors.Is(err, webui.ErrNoInterface):
		if pages != nil {
			t.Error("this binary has no interface and answered a filesystem anyway")
		}
	default:
		t.Fatalf("the interface could not be read and the reason is not one this "+
			"names: %v", err)
	}
}
