package webui_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/webui"
)

// An interface in the binary is said rather than inferred.
//
// Two different failures, and a caller that passes the result straight into
// the server: answering both with nothing makes a build whose interface cannot
// be read indistinguishable from an API-only build, and both silent.
//
// Which of the two this binary is depends on whether the frontend was built
// before the tests ran, so the test asserts the pair rather than one of them:
// either there is a filesystem and no error, or there is an error naming the
// state and no filesystem.
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
