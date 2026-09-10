package version

import "testing"

func TestGetAlwaysReportsSomething(t *testing.T) {
	// An unset field would leave an operator unable to say what they are
	// running, which is the only reason this package exists.
	got := Get()
	for name, field := range map[string]string{
		"version": got.Version, "commit": got.Commit,
		"date": got.Date, "go": got.Go,
	} {
		if field == "" {
			t.Errorf("%s is empty", name)
		}
	}
}
