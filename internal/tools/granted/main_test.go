package main

import "testing"

// A role is held in two tables — one against a product, one across the estate
// — and a query naming one alone answers no for somebody who holds exactly the
// grant being asked about. This gate had no test, so the shape it exists to
// catch had only its own exit code for evidence.

func TestNamingOneGrantTableAndNotTheOther(t *testing.T) {
	for _, c := range []struct {
		what    string
		body    string
		missing string
		only    bool
	}{
		{
			"both, which is the rule",
			`q.Join("role_grant").Join("role_grant_all")`,
			"", false,
		},
		{
			"neither, which is a file about something else",
			`q.Join("person").Where("id = ?", id)`,
			"", false,
		},
		{
			"the per-product one alone",
			`q.Join("role_grant").Where("product_id = ?", id)`,
			"role_grant_all", true,
		},
		{
			// The shape the earlier spelling could not see: the estate name
			// contains the per-product one, so a substring test for
			// "role_grant" was satisfied by "role_grant_all" and the file
			// passed while naming one table.
			"the estate one alone",
			`q.Join("role_grant_all").Where("person_id = ?", id)`,
			"role_grant", true,
		},
		{
			"the estate one alone, several times",
			`role_grant_all ... role_grant_all ... role_grant_all`,
			"role_grant", true,
		},
	} {
		missing, only := namesOneAlone(c.body)
		if only != c.only || missing != c.missing {
			t.Errorf("%s: reported missing=%q only=%v, want %q %v",
				c.what, missing, only, c.missing, c.only)
		}
	}
}
