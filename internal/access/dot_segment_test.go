// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// A browser resolves "." and ".." before sending, so a key, token, team or
// person named that way could never be opened, and removing a member named
// ".." from a team would ask to delete the team.
func TestANameABrowserResolvesAsADotSegmentIsNeverRecorded(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		ana, err := f.store.Ensure(ctx, "ana", "Ana", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{".", "..", " .. "} {
			for what, err := range map[string]error{
				"key":    second3(f.store.NewKey(ctx, name, access.Scope{ProductID: f.products["sonic"]})),
				"token":  second3(f.store.NewToken(ctx, ana.ID, name, nil, nil, time.Hour, 24*time.Hour)),
				"team":   second3(f.store.DeclareTeam(ctx, name, "")),
				"person": second(f.store.Ensure(ctx, name, "", nil, nil)),
			} {
				if !refusal.In(err) {
					t.Errorf("a %s named %q answered %v, want a refusal", what, name, err)
				}
			}
		}
		if _, _, err := f.store.DeclareTeam(ctx, "...", ""); err != nil {
			t.Errorf("a team named with three dots was refused: %v", err)
		}
	})
}

// A sign-in a group mapping would record is refused the way any unknown
// arrival is, and nothing is recorded under the name.
func TestASignInUnderADotSegmentNameIsRefusedAndNotRecorded(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		bind(t, f, access.Mapping{Group: "platform", Grants: string(access.PublicRead), Product: "sonic"})
		for _, name := range []string{".", ".."} {
			_, err := f.store.AdmitByGroups(ctx, access.Arrival{ViaProxy: true, Username: name}, []string{"platform"})
			if !errors.Is(err, access.ErrDenied) {
				t.Errorf("a sign-in as %q answered %v, want the refusal every stranger gets", name, err)
			}
			if _, err := f.store.ByIdentity(ctx, name); err == nil {
				t.Errorf("%q was recorded anyway", name)
			}
		}
	})
}

func second[T any](_ T, err error) error { return err }

func second3[T, U any](_ T, _ U, err error) error { return err }
