// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vercmp

import "strings"

// Release is a version without what a distribution adds when it packages a
// release: the epoch and revision of a Debian version, the epoch and release
// of an RPM one, the revision of an Alpine one, and the local label of a
// PEP 440 one. A version of an ecosystem with no scheme here loses an epoch
// and the part after its last hyphen where it has the shape Debian and RPM
// share, because a producer states a distribution's version beside an
// identifier of another type: a SONiC inventory describes
// `linux-headers-6.12.41+deb13-common-sonic` at `6.12.41-1` with a `github`
// identifier naming a commit. Every other version, and one without the parts
// its scheme cuts, is its own release.
//
// Cut by the shape alone, never checked against the scheme's whole grammar,
// so the cut is one a database upgrade can repeat exactly.
//
// A package carrying its version in its name carries the release, and the
// distribution's additions move without the name moving: Debian's
// `linux-image-6.12.41+deb13-amd64` is at `6.12.41-1`.
func Release(scheme Scheme, v string) string {
	v = strings.TrimSpace(v)
	switch scheme {
	case Debian, RPM, Unordered:
		if cut, ok := splitEVR(v); ok {
			return cut.version
		}
	case APK:
		if at := strings.LastIndex(v, "-r"); at > 0 && digits(v[at+2:]) {
			return v[:at]
		}
	case PyPI:
		if before, _, local := strings.Cut(v, "+"); local && before != "" {
			return before
		}
	}
	return v
}
