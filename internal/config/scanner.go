// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import "github.com/nexthop-ai/openpsirt/internal/scanner"

// ScannerLimits is what one execution of the scanner is read within.
//
// A bound left unset is zero, which the scanner takes as its own default, so a
// deployment can change one bound and leave the rest where they are.
func (c Config) ScannerLimits() scanner.Limits {
	return scanner.Limits{
		MaxOutput:     int64(c.ScannerMaxOutput),
		MaxComplaint:  int64(c.ScannerMaxComplaint),
		MaxMatches:    c.ScannerMaxMatches,
		MaxReferences: c.ScannerMaxReferences,
	}
}
