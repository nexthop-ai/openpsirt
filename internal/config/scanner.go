package config

import "github.com/nexthop-ai/openpsirt/internal/scanner"

// ScannerLimits is what one execution of the scanner is read within.
//
// Each bound left unset here stays at the package's own default rather than
// becoming zero, which is what "all of them configurable" has to mean for a
// deployment that wants one of them changed.
func (c Config) ScannerLimits() scanner.Limits {
	return scanner.Limits{
		MaxOutput:     int64(c.ScannerMaxOutput),
		MaxComplaint:  int64(c.ScannerMaxComplaint),
		MaxMatches:    c.ScannerMaxMatches,
		MaxReferences: c.ScannerMaxReferences,
	}
}
