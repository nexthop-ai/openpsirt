// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cverecord reads what CVE records say about which upstream versions an
// issue affects, and narrows a scanner's match where a record excludes the
// version a place holds (REQ-31).
//
// The records come from the CVE List, the published body of every CVE record.
// Only the part this reads is kept: each record whose upstream entries carry
// an ordered version line stating a version is unaffected. A record without
// one can never narrow anything, so keeping it would cost memory and buy
// nothing.
package cverecord

import (
	"strings"
)

// Record is what one CVE record says about the products it affects.
type Record struct {
	// ID is the record's identifier, as the record spells it.
	ID string `json:"id"`
	// Affected is every entry the record's numbering authority wrote, in the
	// record's order. Kept whole for a record that is kept at all: an entry
	// with only affected lines is what stops another entry's unaffected line
	// narrowing a version both describe.
	Affected []Entry `json:"affected"`
}

// Entry is one product a record describes, and the versions it names.
//
// The identity fields are the record's own. Which of them a given record
// carries varies by who wrote it: the kernel's carry a vendor, a product and a
// repository; a distribution's carry a platform's CPE; a third party's may
// carry a package identifier.
type Entry struct {
	Vendor        string   `json:"vendor,omitempty"`
	Product       string   `json:"product,omitempty"`
	CPEs          []string `json:"cpes,omitempty"`
	PackageURL    string   `json:"packageURL,omitempty"`
	PackageName   string   `json:"packageName,omitempty"`
	CollectionURL string   `json:"collectionURL,omitempty"`
	Repo          string   `json:"repo,omitempty"`
	DefaultStatus string   `json:"defaultStatus,omitempty"`
	Versions      []Line   `json:"versions,omitempty"`
}

// Line is one version line of an entry, in the record format's own terms.
type Line struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	VersionType     string `json:"versionType,omitempty"`
	LessThan        string `json:"lessThan,omitempty"`
	LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
	// Changes says the line carries a list of status changes within its
	// range. Recorded and never read further: a line whose status moves inside
	// its own range is one this does not evaluate.
	Changes bool `json:"changes,omitempty"`
}

// Named is the entry's name for a person: the vendor and the product, or
// whichever of the two it gives.
func (e Entry) Named() string {
	vendor, product := strings.TrimSpace(e.Vendor), strings.TrimSpace(e.Product)
	switch {
	case vendor == "" || strings.EqualFold(vendor, "n/a"):
		return product
	case product == "" || strings.EqualFold(product, "n/a"):
		return vendor
	default:
		return vendor + " " + product
	}
}
