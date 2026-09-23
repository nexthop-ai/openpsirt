// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"fmt"
	"io"
	"strings"
)

// Reading a supplier's CSAF security advisory, the third document a third
// party's judgment arrives in beside OpenVEX and CSAF-VEX.
//
// A VEX document is a statement set: what a publisher says about everything at
// once. An advisory is an announcement about one issue, and a publisher issues
// one per issue. The claims inside are the same shape — a status per product
// identifier, resolved through the same tree — so the same reader reads both
// and what differs is the document around them.
//
// Two of those differences reach the rest of the application. The document
// carries a name of the publisher's own, which is what a revision of it
// supersedes on. And its claims are about the publisher's own versions: an
// advisory exists to say which version is affected and which carries the fix,
// so what it says about one version is not what it says about another.

// advisoryProfile is what a supplier's security advisory says it is.
const advisoryProfile = "csaf_security_advisory"

// Advisory is a supplier's security advisory as this reads it.
type Advisory struct {
	// Identifier is the name the publisher gave the document, which is what a
	// later revision of it replaces. A publisher issues one advisory per
	// issue, so the publisher alone does not identify anything.
	Identifier string
	// Publisher is who issued it, as the document names itself. Mandatory in
	// the format, so a document that names nobody is refused rather than
	// attributed to whoever uploaded it.
	Publisher string
	// Title is what the publisher called it, which is what a reader recognizes
	// it by where the identifier is a serial number.
	Title string
	// Claims are what it says about each product it names, in the shape every
	// other third-party judgment here arrives in.
	Claims []Suppression
}

// ReadAdvisory reads one supplier security advisory.
//
// The profile is checked rather than assumed, in both directions: a VEX
// document read here would be superseded under a name it does not have, and an
// advisory read as a VEX document would take a publisher's announcement about
// their own flaws as claims about what a build ships.
func ReadAdvisory(r io.Reader, lim Limits) (Advisory, error) {
	lim = lim.OrDefault()
	b := newBounded(&capped{r: r, left: lim.MaxBytes}, lim.MaxDepth)
	read := newCSAF(b, lim)
	read.profile = advisoryProfile
	err := b.object(func(key string) error {
		switch key {
		case "document", "product_tree", "vulnerabilities":
			return read.key(key)
		default:
			return b.skip()
		}
	})
	if err != nil {
		return Advisory{}, fmt.Errorf("reading an advisory: %w", err)
	}
	claims, err := read.finish()
	if err != nil {
		return Advisory{}, fmt.Errorf("reading an advisory: %w", err)
	}
	if strings.TrimSpace(read.publisher) == "" {
		return Advisory{}, fmt.Errorf("reading an advisory: it names no publisher, and " +
			"whose judgment it is decides what it supersedes and whose name stands beside it")
	}
	if strings.TrimSpace(read.identifier) == "" {
		return Advisory{}, fmt.Errorf("reading an advisory: it carries no tracking " +
			"identifier, which is the name a later revision of it replaces")
	}
	return Advisory{
		Identifier: strings.TrimSpace(read.identifier),
		Publisher:  strings.TrimSpace(read.publisher),
		Title:      strings.TrimSpace(read.title),
		Claims:     claims,
	}, nil
}
