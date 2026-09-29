// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"bytes"
	"encoding/json"
	"time"
)

// Document is a CSAF 2.0 document.
//
// The field names and their shapes are the standard's, not ours, so they are
// spelled as it spells them and are exempt from this codebase's spelling rule
// for the same reason a producer's field names are.
type Document struct {
	Document    Meta        `json:"document"`
	ProductTree ProductTree `json:"product_tree"`
	// Vulnerabilities holds one entry per issue the advisory covers, which
	// is what lets several flaws released together be one document on one
	// date. Each aggregates to a product and a version range rather than to
	// a path: a reader is asking whether they are affected, and the answer
	// is a release.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// MarshalJSON writes the document with every object's keys in alphabetical
// order.
//
// The standard's optional test 6.2.13 asks for it. The fields here are
// declared in the order a reader of this file follows, so the order is
// imposed on the bytes rather than on the declarations: read back as generic
// values, every object is a map, and a map is written with its keys sorted.
// Numbers are carried through as the text they were written as.
func (d Document) MarshalJSON() ([]byte, error) {
	type declared Document
	body, err := json.Marshal(declared(d))
	if err != nil {
		return nil, err
	}
	reader := json.NewDecoder(bytes.NewReader(body))
	reader.UseNumber()
	var generic any
	if err := reader.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// Meta is the document's own description.
type Meta struct {
	// Category is what kind of document this is, and it follows what the
	// document can actually support rather than what would sound better: the
	// VEX profile where any release is stated known not affected, which is
	// the profile that carries "not affected, and here is why", and the
	// security-advisory profile otherwise.
	Category     string        `json:"category"`
	CSAFVersion  string        `json:"csaf_version"`
	Title        string        `json:"title"`
	Publisher    Issuer        `json:"publisher"`
	Tracking     Tracking      `json:"tracking"`
	Notes        []Note        `json:"notes,omitempty"`
	References   []Reference   `json:"references,omitempty"`
	Distribution *Distribution `json:"distribution,omitempty"`
	Language     string        `json:"lang,omitempty"`
}

// Issuer is the publisher as the document carries it.
type Issuer struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Tracking is the document's identity and where it is in its life.
type Tracking struct {
	ID string `json:"id"`
	// Status is where the document is in its life: final where a second
	// person agrees to what it says now, interim where it has gone out and
	// nobody agrees to what it says now, draft before either.
	//
	// The one field a reader of a CSAF document checks before acting on it,
	// so it answers what they are asking — whether this is the publisher's
	// settled word — rather than whether the flaws behind it are public.
	// How far the document may travel is the distribution label, which is
	// where the embargo is answered.
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	InitialReleaseDate time.Time  `json:"initial_release_date"`
	CurrentReleaseDate time.Time  `json:"current_release_date"`
	Generator          *Generator `json:"generator,omitempty"`
	RevisionHistory    []Revision `json:"revision_history"`
}

// Generator names what assembled the document.
type Generator struct {
	Engine Engine    `json:"engine"`
	Date   time.Time `json:"date"`
}

// Engine is the software that generated it.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Revision is one entry in the document's history.
type Revision struct {
	Number  string    `json:"number"`
	Date    time.Time `json:"date"`
	Summary string    `json:"summary"`
}

// Note is prose attached to a document or a vulnerability.
type Note struct {
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

// ProductTree names everything the document can make a statement about.
type ProductTree struct {
	Branches []Branch `json:"branches,omitempty"`
}

// Branch is one level of that naming.
type Branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Branches []Branch `json:"branches,omitempty"`
	Product  *Named   `json:"product,omitempty"`
}

// Named is a leaf of the product tree: something a status can be stated about.
type Named struct {
	Name string `json:"name"`
	ID   string `json:"product_id"`
	// Helper is how a reader matches this release against something they
	// already hold, where the build said what it is.
	Helper *IdentificationHelper `json:"product_identification_helper,omitempty"`
}

// IdentificationHelper is what a release called itself, in a spelling a machine
// can compare.
//
// The identifier the build declared, never one minted here. An identifier
// only helps if it appears on both sides of the comparison, and one invented
// here appears on one: a reader holding our image has whatever our build wrote
// into its inventory, which is this exact string if they ingested that
// document. A plausible identifier nothing outside this deployment has seen is
// worse than none, because a reader matches on it and misses.
//
// It is read from the scan rather than from the component, because the root
// component is stored by name alone: a package identifier carries the version,
// and the root's version moves every build.
type IdentificationHelper struct {
	Purl string `json:"purl,omitempty"`
}

// Vulnerability is the flaw and what is true of it in each release.
type Vulnerability struct {
	// CVE where it has one, and IDs otherwise. An identifier this
	// deployment minted is not a CVE and saying it is in that field would
	// be a claim nobody assigned.
	CVE   string   `json:"cve,omitempty"`
	IDs   []Issued `json:"ids,omitempty"`
	Title string   `json:"title,omitempty"`
	Notes []Note   `json:"notes,omitempty"`
	// Status is which releases the flaw is in and which it is out of.
	Status Status `json:"product_status"`
	// Flags carry the reason for every release stated known not affected,
	// one per reason. The five reasons a decision records are the standard's
	// five flag labels.
	Flags []Flag `json:"flags,omitempty"`
	// Threats carry what stops the flaw in a release stated known not
	// affected, where the decision named it. The decision's reasoning is never
	// read into a document.
	Threats []Threat `json:"threats,omitempty"`
	// CWE is what kind of flaw this is, where the catalog knows the name.
	CWE *Weakness `json:"cwe,omitempty"`
	// Scores is what is held about the flaw beyond which releases carry
	// it: what it scored, what a holder of an affected release can do, and
	// whoever asked to be credited for telling us.
	Scores          []Score          `json:"scores,omitempty"`
	Remediations    []Remediation    `json:"remediations,omitempty"`
	Acknowledgments []Acknowledgment `json:"acknowledgments,omitempty"`
	// DiscoveryDate is when this deployment first recorded it, which is what
	// it knows. When somebody outside found it is not something it holds.
	//
	// A timestamp rather than a day. The standard asks every date it defines
	// for a date and a time, and a validator refuses a bare day — which is a
	// document a customer's tooling drops. A string rather than a moment,
	// because a moment nothing recorded has to be absent rather than stated
	// as the zero one, and an empty struct is not omitted.
	DiscoveryDate string `json:"discovery_date,omitempty"`
}

// Weakness is the kind of flaw, as the standard carries it.
//
// One, and both halves of it. The standard states a weakness as the
// identifier and the name the catalog gives it, and a consumer's validator
// compares the pair — so an issue classified several ways states the one the
// data calls the root cause, and one whose name the catalog does not know
// states nothing. A name invented to fill the field is the single thing in the
// document guaranteed to be caught.
type Weakness struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Issued is an identifier somebody else's system knows this by.
type Issued struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// Status is which releases the flaw is in and which it is out of.
//
// A release that held the flaw and no longer does is named as fixed rather
// than left out, because leaving it out reads identically to a release that
// never shipped the thing at all — and those are opposite answers, one of them
// the one a reader is hoping for.
//
// A release whose every open place is covered by an approved decision that
// the flaw does not apply is known not affected, with the reason on a flag.
type Status struct {
	KnownAffected    []string `json:"known_affected,omitempty"`
	KnownNotAffected []string `json:"known_not_affected,omitempty"`
	Fixed            []string `json:"fixed,omitempty"`
}

// Flag is a machine-readable reason some releases are not affected.
type Flag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

// Threat is a statement about the flaw in some releases. The only category
// written is the impact statement a known-not-affected release carries.
type Threat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}
