// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

// SaidBody is one standing third-party statement, as a finding shows it.
type SaidBody struct {
	// ID is the citation a decision carries when somebody starts from this, so
	// a revision to it can be noticed later.
	ID        int64  `json:"id" doc:"Pass as from_statement when starting a decision from this, so a later revision can be noticed"`
	Publisher string `json:"publisher"`
	// Source is which kind of document carried it and Identifier the name the
	// publisher gave that document. An advisory is recognized by its own name;
	// a statement set carries none, because a publisher issues one.
	Source        EvidenceSource `json:"source" doc:"Which kind of document carried it"`
	Identifier    string         `json:"identifier,omitempty" doc:"The name the publisher gave the advisory"`
	Status        string         `json:"status" doc:"Their statement, in the format's own vocabulary"`
	Justification string         `json:"justification,omitempty" doc:"The term they gave for it, where the status is one that takes one"`
	// About is the version the publisher spoke about, where they named one. A
	// status read without it is a claim about a version the reader cannot see:
	// "fixed" against a component that is not at that version says the
	// opposite of what it looks like.
	About string `json:"about,omitempty" doc:"The version they made the claim about, where they named one"`
	// Statement is the reasoning, which is the part worth having: the status
	// is in the fix state already.
	Statement string `json:"statement,omitempty" doc:"Their reasoning. What a triager otherwise types from memory"`
	Document  string `json:"document" doc:"The document it came from"`
	At        string `json:"at" doc:"The moment it was uploaded here"`
	// Offers is the outcome this would prefill, where it offers one. A
	// publisher saying they will not fix something is not the same as saying
	// it does not apply, so that offers a will-not-fix and never a dismissal.
	// A statement naming a version offers nothing against a different one.
	Offers OutcomeOffered `json:"offers,omitempty" doc:"The outcome this offers as a prefill, where it was made about the version shipped here. Never applied by itself"`
}

// Cited is a VEX statement's identifier as a citation, or none where
// nothing was cited. Zero is "nothing", which is what a body that omits the
// field sends.
func Cited(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}
