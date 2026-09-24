// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// v0.3.0's declaration of the component table, and its indexes.
//
// v0.1.0's, which v0.2.0 left as it was, with the license an inventory declares.
func componentV030(t *columnTypes) []string {
	return []string{
		// identity is derived from the component's own content — its package
		// identifier, or its name and version where it has none. Never from an
		// identifier the scan file supplied, which nothing guarantees is
		// stable between builds.
		`CREATE TABLE "component" (
			"id"               ` + t.id + `,
			"identity"         ` + t.hash + ` NOT NULL,
			"purl"             ` + t.text + ` NULL,
			-- The second identifier a component can carry.
			--
			-- The package identifier is what identity is derived from and
			-- what most feeds match on. The platform enumeration is what the
			-- national vulnerability database keys on, and a scanner given
			-- one matches components a package identifier alone misses:
			-- vendor firmware, operating systems, appliances, anything never
			-- published to a package ecosystem. Captured because a real
			-- producer emits it for most of what it ships and a scan file is
			-- not kept once read — data discarded at ingest is recoverable
			-- only by asking the producer to build again.
			--
			-- Deliberately not part of identity: adding a second basis would
			-- move the identity of everything carrying both.
			"cpe"              ` + t.text + ` NULL,
			-- Everything below comes from a scan file, and nothing bounds
			-- what a producer puts in it. A bounded column here means a
			-- legitimate but long value fails the whole scan that carried it.
			"name"             ` + t.free + ` NOT NULL,
			"version"          ` + t.free + ` NOT NULL,
			"upstream_name"    ` + t.free + ` NULL,
			"upstream_version" ` + t.free + ` NULL,
			-- The two names, folded, for matching a name somebody typed.
			--
			-- Bounded, unlike the names they fold: the stored name is
			-- unbounded because nothing bounds what a producer puts in a scan
			-- file, and a bounded column there would fail a whole scan over
			-- one long value. These exist to be looked up, and an index needs
			-- a width — truncated on the way in rather than refused, because
			-- two names agreeing for a hundred and ninety-one characters are
			-- the same name by any reading.
			--
			-- Folded in Go rather than by asking an engine to compare
			-- loosely, because the four do not agree on what that means: a
			-- rule naming a package with a capital in it sweeps on two of
			-- them and not the other two, and nothing reports the difference
			-- because both answers look correct. It also makes the
			-- comparisons use an index, where LOWER(name) cannot — every
			-- routing sweep and every component search was a scan of this
			-- table.
			--
			-- Nullable, because a component with no upstream name recorded
			-- has no folded one either.
			"name_folded"      ` + t.name + ` NULL,
			"upstream_folded"  ` + t.name + ` NULL,
			-- The binary packages one source package was built at one version
			-- share this, and it is what a person acts on: curl, libcurl4t64
			-- and libcurl3t64 are one bump. It groups and does not identify —
			-- identity above is what every record hangs off, and none of them
			-- moves when a producer starts stating a source package it did
			-- not state before. Hashed, so that grouping cannot merge two
			-- source packages by agreeing to an index's bound.
			"fold_key"         ` + t.hash + ` NOT NULL,
			"first_seen_at"    ` + t.timestamp + ` NOT NULL,
			-- What upstream has released, and when we last asked.
			--
			-- Kept because "we have never asked" and "we asked and it has not
			-- moved" are different states: without the third column a
			-- component nobody could look up is indistinguishable from one
			-- that is current. Only for what we build ourselves — for a
			-- distribution package the distribution is the maintainer and its
			-- release date says nothing about the software inside, which is
			-- why these sit on the component rather than being inferred for
			-- everything.
			"latest_version"     ` + t.free + ` NULL,
			"latest_released_at" ` + t.timestamp + ` NULL,
			"latest_checked_at"  ` + t.timestamp + ` NULL,
			-- What the index says the package is, and where it is developed.
			-- Taken where an index serves them and absent where it does not,
			-- which is the ordinary case rather than a half-written row: three
			-- of the four serve a summary and the module proxy serves none,
			-- while all four name an address. Both are somebody else's text, so
			-- the summary is bounded and the address is judged before it is
			-- stored.
			"summary"            ` + t.free + ` NULL,
			"project_url"        ` + t.free + ` NULL,
			-- Who the producer said supplied it: a distribution, a vendor, a
			-- project. From the inventory rather than from an index, and absent
			-- for plenty of it — one producer states it for 759 of the 6,866
			-- components it describes. Not part of identity, because two
			-- producers name it differently or not at all.
			"supplier"           ` + t.free + ` NULL,
			-- The license the inventory declares for it, as the producer
			-- wrote it. Not part of identity, for the reason the supplier
			-- is not: two producers state it differently or not at all.
			"license"            ` + t.free + ` NULL,
			CONSTRAINT "component_identity_unique" UNIQUE ("identity")
		)` + t.suffix,

		// Not unique: a fold is many components by construction.
		`CREATE INDEX "component_fold_idx" ON "component" ("fold_key")`,

		// What a routing rule and a component search look one up by. The
		// upstream name matters most, because a rule names a source package:
		// that is the key one rule uses to reach every binary package built
		// from it.
		`CREATE INDEX "component_folded_idx" ON "component" ("name_folded")`,

		`CREATE INDEX "component_upstream_folded_idx" ON "component" ("upstream_folded")`,
	}
}
