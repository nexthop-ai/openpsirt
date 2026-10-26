// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// seriesV0110 is v0.11.0's declaration of the tables results sent per series
// arrive in: the series, each run of it against a build, the documents a run
// arrived as, and the repositories a run's checkout held.
//
// Kept apart from the scan tables. Every reader of those asks which inventory
// a build holds, and a run of an analyzer is not one.
func seriesV0110(t *columnTypes) []string {
	return []string{
		// One analysis a product runs the same way on every build: a tool and
		// its configuration, such as clang-sa/default.
		`CREATE TABLE "series" (
			"id"          ` + t.id + `,
			"product_id"  ` + t.ref + ` NOT NULL,
			-- The kind of finding its results are.
			"kind"        ` + t.kind + ` NOT NULL,
			-- As the first run named it, and folded, which is what a run
			-- naming it again is matched on.
			"name"        ` + t.name + ` NOT NULL,
			"name_folded" ` + t.name + ` NOT NULL,
			"created_at"  ` + t.timestamp + ` NOT NULL,
			-- Written with a fresh value by every run applied, which is what
			-- makes two runs of the series wait for each other.
			"taken_by"    ` + t.name + ` NULL,
			CONSTRAINT "series_name_unique" UNIQUE ("product_id", "kind", "name_folded"),
			CONSTRAINT "series_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id")
		)` + t.suffix,

		// One run of a series against one build: what arrived, what it says
		// about itself, and what became of it.
		`CREATE TABLE "series_run" (
			"id"             ` + t.id + `,
			"series_id"      ` + t.ref + ` NOT NULL,
			"target_id"      ` + t.ref + ` NOT NULL,
			-- Over every document as it arrived, sorted, so a repeat is
			-- answered as the run it repeats.
			"content_hash"   ` + t.hash + ` NOT NULL,
			-- The commit at the top of the checkout that was analyzed.
			"source_commit"  ` + t.free + ` NULL,
			-- When the pipeline says the build was made, which orders runs.
			-- An analyzer writes no time of its own.
			"built_at"       ` + t.timestamp + ` NOT NULL,
			"received_at"    ` + t.timestamp + ` NOT NULL,
			"credential"     ` + t.name + ` NULL,
			"status"         ` + t.kind + ` NOT NULL,
			-- Why a run that was taken could not be read, in the words the
			-- sender is shown.
			"failure"        ` + t.text + ` NULL,
			"tool_name"      ` + t.free + ` NULL,
			"tool_version"   ` + t.free + ` NULL,
			-- The upload client's version, where the client wrote the run.
			"client_version" ` + t.free + ` NULL,
			-- The rules enabled: a digest of their identifiers, sorted, and
			-- how many. Null where the run states none.
			"rules_digest"   ` + t.hash + ` NULL,
			"rules_count"    INTEGER NULL,
			"units_expected" INTEGER NULL,
			"units_analyzed" INTEGER NULL,
			"exit_status"    INTEGER NULL,
			-- What the tool said of its own run: false where it says it did
			-- not finish, null where it says nothing.
			"completed"      ` + t.boolean + ` NULL,
			-- Whether absence in this run is evidence, worked out as it is
			-- read, and the first reason it is not. Null until it is read.
			"comparable"     ` + t.boolean + ` NULL,
			"not_comparable" ` + t.kind + ` NULL,
			-- The paths the pipeline names as code it did not write, as a
			-- JSON list of prefixes.
			"third_party"    ` + t.text + ` NULL,
			-- The inventory the run was read against: the build's newest
			-- read inventory when the run was applied.
			"scan_id"        ` + t.refNull + ` NULL,
			-- Whether this run was the series' first comparable run in the
			-- product, whose results nobody is asked to triage.
			"baseline"       ` + t.boolean + ` DEFAULT FALSE NOT NULL,
			-- The fingerprint schemes the run's results carry, sorted, and
			-- the mark of the salt the client's is taken with. Null where the
			-- run reported nothing, and "none" where nothing carried one.
			"fingerprints"   ` + t.text + ` NULL,
			-- Whether the fingerprints changed from the last run on the build
			-- that stated any, which leaves every lead matched probably.
			"rebaseline"     ` + t.boolean + ` DEFAULT FALSE NOT NULL,
			-- What the sender is told: what was dropped or discarded and why,
			-- and how many results it opened, saw again and did not see, as
			-- JSON. It names no result.
			"receipt"        ` + t.text + ` NULL,
			"applied_at"     ` + t.timestamp + ` NULL,
			CONSTRAINT "series_run_content_unique" UNIQUE ("series_id", "target_id", "content_hash"),
			CONSTRAINT "series_run_series_fk" FOREIGN KEY ("series_id") REFERENCES "series"("id"),
			CONSTRAINT "series_run_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "series_run_scan_fk" FOREIGN KEY ("scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		// The newest applied run of a series against a build, which every
		// arriving run is ordered against and matched against.
		`CREATE INDEX "series_run_newest_idx" ON "series_run" ("series_id", "target_id", "status", "built_at")`,
		// A build's runs, newest first, which the receipts read.
		`CREATE INDEX "series_run_target_idx" ON "series_run" ("target_id", "received_at")`,

		`CREATE TABLE "series_document" (
			"id"           ` + t.id + `,
			"run_id"       ` + t.ref + ` NOT NULL,
			"ordinal"      INTEGER NOT NULL,
			"content_hash" ` + t.hash + ` NOT NULL,
			"size_bytes"   BIGINT NOT NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			-- When the contents were let go, once the run ended.
			"discarded_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "series_document_place_unique" UNIQUE ("run_id", "ordinal"),
			CONSTRAINT "series_document_run_fk" FOREIGN KEY ("run_id") REFERENCES "series_run"("id")
		)` + t.suffix,

		`CREATE TABLE "series_document_chunk" (
			"id"          ` + t.id + `,
			"document_id" ` + t.ref + ` NOT NULL,
			"seq"         INTEGER NOT NULL,
			"body"        ` + t.blob + ` NOT NULL,
			CONSTRAINT "series_document_chunk_seq_unique" UNIQUE ("document_id", "seq"),
			CONSTRAINT "series_document_chunk_document_fk" FOREIGN KEY ("document_id")
				REFERENCES "series_document"("id")
		)` + t.suffix,

		// A repository the checkout held, at the commit it was pinned to.
		// Links into it need its own repository and commit, and two runs'
		// lists say whether its code moved between them.
		`CREATE TABLE "series_module" (
			"id"           ` + t.id + `,
			"run_id"       ` + t.ref + ` NOT NULL,
			-- From the top of the checkout, with no leading or trailing slash.
			"path"         ` + t.text + ` NOT NULL,
			-- As a web address, where the remote could be read as one.
			"remote"       ` + t.text + ` NULL,
			"revision"     ` + t.name + ` NULL,
			-- Whether the working tree differed from the commit when it was
			-- analyzed.
			"changed"      ` + t.boolean + ` DEFAULT FALSE NOT NULL,
			CONSTRAINT "series_module_run_fk" FOREIGN KEY ("run_id") REFERENCES "series_run"("id")
		)` + t.suffix,
		`CREATE INDEX "series_module_run_idx" ON "series_module" ("run_id")`,

		// What a series knows of each finding it reports: the run that first
		// saw it, the last that did, and the first comparable run that did
		// not, which is what not reproduced is.
		`CREATE TABLE "sighting" (
			"id"                  ` + t.id + `,
			"finding_id"          ` + t.ref + ` NOT NULL,
			"series_id"           ` + t.ref + ` NOT NULL,
			"first_run_id"        ` + t.ref + ` NOT NULL,
			"last_run_id"         ` + t.ref + ` NOT NULL,
			-- Null while the last comparable run saw it.
			"absent_run_id"       ` + t.refNull + ` NULL,
			-- Whether it arrived in the series' baseline, or was carried from
			-- a finding that did.
			"baseline"            ` + t.boolean + ` DEFAULT FALSE NOT NULL,
			CONSTRAINT "sighting_finding_unique" UNIQUE ("finding_id"),
			CONSTRAINT "sighting_finding_fk" FOREIGN KEY ("finding_id") REFERENCES "finding"("id"),
			CONSTRAINT "sighting_series_fk" FOREIGN KEY ("series_id") REFERENCES "series"("id"),
			CONSTRAINT "sighting_first_fk" FOREIGN KEY ("first_run_id") REFERENCES "series_run"("id"),
			CONSTRAINT "sighting_last_fk" FOREIGN KEY ("last_run_id") REFERENCES "series_run"("id"),
			CONSTRAINT "sighting_absent_fk" FOREIGN KEY ("absent_run_id") REFERENCES "series_run"("id")
		)` + t.suffix,
		// What a run saw and did not see, counted on its receipt.
		`CREATE INDEX "sighting_last_idx" ON "sighting" ("last_run_id")`,
		`CREATE INDEX "sighting_absent_idx" ON "sighting" ("absent_run_id")`,

		// The last upload of a series to a build that was turned away, and
		// why. One row per build and series, replaced each time: what is
		// asked is whether the series is being refused now, and a pipeline
		// retrying a document nothing can read would otherwise write one a
		// minute.
		`CREATE TABLE "series_refusal" (
			"id"           ` + t.id + `,
			"target_id"    ` + t.ref + ` NOT NULL,
			-- As the upload named it, and folded. Empty where the upload was
			-- turned away before it named one.
			"series"       ` + t.name + ` NOT NULL,
			"series_folded" ` + t.name + ` NOT NULL,
			"kind"         ` + t.kind + ` NOT NULL,
			"at"           ` + t.timestamp + ` NOT NULL,
			-- What the sender was told.
			"reason"       ` + t.text + ` NOT NULL,
			"credential"   ` + t.name + ` NULL,
			CONSTRAINT "series_refusal_unique" UNIQUE ("target_id", "kind", "series_folded"),
			CONSTRAINT "series_refusal_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id")
		)` + t.suffix,
	}
}

// analysisV0110 is v0.11.0's declaration of what an analyzer said about each
// finding of the analysis kind, as the newest run that saw it said it.
func analysisV0110(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "analysis_result" (
			"id"            ` + t.id + `,
			"finding_id"    ` + t.ref + ` NOT NULL,
			-- Relative to the top of the checkout, with forward slashes.
			"path"          ` + t.text + ` NOT NULL,
			"start_line"    INTEGER NULL,
			"start_column"  INTEGER NULL,
			"end_line"      INTEGER NULL,
			"end_column"    INTEGER NULL,
			-- The function the result is in, and the functions its path
			-- passes through, where the output names them.
			"enclosing"     ` + t.text + ` NULL,
			"call_chain"    ` + t.text + ` NULL,
			"message_text"  ` + t.text + ` NOT NULL,
			-- The fingerprint matching read, and the scheme that wrote it.
			"fingerprint"   ` + t.text + ` NULL,
			"fingerprint_scheme" ` + t.name + ` NULL,
			-- A digest of everything an exact match compares: the rule, the
			-- path, the fingerprint or the line, the message with its digits
			-- taken out, the function and the call chain.
			"match_key"     ` + t.hash + ` NOT NULL,
			-- The same without the fingerprint or the line, which a run
			-- whose fingerprints changed compares where one result and one
			-- lead hold it.
			"unprinted_key" ` + t.hash + ` NOT NULL,
			-- The two probable keys: the rule, the path and the message with
			-- its digits taken out, with the function where the output names
			-- one, and with neither.
			"function_key"  ` + t.hash + ` NULL,
			"line_key"      ` + t.hash + ` NOT NULL,
			-- How the newest sighting was paired with the lead: on the whole
			-- key or on the whole key without its fingerprint, which are
			-- strong, or on the function or the nearest line, which are
			-- probable. Null where the sighting opened it.
			"matched_on"    ` + t.kind + ` NULL,
			-- The analyzer's own rating and how sure it is, where it gives
			-- them.
			"level"         ` + t.kind + ` NULL,
			-- The source at the result and the line it starts at, where the
			-- product keeps source under its path.
			"snippet"       ` + t.text + ` NULL,
			"snippet_line"  INTEGER NULL,
			-- The last place the result names, which two analyzers reporting
			-- one flaw agree on: the last step of its path, the last related
			-- location in its own file, or its own location.
			"last_path"     ` + t.text + ` NOT NULL,
			-- A digest of the last path, which is what an index holds: the
			-- path is text no index takes whole on MySQL.
			"last_path_identity" ` + t.hash + ` NOT NULL,
			"last_line"     INTEGER NULL,
			CONSTRAINT "analysis_result_finding_unique" UNIQUE ("finding_id"),
			CONSTRAINT "analysis_result_finding_fk" FOREIGN KEY ("finding_id") REFERENCES "finding"("id")
		)` + t.suffix,
		`CREATE INDEX "analysis_result_key_idx" ON "analysis_result" ("match_key")`,
		// The leads whose last place is near another's, which is how two
		// analyzers' leads are found to be one flaw.
		`CREATE INDEX "analysis_result_last_idx" ON "analysis_result" ("last_path_identity", "last_line")`,

		// The other places a result names: related locations, and the steps
		// of the path the analyzer took to it.
		`CREATE TABLE "analysis_location" (
			"id"           ` + t.id + `,
			"finding_id"   ` + t.ref + ` NOT NULL,
			"ordinal"      INTEGER NOT NULL,
			-- A step on the analyzer's path, or a related location.
			"part"         ` + t.kind + ` NOT NULL,
			"path"         ` + t.text + ` NULL,
			"start_line"   INTEGER NULL,
			"start_column" INTEGER NULL,
			"end_line"     INTEGER NULL,
			"end_column"   INTEGER NULL,
			"message_text" ` + t.text + ` NULL,
			-- How deep in calls a step is, where the output says.
			"depth"        INTEGER NULL,
			"snippet"      ` + t.text + ` NULL,
			"snippet_line" INTEGER NULL,
			CONSTRAINT "analysis_location_place_unique" UNIQUE ("finding_id", "ordinal"),
			CONSTRAINT "analysis_location_finding_fk" FOREIGN KEY ("finding_id") REFERENCES "finding"("id")
		)` + t.suffix,
	}
}

// createSeriesV0110 makes the series, run, sighting and analysis tables,
// stepped over where they are already there.
func createSeriesV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, table := range []struct {
		name string
		made func(*columnTypes) []string
	}{
		{"series", seriesV0110},
		{"series_run", seriesV0110},
		{"series_document", seriesV0110},
		{"series_document_chunk", seriesV0110},
		{"series_module", seriesV0110},
		{"sighting", seriesV0110},
		{"series_refusal", seriesV0110},
		{"analysis_result", analysisV0110},
		{"analysis_location", analysisV0110},
	} {
		present, err := u.hasColumn(table.name, "id")
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.create(table.made(u.t), table.name); err != nil {
			return err
		}
	}
	return nil
}
