// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// vulnerabilityV0140 is v0.14.0's declaration of the vulnerability table.
//
// v0.12.0's, with the files the issue's CVE record lists.
func vulnerabilityV0140(t *columnTypes) []string {
	statements := vulnerabilityV0120(t)
	statements[0] = withColumn(statements[0], `"taken_by"       `+t.free+` NULL,`,
		`-- The source files the issue's CVE record says it is in, one path
			-- a line in byte order, as the record snapshot read by the last
			-- scan reporting the issue had them. Null where the record lists
			-- none or no scan has read one.
			"program_files"  `+t.text+` NULL,`)
	return statements
}

// sourceCorrectionV0140 is v0.14.0's declaration of what a correction by
// source paths names.
func sourceCorrectionV0140(t *columnTypes) []string {
	return []string{
		// One row per decision that is a correction by source paths: the
		// package it answers in one product, the source package that package
		// is matched through, and the paths within that source the package
		// is built from, one a line in byte order. The names are held in
		// lower case, which is how a match records the source.
		`CREATE TABLE "source_correction" (
			"id"           ` + t.id + `,
			"decision_id"  ` + t.ref + ` NOT NULL,
			"product_id"   ` + t.ref + ` NOT NULL,
			"package_name" ` + t.name + ` NOT NULL,
			"source_name"  ` + t.name + ` NOT NULL,
			"source_paths" ` + t.text + ` NOT NULL,
			-- When the decision was withdrawn, after which the correction
			-- answers nothing more. Null while it stands.
			"withdrawn_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "source_correction_decision_unique" UNIQUE ("decision_id"),
			CONSTRAINT "source_correction_decision_fk" FOREIGN KEY ("decision_id") REFERENCES "decision"("id"),
			CONSTRAINT "source_correction_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id")
		)` + t.suffix,
		// The corrections a scan of one of the product's builds answers by.
		`CREATE INDEX "source_correction_product_idx" ON "source_correction" ("product_id")`,
	}
}

// sourceAnswerV0140 is v0.14.0's declaration of the files that justified each
// occurrence a correction by source paths answered.
func sourceAnswerV0140(t *columnTypes) []string {
	return []string{
		// The files the issue's record listed when the row was written, one
		// a line in byte order. Kept, because the record can change after
		// and the row is answered on what it said then. Withdrawn when the
		// answer stops holding: the moment; what withdrew it, the record
		// (record), a match other than through the source (match) or an
		// incident (incident); and the files the record listed where it
		// was the record, empty where it lists none.
		`CREATE TABLE "source_answer" (
			"id"                     ` + t.id + `,
			"decision_occurrence_id" ` + t.ref + ` NOT NULL,
			"files"                  ` + t.text + ` NOT NULL,
			"withdrawn_at"           ` + t.timestamp + ` NULL,
			"withdrawn_because"      ` + t.kind + ` NULL,
			"withdrawn_on"           ` + t.text + ` NULL,
			CONSTRAINT "source_answer_occurrence_unique" UNIQUE ("decision_occurrence_id"),
			CONSTRAINT "source_answer_occurrence_fk" FOREIGN KEY ("decision_occurrence_id") REFERENCES "decision_occurrence"("id")
		)` + t.suffix,
	}
}

// sourceCorrectionsV0140 adds the source package a finding was matched
// through, the files an issue's record lists, and the two tables of a
// correction by source paths. v0.13.0 recorded none of them, so every finding
// and issue starts with none until its next scan.
//
// Each piece is asked for alone: a stop between two leaves some made.
func sourceCorrectionsV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, column := range []struct{ table, name string }{
		{"finding", "matched_through"},
		{"vulnerability", "program_files"},
	} {
		present, err := u.hasColumn(column.table, column.name)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		declared := findingV0140(u.t)
		if column.table == "vulnerability" {
			declared = vulnerabilityV0140(u.t)
		}
		if err := u.change(declared, change{table: column.table, add: []added{{column: column.name}}}); err != nil {
			return err
		}
	}
	for _, table := range []struct {
		name     string
		declared func(*columnTypes) []string
	}{
		{"source_correction", sourceCorrectionV0140},
		{"source_answer", sourceAnswerV0140},
	} {
		present, err := u.hasTable(table.name)
		if err != nil {
			return err
		}
		if !present {
			if err := u.create(table.declared(u.t), table.name); err != nil {
				return err
			}
			continue
		}
		// A table a stopped upgrade made may lack the indexes made after it.
		_, indexes, err := pick(table.declared(u.t), table.name)
		if err != nil {
			return err
		}
		for _, stmt := range indexes {
			held, err := u.hasIndex(table.name, createsIndex.FindStringSubmatch(stmt)[1])
			if err != nil {
				return err
			}
			if !held {
				if err := u.run([]string{stmt}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
