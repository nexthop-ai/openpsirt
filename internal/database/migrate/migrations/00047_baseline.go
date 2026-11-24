// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upBaseline, nil)
}

// Baseline is the migration that makes v0.13.0's schema, the version a
// database v0.13.0 built records.
const Baseline = 47

// The schema v0.13.0 built, made directly on an empty database.
//
// Numbered as v0.13.0's last migration, so a database v0.13.0 built has it
// recorded already and applies only what follows. A database an earlier
// release built records a version below it, and is refused before anything
// runs (design-docs/database-migrations.md § The baseline).
//
// The baseline files beside this one hold each table's declaration, with the
// reasoning for its shape. v0.13.0's record of the schema it built on each
// engine is what holds them to it.
//
// Its statements are bounded in their wait for a lock as every migration's
// are, and none waits: it makes its tables in an empty database, where no
// other session holds one.
func upBaseline(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	var statements []string
	for _, each := range baseline {
		made, indexes, err := pick(each.declared(t), each.table)
		if err != nil {
			return fmt.Errorf("the baseline: %w", err)
		}
		statements = append(statements, made)
		statements = append(statements, indexes...)
	}
	if migrate.EngineFrom(ctx) == database.Postgres {
		statements = append(statements, findingVacuum...)
	}
	return apply(ctx, tx, statements)
}

// findingVacuum is when PostgreSQL vacuums and analyzes the finding table.
// The other engines have no such setting.
//
// An index-only scan reads the table for every row on a page the visibility
// map does not mark all-visible, and only a vacuum marks one. A nightly scan
// rewrites tens of thousands of findings, below the fifth of the table the
// server's defaults wait for, so the pages it touched stay unmarked until the
// table has changed by that much. Measured over 375,843 findings with 46,980
// rewritten: at the defaults no vacuum ran, and the package-kind count read
// the table 413,331 times and took 246 ms; at a fiftieth a vacuum ran within
// the minute, and the count read the table not at all and took 64 ms.
var findingVacuum = []string{
	`ALTER TABLE "finding" SET (
		"autovacuum_vacuum_scale_factor" = 0.02,
		"autovacuum_vacuum_insert_scale_factor" = 0.02,
		"autovacuum_analyze_scale_factor" = 0.01)`,
}

// baselineTable is one table of the baseline, and the declaration it is made
// by.
type baselineTable struct {
	table    string
	declared func(*columnTypes) []string
}

// baseline is every table, each after every table it points at.
var baseline = []baselineTable{
	// Configuration and the work queue, which point at nothing.
	{"application_setting", settingsBaseline},
	{"job", jobBaseline},
	{"lease", leaseBaseline},
	{"schema_change", schemaChangeBaseline},

	// What is built, and who may see it.
	{"product", catalogBaseline},
	{"branch_or_tag", catalogBaseline},
	{"variant", catalogBaseline},
	{"build", catalogBaseline},
	{"repository_host", repositoryBaseline},
	{"repository_path", repositoryBaseline},
	{"party", accessBaseline},
	{"person", accessBaseline},
	{"person_identity", accessBaseline},
	{"session", accessBaseline},
	{"api_key", accessBaseline},
	{"personal_token", accessBaseline},
	{"group_role", accessBaseline},
	{"group_role_all", accessBaseline},
	{"group_admin", accessBaseline},
	{"role_grant", accessBaseline},
	{"role_grant_all", accessBaseline},
	{"team", teamBaseline},
	{"team_member", teamBaseline},
	{"assignment_rule", routingBaseline},
	{"admin_change", trailBaseline},
	{"upgrade", upgradeBaseline},

	// What a build is made of.
	{"scan", scanBaseline},
	{"scan_refusal", scanBaseline},
	{"scan_document", scanDocumentBaseline},
	{"scan_document_chunk", scanDocumentBaseline},
	{"component", componentBaseline},
	{"graph_node", graphNodeBaseline},
	{"graph_edge", graphEdgeBaseline},
	{"image_version", imageVersionBaseline},

	// What an analyzer said, run by run.
	{"series", seriesBaseline},
	{"series_run", seriesBaseline},
	{"series_document", seriesBaseline},
	{"series_document_chunk", seriesBaseline},
	{"series_module", seriesBaseline},
	{"series_refusal", seriesBaseline},

	// The issues, and what is known about them.
	{"vulnerability", vulnerabilityBaseline},
	{"vulnerability_alias", aliasBaseline},
	{"vulnerability_reference", issueBaseline},
	{"vulnerability_weakness", issueBaseline},
	{"vulnerability_rating", issueBaseline},
	{"issue_rating", issueRatingBaseline},
	{"recorded_rating", recordedRatingBaseline},
	{"issue_note", issueNoteBaseline},
	{"issue_note_revision", issueNoteBaseline},

	// Findings, and the judgments about them.
	{"scan_run", issueBaseline},
	{"decision", triageBaseline},
	{"decision_revision", triageBaseline},
	{"decision_approval", triageBaseline},
	{"decision_comment", triageBaseline},
	{"decision_comment_revision", commentHistoryBaseline},
	{"decision_build", claimBuildBaseline},
	{"decision_occurrence", triageBaseline},
	{"decision_stamp", decisionStampBaseline},
	{"statement_text", statementTextBaseline},
	{"suppression", suppressionBaseline},
	{"finding", findingBaseline},
	{"finding_label", tagBaseline},
	{"assessment", assessmentBaseline},
	{"vulnerability_merge", mergeBaseline},
	{"decision_occurrence_superseded", mergeBaseline},
	{"case_collaborator", collaboratorBaseline},
	{"sighting", seriesBaseline},
	{"analysis_result", analysisBaseline},
	{"analysis_location", analysisBaseline},
	{"suppression_rule", codeFindingBaseline},
	{"rule_rating", codeFindingBaseline},
	{"rule_family", codeFindingBaseline},
	{"code_finding_flaw", codeFindingBaseline},
	{"flaw_code_finding", codeFindingBaseline},
	{"flaw_code_finding_build", codeFindingBaseline},
	{"code_finding_component", codeFindingBaseline},
	{"code_finding_collaborator", codeFindingBaseline},

	// Flaws reported here, and what answers them.
	{"report_ruling", rulingBaseline},
	{"flaw_report", flawReportBaseline},
	{"flaw_report_revision", flawReportBaseline},
	{"report_note", flawReportBaseline},
	{"report_note_revision", flawReportBaseline},
	{"report_message", flawReportBaseline},
	{"report_assignment", flawReportBaseline},
	{"report_ruled", rulingBaseline},
	{"attachment", attachmentBaseline},
	{"disclosure_movement", disclosureMovementBaseline},
	{"response_window", obligationBaseline},
	{"response_window_product", obligationBaseline},
	{"incident", obligationBaseline},
	{"told_outside", obligationBaseline},
	{"told_place", obligationBaseline},
	{"incident_fix", obligationBaseline},
	{"patch_repository", patchBranchBaseline},
	{"patch_commit", patchBranchBaseline},
	{"patch_commit_branch", patchBranchBaseline},

	// What is published.
	{"supplier_advisory_feed", advisorySourceBaseline},
	{"document_upload", documentUploadBaseline},
	{"advisory", advisoryBaseline},
	{"advisory_edition", advisoryBaseline},
	{"advisory_approval", advisoryBaseline},
	{"advisory_issuance", advisoryBaseline},
	{"advisory_issue", advisoryBaseline},
	{"advisory_override", advisoryJudgmentBaseline},
	{"advisory_agreed_status", advisoryJudgmentBaseline},
	{"received_vex_statement", vexBaseline},
	{"published_vex", vexIssuanceBaseline},
	{"published_document", publishedDocumentBaseline},
	{"upstream", upstreamBaseline},
	{"upstream_document", upstreamBaseline},

	// Who is told, and how.
	{"notification", notificationBaseline},
	{"outbound", outboundBaseline},
	{"outbound_delivery", outboundDeliveryBaseline},
	{"chat_preference", chatBaseline},
	{"chat_delivery", chatBaseline},
	{"saved_filter", savedFilterBaseline},
}

// declaredV0110 is the baseline's declaration of one table and the indexes it
// makes, under the name the v0.14.0 upgrade reads it by.
func declaredV0110(t *columnTypes, table string) []string {
	for _, each := range baseline {
		if each.table != table {
			continue
		}
		made, indexes, err := pick(each.declared(t), table)
		if err != nil {
			panic(err)
		}
		return append([]string{made}, indexes...)
	}
	panic("the baseline makes no table " + table)
}
