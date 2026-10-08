// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upBaseline, nil)
}

// Baseline is the migration that makes v0.5.0's schema, the version a
// database v0.5.0 built records.
const Baseline = 39

// The schema v0.5.0 built, made directly on an empty database.
//
// Numbered as v0.5.0's last migration, so a database v0.5.0 or v0.6.0 built
// has it recorded already and applies only what follows. A database an
// earlier release built records a version below it, and is refused before
// anything runs (DESIGN-database.md § The baseline).
//
// The baseline files beside this one hold each table's declaration, with the
// reasoning for its shape. v0.5.0's record of the schema it built on each
// engine is what holds them to it.
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
	return apply(ctx, tx, statements)
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

	// What is built, and who may see it.
	{"product", catalogBaseline},
	{"stream", catalogBaseline},
	{"variant", catalogBaseline},
	{"target", catalogBaseline},
	{"party", accessBaseline},
	{"person", accessBaseline},
	{"person_identity", accessBaseline},
	{"session", accessBaseline},
	{"api_key", accessBaseline},
	{"personal_token", accessBaseline},
	{"group_role", accessBaseline},
	{"group_admin", accessBaseline},
	{"role_grant", accessBaseline},
	{"role_grant_all", accessBaseline},
	{"team", teamBaseline},
	{"team_member", teamBaseline},
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

	// The issues, and what is known about them.
	{"vulnerability", vulnerabilityBaseline},
	{"vulnerability_alias", aliasBaseline},
	{"vulnerability_reference", issueBaseline},
	{"vulnerability_weakness", issueBaseline},
	{"vulnerability_rating", issueBaseline},
	{"issue_rating", issueRatingBaseline},
	{"issue_note", issueNoteBaseline},
	{"issue_note_revision", issueNoteBaseline},

	// Findings, and the judgments about them.
	{"scan_run", issueBaseline},
	{"claim", triageBaseline},
	{"claim_revision", triageBaseline},
	{"claim_approval", triageBaseline},
	{"claim_comment", triageBaseline},
	{"claim_comment_revision", commentHistoryBaseline},
	{"claim_build", claimBuildBaseline},
	{"decision", triageBaseline},
	{"suppression", suppressionBaseline},
	{"finding", findingBaseline},
	{"finding_tag", tagBaseline},
	{"assessment", assessmentBaseline},
	{"vulnerability_merge", mergeBaseline},
	{"decision_superseded", mergeBaseline},
	{"case_collaborator", collaboratorBaseline},

	// Flaws reported here, and what answers them.
	{"report_ruling", rulingBaseline},
	{"flaw_report", flawReportBaseline},
	{"report_ruled", rulingBaseline},
	{"attachment", attachmentBaseline},
	{"disclosure_movement", disclosureMovementBaseline},
	{"obligation_window", obligationBaseline},
	{"obligation_window_product", obligationBaseline},
	{"exploited_here", obligationBaseline},
	{"told_outside", obligationBaseline},
	{"patch_repository", patchBranchBaseline},
	{"patch_commit", patchBranchBaseline},
	{"patch_commit_branch", patchBranchBaseline},

	// What is published.
	{"advisory_source", advisorySourceBaseline},
	{"advisory", advisoryBaseline},
	{"advisory_edition", advisoryBaseline},
	{"advisory_approval", advisoryBaseline},
	{"advisory_issuance", advisoryBaseline},
	{"advisory_issue", advisoryBaseline},
	{"advisory_override", advisoryJudgmentBaseline},
	{"advisory_agreed_status", advisoryJudgmentBaseline},
	{"vex_statement", vexBaseline},
	{"vex_issuance", vexIssuanceBaseline},

	// Who is told, and how.
	{"notification", notificationBaseline},
	{"routing_rule", routingBaseline},
	{"outbound", outboundBaseline},
	{"outbound_delivery", outboundDeliveryBaseline},
	{"chat_preference", chatBaseline},
	{"chat_delivery", chatBaseline},
	{"saved_filter", savedFilterBaseline},
}
