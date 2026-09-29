// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationNoTxContext(upV050, downV050)
}

// The v0.4.0 release's schema changed into v0.5.0's, and the rows it holds
// moved onto v0.5.0's rules.
//
// Run in one transaction of its own, the way migrations 37 and 38 are, and
// for the same reason: SQLite rebuilds the table it cannot alter, and its
// foreign keys are switched off before the transaction begins.
func upV050(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV050)
}

// downV050 puts back the schema v0.4.0 built, and the rows the way v0.4.0
// reads them.
func downV050(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, downgradeV050)
}

// upgradeV050 changes the schema v0.4.0 built into v0.5.0's and moves the rows.
//
// The v050 files beside this one hold v0.5.0's declaration of every table this
// changes.
//
//   - The administrative trail records who acted as a person or as the
//     deployment's startup configuration. Every row v0.4.0 wrote was a
//     person's, and keeps its person.
//   - Administration named in configuration is separated from administration
//     granted here. v0.4.0 wrote both into one column, so a name removed from
//     configuration left its administration standing. v0.5.0 reads the name
//     as a grant of its own, and the column holds only what was granted here
//     or derived from a group. A named administrator whose row says a group
//     derived it keeps that, because a group is what says so. Every other
//     named administrator's column is cleared: v0.4.0 kept nothing complete
//     that tells a grant made here apart from the one the name wrote, and
//     clearing it is the reading that ends with configuration deciding. The
//     administrative trail holds a grant made here that moved the column, and
//     none made while the name already had. They administer through the name
//     for as long as it stays in configuration.
//   - Each name an issue answers to records whether a person typed it. Every
//     name v0.4.0 holds takes the declared default and reads as not typed:
//     v0.4.0 kept the act in the administrative trail and nothing beside the
//     name. A column added with its default, which all four engines add where
//     the table stands.
//   - A graph node gains columns for the identifiers its build stated for the
//     component. Every open node takes the component row's, which is what
//     v0.4.0 gave a scanner, and the next scan of each build writes its own.
//     A closed node is left without: nothing reads a closed node's
//     identifiers.
//   - A component's identity is worked out again. v0.4.0 hashed a package
//     identifier and a name with a version into one space, and v0.5.0 hashes
//     them apart. Each row's identity comes from the row's own identifier, or
//     its name and version where it has none, so no two rows meet: two rows
//     v0.4.0 held apart differ in what is hashed.
//   - A scan and a refused upload record who sent them as a key or a person
//     and its identifier, where v0.4.0 recorded a name. A name a key holds is
//     read as that key, and otherwise a name a person holds as that person. A
//     name held by neither stays as it is, and narrows nothing.
//   - An issue states the issue it is read as. v0.4.0 merged nothing, so every
//     row is read as itself.
//   - A merge of two issues, and a decision one superseded, are recorded in
//     two new tables. v0.4.0 refused the report that would have merged them,
//     so both start empty.
//   - A rating claim states why it was withdrawn where no person withdrew it.
//     Every claim v0.4.0 withdrew, a person withdrew, so the column starts
//     empty.
//   - A notification names the team whose queue it is about, and a
//     destination may be a chat channel belonging to the deployment, a
//     product or a team. Every destination v0.4.0 held is a signed request
//     belonging to the deployment.
//   - What somebody chose about chat, and what has been carried to them there,
//     are tables of their own. Nothing v0.4.0 held goes in either.
//   - A kept findings-list filter is rewritten into the words v0.5.0's list
//     reads: the two flags "only" named become flags of their own, and hidden
//     components joined by commas become one parameter each.
//   - A saved filter belongs to its person rather than to a product, and
//     keeps no scope. Where one person kept one name in several products,
//     the oldest keeps it and the others are renamed after their product.
//   - A key's name and a personal token's are stored folded, the way a
//     username is: a key's unique across the deployment, a token's to its
//     owner. v0.4.0 stored them as typed, so two names it held apart can fold
//     to one. The first to hold the name keeps it and stays as it was — one in
//     force before a withdrawn one, then the oldest. Every other one is
//     withdrawn where it is still in force, recorded in the trail with the
//     upgrade as the actor, and named by its folded name and its number,
//     because the name is unique across withdrawn ones too. The senders are
//     read before this, by the names v0.4.0 recorded.
//   - A build's claim records the name of what it is about folded, beside the
//     name as the producer spelled it. Each claim v0.4.0 holds takes its own
//     name folded.
//   - An issue records the day the known-exploited catalog listed it. v0.4.0
//     read no day, so the column starts empty and the first scan stating one
//     re-clocks the issue's open exploited findings.
//   - A movement of an embargo may be one a ruling recorded, naming the ruling
//     and the claim its date counts from, and its dates may be absent. A flaw
//     recorded here that v0.4.0 left undated under a duplicate ruling from
//     outside is dated, and each such date recorded as a movement from its
//     ruling.
func upgradeV050(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	if err := u.change(aliasV050(t), change{table: "vulnerability_alias",
		add: []added{{column: "by_hand"}}}); err != nil {
		return err
	}

	if err := u.change(trailV050(t), change{table: "admin_change",
		add:   []added{{column: "actor", fill: "'person'"}},
		relax: []string{"by"}}); err != nil {
		return err
	}
	if _, err := tx.NewRaw(`UPDATE "person" SET "is_admin" = ?`+
		` WHERE "is_bootstrap" = ? AND "admin_derived" = ?`, false, true, false).
		Exec(ctx); err != nil {
		return fmt.Errorf("separate administration named in configuration: %w", err)
	}

	if err := u.change(graphNodeV050(t), change{table: "graph_node",
		add: []added{{column: "purl"}, {column: "cpe"}}}); err != nil {
		return err
	}
	if err := statedFromComponents(ctx, tx); err != nil {
		return err
	}
	if err := reidentified(ctx, tx, identityV050); err != nil {
		return err
	}
	if err := savedFiltersRespelled(ctx, tx); err != nil {
		return err
	}
	if err := savedFiltersPersonal(ctx, tx); err != nil {
		return err
	}
	if err := sendersQualified(ctx, tx); err != nil {
		return err
	}
	// After the senders, which are matched on the names v0.4.0 recorded.
	if err := namesFolded(ctx, tx, keysV050); err != nil {
		return err
	}
	if err := namesFolded(ctx, tx, tokensV050); err != nil {
		return err
	}
	if err := u.change(suppressionV050(t), change{table: "suppression",
		add: []added{{column: "subject_folded"}}}); err != nil {
		return err
	}
	if err := subjectsFolded(ctx, tx); err != nil {
		return err
	}
	// A column every existing row fills from its own identifier. A default
	// cannot name another column, so it is added holding zero and each row is
	// then pointed at itself.
	if err := u.change(vulnerabilityV050(t), change{table: "vulnerability",
		add:     []added{{column: "issue_id", fill: "0"}, {column: "exploited_on"}},
		then:    func() error { return eachIssueItself(ctx, tx) },
		indexes: []string{"vulnerability_issue_idx"}}); err != nil {
		return err
	}
	if err := u.create(mergeV050(t), "vulnerability_merge", "decision_superseded"); err != nil {
		return err
	}
	if err := movementsFromRulings(ctx, u); err != nil {
		return err
	}
	if err := u.change(assessmentV050(t), change{table: "assessment",
		add: []added{{column: "withdrawn_because"}}}); err != nil {
		return err
	}
	if err := u.change(notificationV050(t), change{table: "notification",
		add:         []added{{column: "team_id"}},
		constraints: []string{"notification_team_fk"}}); err != nil {
		return err
	}
	if err := u.change(outboundV050(t), change{table: "outbound",
		add: []added{
			{column: "platform", fill: "'webhook'"},
			{column: "channel"}, {column: "topic"},
			{column: "product_id"}, {column: "team_id"},
		},
		constraints: []string{"outbound_product_fk", "outbound_team_fk"}}); err != nil {
		return err
	}
	return u.create(chatV050(t), "chat_preference", "chat_delivery")
}

// eachIssueItself reads every issue as itself, which is what an issue nothing
// merged is.
func eachIssueItself(ctx context.Context, tx bun.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE "vulnerability" SET "issue_id" = "id"`); err != nil {
		return fmt.Errorf("read every issue as itself: %w", err)
	}
	return nil
}

// downgradeV050 puts back what v0.4.0 reads.
//
// Each component takes v0.4.0's identity again and a sender is recorded by
// name before any table changes, so a refusal leaves the database as v0.5.0
// left it on every engine. The node columns go.
//
// The merges go with the tables that recorded them, and the reason a merge
// gave for withdrawing a rating claim with its column. The findings a merge
// moved stay with the issue they moved to, and what was decided under the
// issue it absorbed stays filed under that issue, which v0.4.0 reads as an
// issue with no findings.
//
// The name is written back into the administration column, which is where
// v0.4.0 reads it. A trail row configuration or a merge wrote has no person,
// which v0.4.0 has no place for, so it goes with the column that says who
// acted. Whether a person typed each name an issue answers to goes with its
// column, and the names stay. A kept filter stays in v0.5.0's words, which
// v0.4.0's list reads too, except that a hidden name holding a comma is read
// by v0.4.0 as several names, and upgrading again keeps them apart. Each
// saved filter is kept in every product, where v0.5.0 offered it. A claim's
// folded subject goes with its column. A key or token keeps the name it was
// folded or numbered to, which v0.4.0 matches as typed, and one the upgrade
// withdrew stays withdrawn: nothing says it would still be wanted. The trail
// rows recording those withdrawals go, because v0.4.0 has no place for a
// change no person made. The day an issue was listed as exploited goes with
// its column. A movement a ruling recorded goes, and the date it set stays.
func downgradeV050(ctx context.Context, tx bun.Tx) error {
	if err := reidentified(ctx, tx, identityV040); err != nil {
		return err
	}
	if err := sendersNamed(ctx, tx); err != nil {
		return err
	}
	if err := savedFiltersProductsBack(ctx, tx); err != nil {
		return err
	}
	// A chat channel is a destination v0.4.0 cannot reach, so it goes with
	// what it delivered.
	for _, stmt := range []string{
		`DELETE FROM "outbound_delivery" WHERE "outbound_id" IN ` +
			`(SELECT "id" FROM "outbound" WHERE "platform" <> 'webhook')`,
		`DELETE FROM "outbound" WHERE "platform" <> 'webhook'`,
	} {
		if _, err := tx.NewRaw(stmt).Exec(ctx); err != nil {
			return fmt.Errorf("remove the chat channels v0.4.0 cannot reach: %w", err)
		}
	}
	if err := dropTables(ctx, tx.Tx, "chat_delivery", "chat_preference"); err != nil {
		return err
	}
	if err := dropTables(ctx, tx.Tx, "decision_superseded", "vulnerability_merge"); err != nil {
		return err
	}
	if err := dropIndex(ctx, tx.Tx, "vulnerability", "vulnerability_issue_idx"); err != nil {
		return err
	}
	if err := apply(ctx, tx.Tx, []string{
		`ALTER TABLE "suppression" DROP COLUMN "subject_folded"`,
		`ALTER TABLE "assessment" DROP COLUMN "withdrawn_because"`,
		`ALTER TABLE "vulnerability" DROP COLUMN "issue_id"`,
		`ALTER TABLE "vulnerability" DROP COLUMN "exploited_on"`,
		`DELETE FROM "admin_change" WHERE "actor" = 'merge'`,
		`DELETE FROM "admin_change" WHERE "actor" = 'upgrade'`,
	}); err != nil {
		return err
	}

	if _, err := tx.NewRaw(`UPDATE "person" SET "is_admin" = ? WHERE "is_bootstrap" = ?`,
		true, true).Exec(ctx); err != nil {
		return fmt.Errorf("fold administration named in configuration back in: %w", err)
	}

	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	if err := u.movementsNarrowed(); err != nil {
		return err
	}
	if err := u.narrow(narrowing{table: "notification",
		keys: []string{"notification_team_fk"}, columns: []string{"team_id"}}); err != nil {
		return err
	}
	if err := u.narrow(narrowing{table: "outbound",
		keys:    []string{"outbound_product_fk", "outbound_team_fk"},
		columns: []string{"platform", "channel", "topic", "product_id", "team_id"}}); err != nil {
		return err
	}
	// Which names a person typed goes with its column. The names stay.
	if err := u.run([]string{`ALTER TABLE "vulnerability_alias" DROP COLUMN "by_hand"`}); err != nil {
		return err
	}
	if err := u.trailNarrowed(t); err != nil {
		return err
	}
	return apply(ctx, tx.Tx, []string{
		`ALTER TABLE "graph_node" DROP COLUMN "cpe"`,
		`ALTER TABLE "graph_node" DROP COLUMN "purl"`,
	})
}

// trailNarrowed puts back the administrative trail v0.4.0 built: no actor,
// and a person on every row.
func (u *upgrader) trailNarrowed(t *columnTypes) error {
	return u.narrowRequiring(narrowing{table: "admin_change",
		forget:  `DELETE FROM "admin_change" WHERE "actor" = 'configuration'`,
		columns: []string{"actor"}}, trailV050(t), "by")
}
