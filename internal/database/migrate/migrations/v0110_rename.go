// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// A rename changes a name in the catalog and touches no row on any engine at
// its floor, so how long it takes does not grow with the data. What it can do
// is wait: a rename takes the strongest lock a table has, behind anything
// already reading it. Each one therefore waits a few seconds at most, says
// what holds the table, and tries again, rather than queueing every request
// behind it with nothing saying why.

// tableRename is a table's name before and after.
type tableRename struct{ from, to string }

// tablesRenamedV0110 is every table v0.11.0 renames, in order. The rows a
// decision writes at each occurrence move first, because the name a decision
// takes is theirs until they do.
var tablesRenamedV0110 = []tableRename{
	{"decision", "decision_occurrence"},
	{"decision_superseded", "decision_occurrence_superseded"},
	{"claim", "decision"},
	{"claim_revision", "decision_revision"},
	{"claim_approval", "decision_approval"},
	{"claim_comment", "decision_comment"},
	{"claim_comment_revision", "decision_comment_revision"},
	{"claim_build", "decision_build"},
	{"exploited_here", "incident"},
	{"exploited_fix", "incident_fix"},
	{"obligation_window", "response_window"},
	{"obligation_window_product", "response_window_product"},
	{"routing_rule", "assignment_rule"},
	{"advisory_source", "supplier_advisory_feed"},
	{"finding_tag", "finding_label"},
}

// columnRename is a column's name before and after, on its table as v0.11.0
// names the table.
type columnRename struct{ table, from, to string }

// columnsRenamedV0110 is every column v0.11.0 renames, in order. A superseded
// row's column moves first, because the name the others take is its own until
// it does.
var columnsRenamedV0110 = []columnRename{
	{"decision_occurrence_superseded", "decision_id", "decision_occurrence_id"},
	{"decision_occurrence", "claim_id", "decision_id"},
	{"decision_occurrence", "place_identity", "occurrence_identity"},
	{"decision_revision", "claim_id", "decision_id"},
	{"decision_approval", "claim_id", "decision_id"},
	{"decision_comment", "claim_id", "decision_id"},
	{"decision_build", "claim_id", "decision_id"},
	{"upgrade", "claim_id", "decision_id"},
	{"finding", "place_identity", "occurrence_identity"},
	{"incident_fix", "exploited_here_id", "incident_id"},
	{"told_outside", "exploited_here_id", "incident_id"},
	{"finding", "urgency_exploited_here", "urgency_incident"},
	{"product", "triage_floor", "minimum_severity"},
	{"finding", "routed_by", "assigned_by_rule"},
	{"finding_label", "tag", "label"},
}

// nameKind is what a renamed name belongs to, which decides how each engine
// renames it.
type nameKind int

const (
	// anIndex is an index no constraint is named by.
	anIndex nameKind = iota
	// aUnique is a unique constraint, which MySQL and MariaDB hold as an
	// index of the same name.
	aUnique
	// aForeignKey is a foreign key. MySQL and MariaDB also name the index
	// they made for it, where no other index served, by the key's name.
	aForeignKey
	// aPrimaryKey is a primary key, which only PostgreSQL names.
	aPrimaryKey
)

// nameRename is an index's or a constraint's name before and after, on its
// table as v0.11.0 names the table.
type nameRename struct {
	kind            nameKind
	table, from, to string
}

// namesRenamedV0110 is every index and constraint v0.11.0 renames, in order.
// An occurrence's names move before a decision's, because a decision takes
// several of them. PostgreSQL holds an index name once per schema and MySQL a
// foreign key's, so a name is free only once its holder has moved.
var namesRenamedV0110 = []nameRename{
	{aPrimaryKey, "decision_occurrence", "decision_pkey", "decision_occurrence_pkey"},
	{aUnique, "decision_occurrence", "decision_live_unique", "decision_occurrence_live_unique"},
	{aForeignKey, "decision_occurrence", "decision_claim_fk", "decision_occurrence_decision_fk"},
	{aForeignKey, "decision_occurrence", "decision_product_fk", "decision_occurrence_product_fk"},
	{aForeignKey, "decision_occurrence", "decision_vulnerability_fk", "decision_occurrence_vulnerability_fk"},
	{aForeignKey, "decision_occurrence", "decision_proposer_fk", "decision_occurrence_proposer_fk"},
	{anIndex, "decision_occurrence", "decision_applies_idx", "decision_occurrence_applies_idx"},
	{anIndex, "decision_occurrence", "decision_claim_idx", "decision_occurrence_decision_idx"},
	{anIndex, "decision_occurrence", "decision_state_claim_idx", "decision_occurrence_state_decision_idx"},

	{aPrimaryKey, "decision_occurrence_superseded", "decision_superseded_pkey", "decision_occurrence_superseded_pkey"},
	{aUnique, "decision_occurrence_superseded", "decision_superseded_once", "decision_occurrence_superseded_once"},
	{aForeignKey, "decision_occurrence_superseded", "decision_superseded_decision_fk",
		"decision_occurrence_superseded_occurrence_fk"},
	{aForeignKey, "decision_occurrence_superseded", "decision_superseded_standing_fk",
		"decision_occurrence_superseded_standing_fk"},
	{aForeignKey, "decision_occurrence_superseded", "decision_superseded_merge_fk",
		"decision_occurrence_superseded_merge_fk"},

	{aPrimaryKey, "decision", "claim_pkey", "decision_pkey"},
	{aForeignKey, "decision", "claim_proposer_fk", "decision_proposer_fk"},
	{aForeignKey, "decision", "claim_derived_fk", "decision_derived_fk"},
	{anIndex, "decision", "claim_derived_idx", "decision_derived_idx"},

	{aPrimaryKey, "decision_revision", "claim_revision_pkey", "decision_revision_pkey"},
	{aUnique, "decision_revision", "claim_revision_unique", "decision_revision_unique"},
	{aForeignKey, "decision_revision", "claim_revision_claim_fk", "decision_revision_decision_fk"},
	{aForeignKey, "decision_revision", "claim_revision_author_fk", "decision_revision_author_fk"},

	{aPrimaryKey, "decision_approval", "claim_approval_pkey", "decision_approval_pkey"},
	{aForeignKey, "decision_approval", "claim_approval_carried_fk", "decision_approval_carried_fk"},
	{aForeignKey, "decision_approval", "claim_approval_claim_fk", "decision_approval_decision_fk"},
	{aForeignKey, "decision_approval", "claim_approval_revision_fk", "decision_approval_revision_fk"},
	{aForeignKey, "decision_approval", "claim_approval_approver_fk", "decision_approval_approver_fk"},
	{aForeignKey, "decision_approval", "claim_approval_withdrawer_fk", "decision_approval_withdrawer_fk"},
	{anIndex, "decision_approval", "claim_approval_claim_idx", "decision_approval_decision_idx"},
	{anIndex, "decision_approval", "claim_approval_batch_idx", "decision_approval_batch_idx"},

	{aPrimaryKey, "decision_comment", "claim_comment_pkey", "decision_comment_pkey"},
	{aForeignKey, "decision_comment", "claim_comment_claim_fk", "decision_comment_decision_fk"},
	{aForeignKey, "decision_comment", "claim_comment_author_fk", "decision_comment_author_fk"},
	{anIndex, "decision_comment", "claim_comment_claim_idx", "decision_comment_decision_idx"},

	{aPrimaryKey, "decision_comment_revision", "claim_comment_revision_pkey", "decision_comment_revision_pkey"},
	{aForeignKey, "decision_comment_revision", "claim_comment_revision_fk", "decision_comment_revision_fk"},
	{aUnique, "decision_comment_revision", "claim_comment_revision_once", "decision_comment_revision_once"},

	{aPrimaryKey, "decision_build", "claim_build_pkey", "decision_build_pkey"},
	{aUnique, "decision_build", "claim_build_once", "decision_build_once"},
	{aForeignKey, "decision_build", "claim_build_claim_fk", "decision_build_decision_fk"},
	{aForeignKey, "decision_build", "claim_build_target_fk", "decision_build_target_fk"},

	{anIndex, "finding", "finding_place_idx", "finding_occurrence_idx"},

	{aPrimaryKey, "incident", "exploited_here_pkey", "incident_pkey"},
	{aUnique, "incident", "exploited_here_live_unique", "incident_live_unique"},
	{aForeignKey, "incident", "exploited_here_vulnerability_fk", "incident_vulnerability_fk"},
	{aForeignKey, "incident", "exploited_here_product_fk", "incident_product_fk"},
	{aForeignKey, "incident", "exploited_here_recorder_fk", "incident_recorder_fk"},
	{aForeignKey, "incident", "exploited_here_clearer_fk", "incident_clearer_fk"},
	{anIndex, "incident", "exploited_here_product_idx", "incident_product_idx"},
	{anIndex, "incident", "exploited_here_issue_idx", "incident_issue_idx"},

	{aPrimaryKey, "incident_fix", "exploited_fix_pkey", "incident_fix_pkey"},
	{aUnique, "incident_fix", "exploited_fix_live_unique", "incident_fix_live_unique"},
	{aForeignKey, "incident_fix", "exploited_fix_record_fk", "incident_fix_incident_fk"},
	{aForeignKey, "incident_fix", "exploited_fix_stream_fk", "incident_fix_stream_fk"},
	{aForeignKey, "incident_fix", "exploited_fix_namer_fk", "incident_fix_namer_fk"},
	{aForeignKey, "incident_fix", "exploited_fix_withdrawer_fk", "incident_fix_withdrawer_fk"},

	{aForeignKey, "told_outside", "told_outside_record_fk", "told_outside_incident_fk"},
	{anIndex, "told_outside", "told_outside_record_idx", "told_outside_incident_idx"},

	{aPrimaryKey, "response_window", "obligation_window_pkey", "response_window_pkey"},
	{aUnique, "response_window", "obligation_window_live_unique", "response_window_live_unique"},
	{aForeignKey, "response_window", "obligation_window_declarer_fk", "response_window_declarer_fk"},
	{aForeignKey, "response_window", "obligation_window_from_fk", "response_window_from_fk"},

	{aPrimaryKey, "response_window_product", "obligation_window_product_pk", "response_window_product_pk"},
	{aForeignKey, "response_window_product", "obligation_window_product_window_fk",
		"response_window_product_window_fk"},
	{aForeignKey, "response_window_product", "obligation_window_product_product_fk",
		"response_window_product_product_fk"},

	{anIndex, "job", "job_set_aside_idx", "job_failed_idx"},

	{aPrimaryKey, "assignment_rule", "routing_rule_pkey", "assignment_rule_pkey"},
	{aForeignKey, "assignment_rule", "routing_rule_product_fk", "assignment_rule_product_fk"},
	{aForeignKey, "assignment_rule", "routing_rule_team_fk", "assignment_rule_team_fk"},
	{aForeignKey, "assignment_rule", "routing_rule_by_fk", "assignment_rule_by_fk"},
	{anIndex, "assignment_rule", "routing_rule_order_idx", "assignment_rule_order_idx"},

	{aPrimaryKey, "supplier_advisory_feed", "advisory_source_pkey", "supplier_advisory_feed_pkey"},
	{aUnique, "supplier_advisory_feed", "advisory_source_named_once", "supplier_advisory_feed_named_once"},
	{aForeignKey, "supplier_advisory_feed", "advisory_source_product_fk", "supplier_advisory_feed_product_fk"},
	{aForeignKey, "supplier_advisory_feed", "advisory_source_by_fk", "supplier_advisory_feed_by_fk"},
	{anIndex, "supplier_advisory_feed", "advisory_source_due_idx", "supplier_advisory_feed_due_idx"},

	{aPrimaryKey, "finding_label", "finding_tag_pkey", "finding_label_pkey"},
	{aUnique, "finding_label", "finding_tag_once", "finding_label_once"},
	{aForeignKey, "finding_label", "finding_tag_product_fk", "finding_label_product_fk"},
	{aForeignKey, "finding_label", "finding_tag_issue_fk", "finding_label_issue_fk"},
	{aForeignKey, "finding_label", "finding_tag_component_fk", "finding_label_component_fk"},
	{aForeignKey, "finding_label", "finding_tag_by_fk", "finding_label_by_fk"},
	{anIndex, "finding_label", "finding_tag_named_idx", "finding_label_named_idx"},
}

// renamesV0110 is every name above, from its v0.10.0 spelling to its v0.11.0
// one. Each name changes once whichever list holds it, so one map serves a
// table, a column and a constraint alike. A column's name is renamed in every
// declaration the map rewrites, so a column is listed only where no other
// renamed table holds one of the same name: tag is finding_label's alone.
var renamesV0110 = func() map[string]string {
	out := map[string]string{}
	add := func(from, to string) {
		if was, ok := out[from]; ok && was != to {
			panic("v0.11.0 renames " + from + " twice")
		}
		out[from] = to
	}
	for _, r := range tablesRenamedV0110 {
		add(r.from, r.to)
	}
	for _, r := range columnsRenamedV0110 {
		add(r.from, r.to)
	}
	for _, r := range namesRenamedV0110 {
		add(r.from, r.to)
	}
	return out
}()

var quotedName = regexp.MustCompile(`"([a-z0-9_]+)"`)

// renamedV0110 is a declaration v0.10.0 holds, with every quoted name v0.11.0
// renames spelled as v0.11.0 spells it. Each name is looked up once, so one
// renamed to a name another held is not renamed again.
func renamedV0110(statements []string) []string {
	out := make([]string, len(statements))
	for i, stmt := range statements {
		out[i] = quotedName.ReplaceAllStringFunc(stmt, func(q string) string {
			if to, ok := renamesV0110[q[1:len(q)-1]]; ok {
				return `"` + to + `"`
			}
			return q
		})
	}
	return out
}

// keptV0110 is each table v0.11.0 renames a column or an index of and keeps
// the name of, with the declaration the table last had.
var keptV0110 = map[string]func(*columnTypes) []string{
	"upgrade":      upgradeBaseline,
	"job":          jobBaseline,
	"told_outside": obligationBaseline,
	"product":      productV0100,
}

// declaredV0110 is v0.11.0's declaration of a table it renames or renames
// something in, and the indexes it makes: the declaration the table last had,
// renamed.
func declaredV0110(t *columnTypes, table string) []string {
	var before string
	var statements []string
	for _, r := range tablesRenamedV0110 {
		if r.to == table {
			before = r.from
		}
	}
	switch before {
	case "decision":
		statements = decisionV080(t)
	case "claim":
		statements = claimV0100(t)
	case "decision_superseded":
		statements = mergeBaseline(t)
	case "claim_comment_revision":
		statements = commentHistoryBaseline(t)
	case "claim_build":
		statements = claimBuildBaseline(t)
	case "exploited_here", "exploited_fix", "obligation_window", "obligation_window_product":
		statements = obligationBaseline(t)
	case "routing_rule":
		statements = routingBaseline(t)
	case "advisory_source":
		statements = advisorySourceBaseline(t)
	case "finding_tag":
		statements = tagBaseline(t)
	case "":
		kept, ok := keptV0110[table]
		if !ok {
			panic("v0.11.0 gives no table the name " + table)
		}
		before, statements = table, kept(t)
	default:
		statements = triageBaseline(t)
	}
	made, indexes, err := pick(statements, before)
	if err != nil {
		panic(err)
	}
	return renamedV0110(append([]string{made}, indexes...))
}

// renameAttemptWait bounds how long one rename waits for its table, and the
// pause before the next attempt. Seconds: MySQL and MariaDB count the wait in
// whole seconds.
const (
	renameAttemptWait  = 3
	renamePause        = time.Second
	renameHoldersShown = 20
)

// renameV0110 gives the renamed tables, columns, indexes and constraints their
// v0.11.0 names. It runs before anything else the upgrade does, so the rest
// of it, and the declarations it is written against, use the new names.
//
// PostgreSQL and SQLite run every rename inside the upgrade's one
// transaction, so a failure leaves every name as it was. MySQL and MariaDB
// commit each one as it runs, so each asks first whether it is already done
// and steps over it if so: a start that stopped part way resumes.
func renameV0110(ctx context.Context, tx bun.Tx) error {
	return renameV0110Stopping(ctx, tx, "")
}

// errRenameStopped is what a rename stopped on purpose returns.
var errRenameStopped = errors.New("the renames were stopped part way")

// renameV0110Stopping renames as renameV0110 does, and where stopAfter names
// something renamed, stops once the first statement renaming it has run: an
// upgrade that stopped there.
func renameV0110Stopping(ctx context.Context, tx bun.Tx, stopAfter string) (err error) {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	r := renamer{u: u, stopAfter: stopAfter}
	restore, err := r.bound()
	if err != nil {
		return err
	}
	defer func() {
		if undo := restore(); undo != nil && err == nil {
			err = undo
		}
	}()
	for _, t := range tablesRenamedV0110 {
		if err := r.table(t); err != nil {
			return err
		}
	}
	for _, c := range columnsRenamedV0110 {
		if err := r.column(c); err != nil {
			return err
		}
	}
	for _, n := range namesRenamedV0110 {
		if err := r.name(n); err != nil {
			return err
		}
	}
	if u.engine == database.Postgres {
		for _, t := range tablesRenamedV0110 {
			if err := r.sequence(t.to); err != nil {
				return err
			}
		}
	}
	return nil
}

// renamer runs one upgrade's renames.
type renamer struct {
	u         *upgrader
	stopAfter string
}

// resumable reports whether a rename asks whether it is already done: on the
// two engines that commit each one as it runs.
func (r renamer) resumable() bool {
	return r.u.engine == database.MySQL || r.u.engine == database.MariaDB
}

// bound sets how long one statement waits for a lock, and returns what puts
// it back. MySQL and MariaDB add a foreign key without reading a row only
// while foreign keys are not checked, so that is set for the renames as well.
// SQLite holds the database for the whole upgrade, so nothing waits there.
func (r renamer) bound() (func() error, error) {
	var set, reset []string
	switch r.u.engine {
	case database.Postgres:
		set = []string{fmt.Sprintf("SET LOCAL lock_timeout = '%ds'", renameAttemptWait)}
		reset = []string{"SET LOCAL lock_timeout TO DEFAULT"}
	case database.MySQL, database.MariaDB:
		set = []string{fmt.Sprintf("SET SESSION lock_wait_timeout = %d", renameAttemptWait),
			"SET SESSION foreign_key_checks = 0"}
		reset = []string{"SET SESSION lock_wait_timeout = DEFAULT", "SET SESSION foreign_key_checks = 1"}
	default:
		return func() error { return nil }, nil
	}
	for _, stmt := range set {
		if _, err := r.u.raw.ExecContext(r.u.ctx, stmt); err != nil {
			return nil, fmt.Errorf("bound the wait to rename: %w", err)
		}
	}
	return func() error {
		for _, stmt := range reset {
			if _, err := r.u.raw.ExecContext(context.WithoutCancel(r.u.ctx), stmt); err != nil {
				return fmt.Errorf("lift the bound on the wait to rename: %w", err)
			}
		}
		return nil
	}, nil
}

func (r renamer) table(t tableRename) error {
	if r.resumable() {
		done, err := r.u.hasTable(t.to)
		if err != nil || r.skipped(done, "table "+t.from) {
			return err
		}
	}
	stmt := `ALTER TABLE "` + t.from + `" RENAME TO "` + t.to + `"`
	if r.resumable() {
		stmt = `RENAME TABLE "` + t.from + `" TO "` + t.to + `"`
	}
	return r.exec(t.from, t.from, stmt)
}

func (r renamer) column(c columnRename) error {
	if r.resumable() {
		left, err := r.u.hasColumn(c.table, c.from)
		if err != nil || r.skipped(!left, "column "+c.table+"."+c.from) {
			return err
		}
	}
	return r.exec(c.table, c.from, `ALTER TABLE "`+c.table+`" RENAME COLUMN "`+c.from+`" TO "`+c.to+`"`)
}

func (r renamer) name(n nameRename) error {
	switch r.u.engine {
	case database.Postgres:
		if n.kind == anIndex {
			return r.exec(n.table, n.from, `ALTER INDEX "`+n.from+`" RENAME TO "`+n.to+`"`)
		}
		return r.exec(n.table, n.from, `ALTER TABLE "`+n.table+`" RENAME CONSTRAINT "`+n.from+`" TO "`+n.to+`"`)
	case database.SQLite:
		// A constraint's name is part of a SQLite table's text, which only
		// rebuilding the table rewrites, and SQLite reports none of them.
		if n.kind != anIndex {
			return nil
		}
		return r.sqliteIndex(n)
	}
	switch n.kind {
	case aPrimaryKey:
		return nil
	case aForeignKey:
		// The index first. MySQL drops the index it made for a foreign key
		// along with the key when the key is declared again, and builds one
		// under the new name, which reads every row; an index renamed first
		// is no longer the key's own and serves the new key as it stands.
		if err := r.mysqlIndex(n); err != nil {
			return err
		}
		return r.mysqlForeignKey(n)
	}
	return r.mysqlIndex(n)
}

// mysqlForeignKey renames a foreign key on MySQL or MariaDB, which have no
// statement for it: the key is dropped and declared again in one statement,
// in place, under the new name. With foreign keys not checked, adding one
// reads no row, and the index the key had serves the new one.
func (r renamer) mysqlForeignKey(n nameRename) error {
	held, err := r.u.hasForeignKey(n.table, n.from)
	if err != nil || r.skipped(!held, "foreign key "+n.from) {
		return err
	}
	made, _, err := pick(declaredV0110(r.u.t, n.table), n.table)
	if err != nil {
		return err
	}
	items, err := declared(made)
	if err != nil {
		return err
	}
	def, err := items.constraint(n.to)
	if err != nil {
		return err
	}
	return r.exec(n.table, n.from, `ALTER TABLE "`+n.table+`" DROP FOREIGN KEY "`+n.from+`", ADD `+def+
		`, ALGORITHM=INPLACE`)
}

// mysqlIndex renames an index on MySQL or MariaDB, and with it a unique
// constraint, or the index made for a foreign key where there is one.
func (r renamer) mysqlIndex(n nameRename) error {
	held, err := r.u.hasIndex(n.table, n.from)
	if err != nil {
		return err
	}
	if !held {
		if n.kind == aForeignKey {
			return nil
		}
		r.skipped(true, "index "+n.from)
		return nil
	}
	return r.exec(n.table, n.from, `ALTER TABLE "`+n.table+`" RENAME INDEX "`+n.from+`" TO "`+n.to+`"`)
}

// sqliteIndex renames an index on SQLite, which has no statement for it, by
// making it again under the new name. SQLite is a development database, never
// a production one, so building an index again costs nothing that matters.
func (r renamer) sqliteIndex(n nameRename) error {
	var made string
	err := r.u.tx.QueryRowContext(r.u.ctx, `SELECT "sql" FROM "sqlite_master"
		WHERE "type" = 'index' AND "name" = ?`, n.from).Scan(&made)
	if err != nil {
		return fmt.Errorf("read index %s: %w", n.from, err)
	}
	if err := r.u.run([]string{`DROP INDEX "` + n.from + `"`}); err != nil {
		return err
	}
	return r.exec(n.table, n.from, strings.Replace(made, `"`+n.from+`"`, `"`+n.to+`"`, 1))
}

// sequence names a renamed PostgreSQL table's identifier sequence after the
// table. A table keyed by the rows it joins has no identifier and no sequence.
func (r renamer) sequence(table string) error {
	identified, err := r.u.hasColumn(table, "id")
	if err != nil || !identified {
		return err
	}
	var had string
	if err := r.u.tx.QueryRowContext(r.u.ctx, `SELECT pg_get_serial_sequence(?, 'id')`,
		`"`+table+`"`).Scan(&had); err != nil {
		return fmt.Errorf("read the sequence of %s: %w", table, err)
	}
	return r.exec(table, had, `ALTER SEQUENCE `+had+` RENAME TO "`+table+`_id_seq"`)
}

// skipped logs a rename stepped over because a start that stopped had made it.
func (r renamer) skipped(done bool, what string) bool {
	if done {
		migrate.LoggerFrom(r.u.ctx).Warn("a migration is resuming past a rename it had already made",
			"renamed", what)
	}
	return done
}

// exec runs one statement renaming from, and when it waits out its bound,
// says what holds the table and tries again until it runs or the upgrade is
// stopped. On PostgreSQL the attempt is a savepoint, because a statement that
// failed otherwise ends the transaction.
func (r renamer) exec(table, from, stmt string) error {
	for attempt := 1; ; attempt++ {
		err := r.attempt(stmt)
		if err == nil {
			if from == r.stopAfter {
				return errRenameStopped
			}
			return nil
		}
		if !lockWaitedOut(err) {
			return fmt.Errorf("%s: %w", stmt, err)
		}
		migrate.LoggerFrom(r.u.ctx).Warn("a rename is waiting for a table something else holds",
			"table", table, "attempt", attempt, "held_by", r.holders(table))
		select {
		case <-r.u.ctx.Done():
			return fmt.Errorf("%s: %w", stmt, r.u.ctx.Err())
		case <-time.After(renamePause):
		}
	}
}

func (r renamer) attempt(stmt string) error {
	if r.u.engine != database.Postgres {
		_, err := r.u.raw.ExecContext(r.u.ctx, stmt)
		return err
	}
	if _, err := r.u.raw.ExecContext(r.u.ctx, `SAVEPOINT "renaming"`); err != nil {
		return err
	}
	if _, err := r.u.raw.ExecContext(r.u.ctx, stmt); err != nil {
		if _, back := r.u.raw.ExecContext(r.u.ctx, `ROLLBACK TO SAVEPOINT "renaming"`); back != nil {
			return errors.Join(err, back)
		}
		return err
	}
	_, err := r.u.raw.ExecContext(r.u.ctx, `RELEASE SAVEPOINT "renaming"`)
	return err
}

// lockWaitedOut reports whether a statement gave up waiting for a lock.
func lockWaitedOut(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "55P03" // lock not available
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1205 // lock wait timeout exceeded
	}
	return false
}

// holders is every other session holding a lock on the table, as the engine
// describes it: on PostgreSQL the locks granted on it, and on MySQL and
// MariaDB the metadata locks granted on it where the server records them and
// otherwise every other session on this database. What it cannot read is
// said in its place, so a wait is never logged with nothing beside it.
func (r renamer) holders(table string) []string {
	type asking struct {
		query string
		args  []any
	}
	var asks []asking
	switch r.u.engine {
	case database.Postgres:
		asks = []asking{{`SELECT CONCAT("a"."pid", ' ', "l"."mode", ' ', COALESCE("a"."application_name", ''), ' ',
				COALESCE("a"."state", ''), ' since ', "a"."xact_start", ': ',
				LEFT(COALESCE("a"."query", ''), 200))
			FROM "pg_catalog"."pg_locks" AS "l"
			JOIN "pg_catalog"."pg_stat_activity" AS "a" ON "a"."pid" = "l"."pid"
			WHERE "l"."relation" = to_regclass(?) AND "l"."granted" AND "l"."pid" <> pg_backend_pid()`,
			[]any{`"` + table + `"`}}}
	default:
		asks = []asking{
			{`SELECT CONCAT("t"."PROCESSLIST_ID", ' ', "m"."LOCK_TYPE", ' ', COALESCE("t"."PROCESSLIST_USER", ''), ' ',
				COALESCE("t"."PROCESSLIST_COMMAND", ''), ' ', COALESCE("t"."PROCESSLIST_TIME", 0), 's: ',
				LEFT(COALESCE("t"."PROCESSLIST_INFO", ''), 200))
			FROM "performance_schema"."metadata_locks" AS "m"
			JOIN "performance_schema"."threads" AS "t" ON "t"."THREAD_ID" = "m"."OWNER_THREAD_ID"
			WHERE "m"."OBJECT_SCHEMA" = DATABASE() AND "m"."OBJECT_NAME" = ? AND "m"."LOCK_STATUS" = 'GRANTED'
			  AND "t"."PROCESSLIST_ID" <> CONNECTION_ID()`, []any{table}},
			{`SELECT CONCAT("ID", ' ', "USER", ' ', "COMMAND", ' ', "TIME", 's: ', LEFT(COALESCE("INFO", ''), 200))
			FROM "information_schema"."PROCESSLIST"
			WHERE "DB" = DATABASE() AND "ID" <> CONNECTION_ID()`, nil},
		}
	}
	var failed []string
	for _, ask := range asks {
		out, err := r.read(ask.query, ask.args...)
		if err != nil {
			failed = append(failed, err.Error())
			continue
		}
		if len(out) == 0 {
			continue
		}
		if len(out) > renameHoldersShown {
			out = append(out[:renameHoldersShown], fmt.Sprintf("and %d more", len(out)-renameHoldersShown))
		}
		return out
	}
	if len(failed) > 0 {
		return []string{"could not be read: " + strings.Join(failed, "; ")}
	}
	return []string{"nothing this session can see"}
}

// read answers one column of rows. On PostgreSQL it asks inside a savepoint,
// so a question the server refuses leaves the upgrade's transaction usable.
func (r renamer) read(query string, args ...any) ([]string, error) {
	pg := r.u.engine == database.Postgres
	if pg {
		if _, err := r.u.raw.ExecContext(r.u.ctx, `SAVEPOINT "asking"`); err != nil {
			return nil, err
		}
	}
	var out []string
	err := r.u.tx.NewRaw(query, args...).Scan(r.u.ctx, &out)
	if pg {
		end := `RELEASE SAVEPOINT "asking"`
		if err != nil {
			end = `ROLLBACK TO SAVEPOINT "asking"`
		}
		if _, after := r.u.raw.ExecContext(r.u.ctx, end); after != nil {
			return nil, errors.Join(err, after)
		}
	}
	return out, err
}

// hasTable reports whether a table of this name is there.
func (u *upgrader) hasTable(table string) (bool, error) {
	query := `SELECT 1 FROM "information_schema"."TABLES"
		WHERE "TABLE_SCHEMA" = DATABASE() AND "TABLE_NAME" = ? LIMIT 1`
	switch u.engine {
	case database.Postgres:
		query = `SELECT 1 FROM "information_schema"."tables"
			WHERE "table_schema" = CURRENT_SCHEMA() AND "table_name" = ?`
	case database.SQLite:
		query = `SELECT 1 FROM "sqlite_master" WHERE "type" = 'table' AND "name" = ?`
	}
	return exists(u.ctx, u.tx, "there is a table "+table, query, table)
}
