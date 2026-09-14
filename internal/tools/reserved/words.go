package main

import "slices"

// reservedWords is every word that is reserved on at least one of the four
// engines this runs against, so an invented alias spelled as one of them is a
// query that parses here and fails there.
//
// **Two of the four are asked and two are typed**, and which is which is what
// this file has to be honest about. The header here used to say the whole list
// was regenerated from the running engines; it was not, and "make
// reserved-words" printed two statements for a person to run and merge by
// hand. An engine upgrade adds reserved words — MySQL and MariaDB both do,
// across minor releases — and a gate checking against a typed list keeps
// passing while a query inventing that alias fails as a syntax error on
// whichever engine a deployment is running.
//
//   - PostgreSQL and MySQL publish what they reserve, and are asked: see
//     words_asked.go, which "make reserved-words" writes and
//     "make check-engines" refuses to let drift.
//   - SQLite and MariaDB publish nothing a query can read, so their words are
//     typed below with the documentation each came from. **That is a gap**,
//     and it is stated rather than glossed: a word either of them adds arrives
//     here when somebody reads the release notes.
func reservedWords() []string {
	all := slices.Concat(askedWords, sqliteWords, mariadbWords)
	slices.Sort(all)
	return slices.Compact(all)
}

// sqliteWords is what SQLite reserves and neither PostgreSQL nor MySQL does.
//
// From https://sqlite.org/lang_keywords.html. SQLite is lenient about where a
// keyword may be used — it accepts most of these as an alias — but the rule
// this gate enforces is that a name is safe on all four, so a word one engine
// reserves belongs here whatever the others allow.
var sqliteWords = []string{
	"abort", "attach", "autoincrement", "conflict", "detach", "glob",
	"indexed", "instead", "pragma", "reindex", "temp", "vacuum",
}

// mariadbWords is what MariaDB reserves and MySQL does not.
//
// From https://mariadb.com/kb/en/reserved-words/. MariaDB publishes no
// keywords table, so this is the one part of the list nothing can check: a
// word a later MariaDB reserves is invisible here until somebody reads the
// release notes and adds it.
var mariadbWords = []string{
	"delete_domain_id", "do_domain_ids", "general", "ignore_domain_ids", "ignore_server_ids", "master_heartbeat_period",
	"page_checksum", "parse_vcol_expr", "position", "ref_system_id", "slow", "stats_auto_recalc",
	"stats_persistent", "stats_sample_pages",
}
