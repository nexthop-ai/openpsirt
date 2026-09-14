package main

import "slices"

// reservedWords is every word that is reserved on at least one of the four
// engines this runs against, so an invented alias spelled as one of them is a
// query that parses here and fails there.
//
// **Two of the four are asked and two are typed**, and which is which is what
// this file has to be honest about. An engine upgrade adds reserved words —
// MySQL and MariaDB both do, across minor releases — and a gate checking a
// typed list keeps passing while a query inventing that alias fails as a
// syntax error on whichever engine a deployment happens to run.
//
//   - PostgreSQL and MySQL publish what they reserve, and are asked: see
//     words_asked.go, which "make reserved-words" writes and
//     "make check-engines" refuses to let drift.
//   - SQLite and MariaDB publish nothing a query can read, so their words are
//     typed below with the documentation each came from, and neither list is
//     complete. **That is a gap**, and it is stated rather than glossed: a
//     word either of them reserves that is not already answered by PostgreSQL
//     or MySQL arrives here when somebody reads the page and types it.
func reservedWords() []string {
	all := slices.Concat(askedWords, sqliteWords, mariadbWords)
	slices.Sort(all)
	return slices.Compact(all)
}

// sqliteWords is the part of SQLite's keyword list carried here by hand.
//
// From https://sqlite.org/lang_keywords.html, which names far more than these:
// most of that page is already covered by what PostgreSQL and MySQL answer,
// and the rest is not carried. **So this is a sample rather than a
// derivation**, and the gap is the same shape as MariaDB's below — a word
// SQLite reserves that neither of the asked engines does, and that nobody has
// typed here, is invisible.
//
// SQLite is also lenient about where a keyword may be used: it accepts most of
// these as an alias. They belong on the list anyway, because the rule this
// gate enforces is that a name is safe on all four.
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
