# Database upgrades

What each release's upgrade migration does to the schema and the rows, and
the checks each runs on the four engines. `design-docs/database-migrations.md`
holds the chain they sit in.

Satisfies REQ-72.

## Contents

- [Release upgrades](#release-upgrades)
- [The v0.13.0 upgrade](#the-v0130-upgrade)
- [The v0.14.0 upgrade](#the-v0140-upgrade)
- [Limits](#limits)

## Release upgrades

Each release after v0.12.0 that changes the schema carries one migration that
changes the previous release's schema into its own and moves the rows with it,
forward only (REQ-72). A database applies the ones after its own release; a
fresh install makes the baseline and applies every one. They are shaped as
every migration after 1.0 will be.

| Rule | Reason |
|---|---|
| Every table and index is made by the release's own statement | The release's declaration of each table it creates or changes sits beside its migration, with its reasoning. A column it adds is declared as that statement declares it. The migration writes the order, the rows, and how an existing table changes on each engine |
| One transaction of its own, outside the migration library's | SQLite's foreign keys are switched off before a transaction begins, and moved rows are read back by name |
| Not retried in place | It opens its transaction directly, not through the retrying helper. On PostgreSQL and SQLite a lost race fails it and the next start runs it whole; on MySQL and MariaDB it leaves the schema part changed |
| PostgreSQL, MySQL and MariaDB alter a table where it stands | A column every row fills is added with a default and the default dropped: declared as the release declares it, with no row rewrite |
| SQLite rebuilds a table it cannot alter | It cannot drop a default or change nullability. A replacement is made by the release's statement, rows copied by column name with their identifiers, the original dropped, the replacement renamed. Indexes from other migrations are read from the catalog first and made again |
| SQLite's foreign keys are off while it rebuilds | Dropping a referenced table is refused otherwise. The setting is ignored inside a transaction, so it is made before one, and every reference is checked before commit |
| Rows written with their own identifiers keep them, and PostgreSQL's identity is moved past them | References still land. The other three move on the insert |
| A column added is last in its table on the three servers | A rebuilt SQLite table has it where declared. No query reads a column by position |
| Changing a table is spelled per engine | PostgreSQL drops a uniqueness rule or a foreign key as a constraint; MySQL and MariaDB drop the index or the foreign key, name the table an index is dropped from, and refuse to drop a column a foreign key names |
| On MySQL and MariaDB a failure part way is recovered from a backup | Each statement commits as it runs and no version is recorded. The operator page says to take one first |

## The v0.13.0 upgrade

Migration 47. One table is created, one column is filled in each of
`advisory_issue` and `advisory_override`, and package identifiers, occurrence
keys and one fix state are rewritten in place. Each piece is stepped over where
a stopped upgrade made it already. Two sets of rows move, each found done by a
stopped upgrade run again: of a publisher's statements standing about one
subject in documents of one kind, the older are set aside as overtaken by the
newest, by upload order; and of two live decisions an occurrence key's rewrite
brings together, one lapses.

| Table | Gains |
|---|---|
| `advisory_issue` | A mark held while the issue is on the advisory: true on every row not taken off, null on the rest; and the issue unique on the advisory among the rows holding the mark (`design-docs/remediation-advisories.md` § The advisory) |
| `advisory_override` | A mark held while the release is marked affected: true on every row not cleared, null on the rest; and the release marked once on the advisory among the rows holding the mark (`design-docs/remediation-advisories.md` § Editions and agreement) |
| `component` | The identifying name folded, null, then filled by the occurrence re-keying for each component whose name holds its own version (`design-docs/data-model-components.md` § The identifying name) |
| `decision_occurrence` | Who withdrew the row, null on every row v0.12.0 holds, and its key to the person (`design-docs/triage-approval.md` § Approval) |
| `graph_node` | The name and the version the build stated, the name's fold and the stated source's fold, all empty, and an index of each build's nodes by each fold (`design-docs/data-model-graph.md` § The dependency graph) |
| `person` | When a sign-in in group-bound mode last judged what the person holds, empty, so each person's next such sign-in judges it once (`design-docs/access-assignment.md`) |
| `received_vex_statement` | When each statement was made, which newer statement of its publisher set it aside, and its remediation category, all empty, so a statement held before the upgrade is ordered by its upload (`design-docs/ingest-claims.md` § Administrator-supplied VEX) and offers no outcome where it says affected (`design-docs/triage-evidence.md` § Statement display and filters); the older of two standing about one subject, such as two supplier advisories, set aside as overtaken by the newer |

| Table | Created |
|---|---|
| `schema_change` | The record of an upgrade under way: when it started, which process started it and the last version it applies, empty (`design-docs/database-migrations.md` § Instances during an upgrade). Migration 47 writes its own row in its transaction, after its other steps. On MySQL and MariaDB the upgrade writes no row before its first statement, since the table does not exist yet, so a v0.13.0 upgrade failing part way before its row leaves none; a v0.12.0 instance does not look, and a v0.13.0 instance at version 46 stops as behind |

| Table | Loses |
|---|---|
| `advisory_issue` | The issue unique on the advisory over every row, dropped once the rule holding the mark stands. MySQL and MariaDB hold the advisory's foreign key on an index led by its column and refuse to drop the last one |
| `advisory_override` | The release marked once over every row, dropped once the rule holding the mark stands. MySQL and MariaDB hold the advisory's foreign key on an index led by its column and refuse to drop the last one |

| Table | Rewritten |
|---|---|
| `component`, `graph_node`, `image_version`, the scan's root identifier | A package identifier is rewritten as v0.13.0 stores it (`design-docs/data-model-components.md` § Component identity): the slashes after its scheme dropped, and a qualifier's address kept without its credential, query or fragment. Read in Go, 5,000 rows a read in order of identifier: every row holding a question mark or starting `pkg:/` in any case, with the cleaner deciding, since a filter naming the shapes a credential takes misses the next one. A row already in that form is left alone. The identifiers are read first and written last; between, each document served to anybody, in `published_document` and `advisory_issuance`, read 50 a time because a body can run to megabytes, has every identifier the step rewrites replaced wherever a JSON string states it, as the whole string or as a part split at `\|` or ` as part of `, as a CSAF relationship names one. A document left unchanged is not written. On MySQL and MariaDB the earlier steps' definitions commit on their own, so this step's writes can be cut off part way: a start stopped before the identifiers were written finds them as they were and rewrites the documents again, and one stopped after finds nothing left in a document. A published document's digest is left, so the next publishing pass, five minutes on, writes a new revision; until then a document naming two identifiers that become one, such as `pkg://deb/debian/curl` and `pkg:deb/debian/curl`, names that product twice. An issued advisory rewritten has its settled digest taken again from the document as rewritten, by a copy the upgrade holds of the rule that compares it with what would go out now, held to the application's by a test, so it reads as unchanged since it went out; one that cannot be read as an advisory keeps its digest. A remote on a node or a series module holding an `@`, a question mark or a fragment mark, with a scheme or without one, is rewritten as `design-docs/analysis-source.md` § Source links records one: without its user, password, query or fragment. One that does not parse, or whose credential cannot be told apart, becomes none. The upgrade moves no identity; the upgrade note says which components are identified anew |
| `finding`, `saved_filter` | The fix state of no fix scheduled is `unscheduled` where v0.12.0 stored `wont-fix`: on every finding in one statement, and in each saved filter whose query asks `fix_state=wont-fix`, read in Go and rewritten parameter by parameter. The outcome of the same word is a decision and is left alone. A second start finds nothing left to rename. One statement, unbatched: 20,830 of 500,000 findings renamed in 0.5 s on PostgreSQL and 0.4 s on MySQL, the findings in one build on the test servers, while no instance serves |

| Table | Re-keyed |
|---|---|
| `finding`, `decision_occurrence` | An occurrence on a package whose name holds its own version is keyed by its identifying name (`design-docs/data-model-components.md` § The identifying name). Every component is read, 5,000 a read in order of identifier, and the rule applied in Go from a copy the upgrade holds; a test holds the copy to the application's. For those it renames, the findings at or under them are read, 500 components a read, each with the product its build's branch belongs to, and a finding is rewritten where its key is the one its two names made, so a code finding's key, minted from its series, is left. A decision occurrence moves with the key its own product's findings moved from, where in that product the key moved to one key alone and no finding still holds it; another product's findings at the same name decide nothing about it. A product holding no finding at the key follows every product's findings, where together they moved to one key and none still holds it. A live one takes the live key the new occurrence makes. Two live rows meeting at one key keep the approved over the proposed, otherwise the later proposed, otherwise the higher identifier; the other lapses, ending at the upgrade. Every key is read before any is written and none is read twice, so a start after a stopped one finds the rewritten keys already as v0.13.0 makes them |

| Upgrade note | Detail |
|---|---|
| Names and versions | A node from before the upgrade shows the component's name and version, and is found by the component's name, until its build's inventory is sent again; a rescan alone keeps them |
| Advisories from v0.12.0 | Two supplier advisories or upstream documents from one publisher about one product and issue both stood; the older now stands aside, and an approval citing it is flagged as citing a revised statement |
| VEX statements from v0.12.0 | Carry no document identifier, so a later revision stating an identifier replaces none of them. Those uploaded without `publisher` are filed under the file name, which names no real publisher. The document is not kept, so nothing backfills them; `docs/configuration.md` § VEX statements from v0.12.0 says how to clear them |
| Serving during the upgrade | A v0.12.0 process does not look for a schema change and serves through this upgrade; stop every one first (`docs/configuration.md` § From v0.12.0) |
| Withdrawals from v0.12.0 | Name nobody as the withdrawer and count toward nobody's throughput, since v0.12.0 recorded nobody; `docs/configuration.md` § From v0.12.0 |
| Packages named after their version | A package whose name holds its own version continues across an upgrade that renames it; a finding an upgrade under v0.12.0 closed as removed stays closed as it was (`docs/configuration.md` § From v0.12.0) |
| Identity of a reworded identifier | A component stated with slashes after its scheme, with an escaped slash or percent sign in a segment, with a percent sign starting no escape, or with an identifier stating no version, is identified anew the next time its build's inventory arrives; until then a scan of the build reaches it under the identity it holds. Decisions, labels, assignments and upgrade promises on the earlier component do not carry over and are made again |

| Check, on each engine | What it holds |
|---|---|
| A v0.12.0 database holding an issue on an advisory and one taken off | Upgraded, the table built as declared, the first marked, the second not, the second may be put back and the first may not be put on twice |
| A v0.12.0 database holding a release marked affected and one cleared | Upgraded, the table built as declared, the first marked, the second not, the second may be marked again and the first may not be marked twice |
| The same stopped after the column, or after the rule holding the mark, on MySQL and MariaDB | Upgraded the same, nothing already made replaced |
| A v0.12.0 database holding a node | Upgraded, the table built as declared, the node holding no name or version |
| The same stopped after the name, or after every node column and before the index, on MySQL and MariaDB | Upgraded the same, nothing already made replaced |
| A v0.12.0 database holding a received statement, and two advisories from one publisher about one subject | Upgraded, the table built as declared, the statement holding no time and nothing that overtook it, the affected advisory no remediation, the older advisory's set aside as overtaken by the newer's |
| A v0.12.0 database holding a publisher's advisories about two subjects of one product and issue, at four times | Each subject's older advisory set aside as overtaken by that subject's newer, both newer standing, the newest of all overtaking nothing about the other subject |
| The same stopped after the time, on MySQL and MariaDB | Upgraded the same, nothing already made replaced |
| A v0.12.0 database stopped after the withdrawer's column, on MySQL and MariaDB | Upgraded the same, the key added and the column kept |
| A v0.12.0 database holding identifiers with a credential in an address, escaped and plain, a token in an address's query, slashes after the scheme, and one already clean, on a component, a node, an image version and a scan's root identifier | Each rewritten as v0.13.0 stores it, the other qualifiers kept, the clean one unchanged |
| A v0.12.0 database holding a credentialed identifier stated in published documents and an issued advisory, whole and inside a relationship's identifier and name | Each document states the identifier as the upgrade leaves it |
| The same stopped after each phase of the credential step, on MySQL and MariaDB | No document and no identifier holds the credential |
| A v0.12.0 database holding findings and decisions on a kernel at two versions, one under its headers, a library holding no version in its name, a package beneath each kernel, and a code finding on the kernel | Each kernel key rewritten to its identifying name, the package's beneath it included, the library's and the code finding's left, the approved dismissal standing and the proposed one at the same key lapsed, the newer of two proposals brought together standing and the older lapsed, the decision keyed on the kernel's version standing under its new key |
| A v0.12.0 database holding a decision at a key one name made at two versions, the name holding its release at one of them or a different release at each | The decision left at its key, standing |
| The same name in a second product holding it at the version that moves alone, each product with a decision at the key; and a product holding a decision and no finding at a key another product's findings moved from | The second product's decision moved with its findings and standing there, the first's left; the product holding no finding's decision moved with the other's |
| The upgrade's copy of the rule, over names, versions and identifiers of every ecosystem | Reads every name as the application does |
| A v0.12.0 database holding a kernel and a library holding no version in its name | The kernel stores its identifying name as the application writes it; the library stores none |
| A v0.12.0 database holding an issued advisory naming a credentialed identifier | The advisory rewritten, its settled digest the one the application takes from it, so it reads as unchanged |
| The upgrade's copy of the settled digest rule, over real advisories and documents it refuses | Digests every document as the application does, and refuses the ones it refuses |
| A v0.12.0 database holding a finding at `wont-fix` and one at none, and saved filters asking for `wont-fix` as a fix state and as an outcome | The finding and the fix-state filter at `unscheduled`, the finding at none and the outcome filter left |

## The v0.14.0 upgrade

Migration 48. Three indexes are made again, each holding one more column,
five tables gain a column, and three tables are made.

| Table | Gains |
|---|---|
| `finding` | The group index holds the run that opened a finding, last, so it holds every column the trend and the burndown group one build by (`design-docs/analytics.md` § Computed on demand) |
| `finding` | The opened-run and closed-run indexes hold why a finding closed, last, so what each upload changed is counted from them alone |
| `suppression` | The status notes a build's claim gives, null for every claim stored before (`design-docs/ingest-claims.md` § Status notes) |
| `received_vex_statement` | The status notes a received statement gives, null for every statement stored before |
| `finding` | The source package it was matched through, null for every finding stored before until its next scan |
| `vulnerability` | The files its record lists, null for every issue stored before until its next scan (`design-docs/ingest-scanner.md` § Program files) |
| `source_correction`, `source_answer` | Made: a correction by source paths, and what it answered on which files (`design-docs/triage.md` § Corrections) |
| `component` | What the inventory says the component is, null for every component stored before (`design-docs/findings-components.md` § Inventory descriptions) |
| `component_name` | Made: every name a component goes by (`design-docs/data-model-components.md` § Component identity). Filled in Go, 5,000 components a read in order of identifier: each component's folded name, and the name its package identifier gives where that differs, by a copy the upgrade holds of the application's rule; a test holds the copy to the application's. A component whose identifier is not a package identifier gets its own name alone. A name already held is kept. The whole upgrade of 100,000 `pkg:deb` components, one in ten named apart from its identifier, takes 12 s on PostgreSQL, 1.4 s on MySQL, 1.1 s on MariaDB and 0.6 s on SQLite |

A statement or claim the upgrade leaves without notes takes them in place when
its document or the build's next inventory gives them: the row stays, with its
decline, what cites it and the findings it answers, and no alert is raised
(`design-docs/ingest-claims.md` § Status notes). A component the upgrade leaves
without a description takes one from the next inventory stating it. A name a
component goes by that is already held is kept, so a start that stopped part
way fills what it left.

Each index is dropped and made again, so an upgrade stopped between the two
makes it. Each column is added where the table lacks it, so a start that
stopped after the first, as MySQL and MariaDB leave one, adds the second.

| Check, on each engine | What it holds |
|---|---|
| A v0.13.0 database | Upgraded, the tables built as declared |
| The same, upgraded and run again with its version unrecorded | Upgraded the same |
| A v0.13.0 database whose claims already gained the notes column | Upgraded, the tables built as declared |
| A v0.13.0 database holding components named apart from their package identifier, one namespaced and escaped, one named as its identifier, one with none, and one with an address that is not one | The first two go by their own name and the name their identifier gives, folded and decoded; the others by their own name alone |
| The same, upgraded, two components' names removed, and upgraded again with its version unrecorded | The names put back, the others left |
| The upgrade's package name rule against the application's, over identifiers escaped, malformed, holding control characters and holding none | The same name for each |

## Limits

| Limit | Detail |
|---|---|
| A database a release before v0.12.0 built is not upgraded | The baseline makes v0.12.0's schema and no migration here reads an earlier one. v0.13.0 upgrades one v0.10.x or v0.11.0 built first, v0.12.0 one v0.9.0 built, and v0.10.2 then v0.13.0 an earlier one (`design-docs/database-migrations.md` § The baseline) |
| An upgraded database keeps only the last stretch v0.12.0 recorded for an issue on an advisory | v0.12.0 revived the row on putting an issue back and overwrote when it was first added, and nothing else recorded it. An issue taken off, put back and taken off again before the upgrade reads as not named by an issuance from an earlier stretch |
| An upgraded database keeps only the last stretch v0.12.0 recorded for a release marked affected | v0.12.0 revived the row on marking a release again and overwrote who marked and cleared it before |
| A decision at a key v0.12.0 made that v0.13.0 reads as two occurrences in its product is left at that key | One package name held in one product at a version its name carries and at one it does not, or carrying a different release at each, under one consumer, made one key; nothing says which the decision was about, so it reaches the side whose name does not carry its version, where there is one, and the other only once made again |
