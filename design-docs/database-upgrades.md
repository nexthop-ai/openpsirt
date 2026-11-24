# Database upgrades

What each release's upgrade migration does to the schema and the rows, and
the checks each runs on the four engines. `design-docs/database-migrations.md`
holds the chain they sit in.

Satisfies REQ-72.

## Contents

- [Release upgrades](#release-upgrades)
- [The v0.14.0 upgrade](#the-v0140-upgrade)
- [The v0.15.0 upgrade](#the-v0150-upgrade)
- [Limits](#limits)

## Release upgrades

Each release after v0.13.0 that changes the schema carries one migration that
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
| A v0.13.0 database whose upgrade fails at its last step, on PostgreSQL and SQLite | The schema and the version applied left as v0.13.0 built them |
| A v0.13.0 database holding components named apart from their package identifier, one namespaced and escaped, one named as its identifier, one with none, and one with an address that is not one | The first two go by their own name and the name their identifier gives, folded and decoded; the others by their own name alone |
| The same, upgraded, two components' names removed, and upgraded again with its version unrecorded | The names put back, the others left |
| The upgrade's package name rule against the application's, over identifiers escaped, malformed, holding control characters and holding none | The same name for each |

## The v0.15.0 upgrade

Migration 49. One table gains a column.

| Table | Gains |
|---|---|
| `scan_run` | Whether the run recorded the source package each finding it applied was matched through, false for every run stored before (`design-docs/findings-components.md` § Match methods). v0.13.0's runs recorded none, and nothing held tells a v0.14.0 run from one of them; each build's next scheduled scan records them (`design-docs/ingest.md` § Scheduled rescanning) |

The column is added where the table lacks it, so a start that stopped after
adding it finishes.

| Check, on each engine | What it holds |
|---|---|
| A v0.14.0 database | Upgraded, the table built as declared |
| The same, upgraded and run again with its version unrecorded | Upgraded the same |
| A v0.14.0 database holding a run | The run reads as having recorded no sources |

## Limits

| Limit | Detail |
|---|---|
| A database a release before v0.13.0 built is not upgraded | The baseline makes v0.13.0's schema and no migration here reads an earlier one. v0.14.0 upgrades one v0.12.0 built first, v0.13.0 one v0.10.x or v0.11.0 built, v0.12.0 then v0.14.0 one v0.9.0 built, and v0.10.2 then v0.13.0 an earlier one (`design-docs/database-migrations.md` § The baseline) |
