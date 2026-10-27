# Database upgrades

What each release's upgrade migration does to the schema and the rows, and
the checks each runs on the four engines. `design-docs/database-migrations.md`
holds the chain they sit in.

Satisfies REQ-72.

## Contents

- [Release upgrades](#release-upgrades)
- [The v0.8.0 upgrade](#the-v080-upgrade)
- [The v0.9.0 upgrade](#the-v090-upgrade)
- [The v0.10.0 upgrade](#the-v0100-upgrade)
- [The v0.11.0 upgrade](#the-v0110-upgrade)
- [Limits](#limits)

## Release upgrades

Each release after v0.7.0 that changes the schema carries one migration that
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

## The v0.8.0 upgrade

Migration 42. Each change is an index or a storage setting; no column or row
moves. `design-docs/database-schema.md` § Indexes says what each index serves.

| Table | Gains | Every engine |
|---|---|---|
| `finding` | What is open in a build with its deadline, and the grouping index carrying when a finding opened, why it closed and who holds it | Each index dropped and made again where the table stands, SQLite included |
| `decision`, v0.11.0's `decision_occurrence` | An index on the state and the decision | Made where the table stands |
| `notification` | An index on the kind, whether a row is open, and the person | Made where the table stands |
| `finding`, PostgreSQL alone | Vacuumed after a fiftieth changes, analyzed after a hundredth | A storage setting |

An index the database already holds under the name is replaced, because on
MySQL and MariaDB a stopped upgrade leaves the indexes it made and the next
start runs the migration from the top.

| Check, on each engine | What it holds |
|---|---|
| A v0.7.0 database | Upgraded, each declaration describing the built table |
| A v0.7.0 database holding some new indexes already | Upgraded the same, each index in the release's shape |
| A v0.7.0 database, on PostgreSQL | The finding table holds the three storage settings |

## The v0.9.0 upgrade

Migration 43. It adds the image version table and merges what v0.8.0 stored
per container image stamp into one image identified by name
(`design-docs/data-model.md` § Container images), folds each destination's
name into its key, stores a claim's reasoning once, keys a build's claim on it,
and keys a reference on its address as given. A delivery gains when its latest
attempt began (`design-docs/notifications.md` § Delivery); one v0.8.0 recorded
holds none, which reads as no attempt in flight.

On MySQL and MariaDB each step runs in a transaction of its own and steps over
what a stopped attempt finished, because both commit data definition as it
runs.

| Step | What it does |
|---|---|
| The image version table is made | By v0.9.0's declaration |
| Every build's row is taken | The lock a scan's apply and a run's apply take, so a v0.8.0 replica still running waits rather than writing a graph part way |
| Images are found by package identifier | A component whose identifier is of type `oci` or `docker`. One with no identifier is not found (§ Limits) |
| On PostgreSQL the columns pointing at what the merge removes are indexed while it runs | A finding's component and what pulls it in, a label's component, a node's component, an edge's parent. PostgreSQL checks a removed row's references by reading each referring table, a whole-table read per row where no index leads with the column. Each index has its own name, is made only where none of that name exists, and is removed once findings have moved. MySQL and MariaDB index every foreign key column, and SQLite checks no reference during an upgrade |
| Each image's components are grouped by name | The identifier with no version, reduced as identity reduces it |
| A name some build held at two versions at once is left as it is, in every build | Two of its nodes in one build with overlapping intervals. v0.9.0 keeps such images apart by version too. A build holding the name once moves on its next upload |
| One component is kept per name | The one already identified by the name, else the earliest. It takes the name's identity, no version, the versionless identifier and the fold key that follows; a supplier, license or platform enumeration it lacks is taken from the others |
| Live decision occurrences are keyed on the merged image | A live decision keyed on an image stamp's version, as component or as what pulls it in, is keyed on the merged image's, which is none, and its live key is worked out again. An ended one stays as recorded. Read a product at a time, its occurrences a batch at a time, because no index on decision occurrences leads with the occurrence |
| Two live rows coming to share one live key keep one | The approved over the proposed, then the one proposed last, then the later row. The other lapses at the moment of the upgrade |
| Upgrade commitments move to the merged image's fold | A build already committed there keeps that one and drops the old fold's |
| Nodes are pointed at the kept component and joined | Nodes of a build whose intervals meet, one closing at the scan the next opened, become the first node, reaching the last one's end, with the last one's identifier without version. A gap stays two nodes |
| Each old node becomes an image version on the kept node | The old component's version and the node's identifier, across the old node's interval |
| Edges are pointed at the kept nodes and joined | After every image is merged, an edge whose pair and scope match one that closed at the scan it opened joins that one |
| Findings and labels are pointed at the kept component | Both a finding's component and what pulls it in. A label carried twice for one issue in one product keeps the first added |
| Findings are read and moved once for every image | Read for the occurrences decisions key on before anything moves; moved after every image is merged, a batch of components at a time. Nothing indexes the finding table by component alone |
| The other components are removed | Nothing points at them |
| Each destination's name is folded | The lower-case name becomes the key and the typed spelling is kept (`design-docs/notifications.md` § Outbound HTTP). Two names of one kind folding to one key stay two: the one in use before a retired one, then the one spelled as the key, then the earliest keeps the key; the other takes the key followed by its own number, which is also the name it is listed and retired under. On MySQL and MariaDB between the image version table and the merge, asking first whether the column exists |
| A delivery gains when its latest attempt began | A nullable column added where the table stands, after the fold. On MySQL and MariaDB between the fold and the merge, stepped over where present |
| A patch repository records when its last visit ended | No v0.8.0 visit has an end, so each counts as holding the pass for no time until visited again (`design-docs/findings-patch-branches.md` § Host share) |
| A graph node records the source package its build stated | Each node takes its component's source package and version. On v0.8.0 that can be another product's statement, and an upgraded node keeps it until a moving line's next scan (`design-docs/data-model.md` § Duplicate descriptions) |
| A finding no longer records when it last moved | Nothing read it. SQLite rebuilds the table; the others drop the column, stepped over where gone |
| A recorded flaw's rating moves to the product that recorded it | The recorded rating table is made. Where an issue holds a flaw a person entered, its word and the score, vector and scheme naming no publisher become each recording product's recorded rating, and the word is put in force there where nothing rates the issue. Where a feed's score holds the row, the record's score is the newest rating beside it naming no publisher. The issue's word, unsourced score and unsourced ratings are emptied. A scanned issue that absorbed a record keeps its own rating except where it equals the absorbed record's, which moves as a record's does. Another product's finding of an emptied issue reads no word and keeps v0.8.0's deadline until a report fills a word and re-clocks it (`design-docs/findings-issues.md` § Report merging). On MySQL and MariaDB last, the table and the move in transactions of their own |

| Rule | Reason |
|---|---|
| The rules an identity, a fold key and a live key are worked out by are copied into the migration, never called | A later application change must not change what a v0.8.0 database is upgraded into. A test holds the copies to the application's own: a merged image is stored exactly as v0.9.0 stores it |
| Findings a rebuild closed before the upgrade stay closed and unjoined | A row is closed, never deleted, and joining would rewrite when each opened |
| A process applying it answers `/healthz` throughout (`design-docs/packaging.md` § Starting and stopping) | A platform checking that path lets it finish. `/readyz` fails throughout, and a platform ending the process on it undoes the upgrade on every engine |
| It takes 2 min 41 s on PostgreSQL 16 for ten nightly builds of 34 restamped images, and grows with images times stamps | A month of nightly history takes three times as long. `design-docs/database-measurements.md` § The v0.9.0 upgrade has the run, and `make measure` repeats it |

The claims and references move after the images. On MySQL and MariaDB the
table and columns are made in one transaction, the rows moved in a second, and
the copies removed in a third, each stepping over what a stopped attempt did.

| Step | What it does |
|---|---|
| The statement text table is made, and `suppression` and `vex_statement` gain a reference to it | A nullable column added where the table stands, SQLite included. A table holding it is stepped over |
| Each piece of reasoning is stored once | Every build claim and supplier statement points at one copy of its words, cut as v0.9.0 cuts them. Read a page at a time by identifier |
| Every build claim is keyed again | On its reasoning beside what it says, the issue's identifier and justification cut as v0.9.0 writes them, and for a claim from a published statement the version it repeats. Only a row whose key or input moves is written |
| A supplier statement's justification and named versions are cut to their columns' width | SQLite held them at any length, and a claim keyed on one cut and the other whole would close and reopen on the first scan |
| Every reference is keyed on its address as given | v0.8.0 keyed it in capitals, cut to an index key's width. Two references v0.8.0 held apart differ in capitals or past the cut, so no keys collide |
| The copy each claim row carried is removed | SQLite rebuilds both tables; the others drop the column. A table without it is stepped over, with the move above |
| A claim's reference to its reasoning has no foreign key | Stored reasoning is never deleted |
| The ways reasoning is cut and each key is worked out are copied into the migration | As the image merge's are |

| Check, on each engine | What it holds |
|---|---|
| A v0.8.0 build whose image was restamped between two scans, with findings beneath and against it, a label, a commitment on each stamp's fold, decision occurrences beneath and about it; an image that left and came back; two layers of one name held at once | One component stored as v0.9.0 stores it, one node and one edge above and below it across both scans, two image versions on that node, every finding and one label on it, one commitment on its fold; the occurrence proposed last live over an earlier one, an approved one over a proposed one, the occurrence about the image live with no version, the lapsed one as recorded; the returning image on two nodes; both layers left by version |
| The same on PostgreSQL, with a trigger on every table refusing a removal while a referring column leads no index, and an index made by hand on such a column | Migrations 42 to 44 remove nothing the trigger refuses, components and nodes are removed under it, the hand-made index remains, and none of the merge's own indexes do |
| The same on MySQL and MariaDB, stopped at the merge's last step | No version recorded, no image version written, every stamp its own component. The next start steps over the table and leaves what an unstopped upgrade leaves |
| That build's nodes, one component carrying a source package | Its node holds that source package and version; every other node holds none |
| A recorded flaw rated on the issue row; a scanned issue that absorbed a record rated differently; a scanned issue a merge copied a record's rating onto; a record under a published name, scanned elsewhere, scored by a feed on a newer scheme | The first's rating is the recording product's and in force there, and the issue keeps only the feed's sourced rating; the second keeps the scanner's word and score; the third's copied rating is the recording product's and gone from the issue; the fourth's word and unsourced rating are the recording product's and its issue keeps the feed's score |
| The next build restamping the image | One image version opened and one closed, nothing else |
| A v0.8.0 build with claims sharing an explanation, a claim giving none, a claim identifier longer than an indexed name, two supplier statements giving the first explanation, two references | Each explanation stored once and pointed at, the first scan restating every claim writes nothing, each reference keyed as given, each declaration describing the built table |
| The same on SQLite, with a statement whose justification and version exceed an indexed name, and a claim from it | Statement and claim hold the same cut justification and version |
| The same on MySQL and MariaDB, the rows' move stopped part way | The next start steps over what was made and leaves what an unstopped upgrade leaves |
| The same on MySQL and MariaDB, stopped between the two removals, and after both | The next start moves and removes only what remains |

## The v0.10.0 upgrade

Migration 44. No row moves. `design-docs/database-schema.md` § Indexes says
what each index serves, `design-docs/publishing.md` what a published document
is, and `design-docs/upstream.md` what an upstream is. Each addition is stepped
over where a stopped upgrade made it already.

| Table | Gains |
|---|---|
| `finding` | An index on the run that opened a finding and one on the run that closed it, made where the table stands. One held under the name is replaced |
| `product` | Whether its security documents are published, false for every product |
| `claim`, v0.11.0's `decision` | Whom a statement published from it holds for, empty |
| `published_document` | New: one row per published document, holding the revision a reader is handed |
| `upstream` | New: the upstream a product trusts, the key it confirmed, and how reading it went |
| `upstream_document` | New: one row per document an upstream lists, at the revision last recorded |
| `vex_statement`, v0.11.0's `received_vex_statement` | Who here declined a statement and when, empty |

| Check, on each engine | What it holds |
|---|---|
| A v0.9.0 database | Upgraded, each changed or new table's declaration describing the built table |
| A v0.9.0 database holding a new index in another shape | Upgraded the same, the index in the release's shape |

Each index builds in 0.7 s on PostgreSQL over 1,159,943 findings, at 21 to
29 MB beside a 306 MB table.

## The v0.11.0 upgrade

Migration 45, the untagged release's own, in three phases: renames, stored
values, then changes. Each phase logs its duration.
`design-docs/findings-reports.md` § The case says what a report's case holds.

The renames come first, so the rest and the release's declarations use the new
names.

| v0.10.0 table | v0.11.0 table |
|---|---|
| `decision`, the row at one occurrence | `decision_occurrence` |
| `decision_superseded` | `decision_occurrence_superseded` |
| `claim` | `decision` |
| `claim_revision`, `claim_approval`, `claim_comment`, `claim_comment_revision`, `claim_build` | `decision_revision`, `decision_approval`, `decision_comment`, `decision_comment_revision`, `decision_build` |
| `exploited_here`, `exploited_fix` | `incident`, `incident_fix` |
| `obligation_window`, `obligation_window_product` | `response_window`, `response_window_product` |
| `routing_rule` | `assignment_rule` |
| `advisory_source` | `supplier_advisory_feed` |
| `finding_tag` | `finding_label` |
| `vex_statement` | `received_vex_statement` |
| `vex_issuance` | `published_vex` |
| `stream` | `branch_or_tag` |
| `target` | `build` |

| Column | v0.11.0 name |
|---|---|
| `claim_id`, on every table above and on `upgrade` | `decision_id` |
| `decision_id`, on `decision_occurrence_superseded` | `decision_occurrence_id` |
| `place_identity`, on `decision_occurrence` and `finding` | `occurrence_identity` |
| `exploited_here_id`, on `incident_fix` and `told_outside` | `incident_id` |
| `urgency_exploited_here`, on `finding` | `urgency_incident` |
| `triage_floor`, on `product` | `minimum_severity` |
| `routed_by`, on `finding` | `assigned_by_rule` |
| `tag`, on `finding_label` | `label` |
| `stream_id`, on `advisory_agreed_status`, `advisory_override`, `api_key`, `build` and `incident_fix` | `branch_or_tag_id` |
| `live_stream_id`, on `incident_fix` | `live_branch_or_tag_id` |
| `target_id`, on `decision_build`, `finding`, `graph_edge`, `graph_node`, `published_vex`, `scan`, `scan_refusal`, `scan_run`, `suppression` and `upgrade` | `build_id` |
| `summary`, on `flaw_report` | `reported_problem` |

Every index and constraint named after a renamed table or column is renamed
with it: `claim_approval_claim_idx` is `decision_approval_decision_idx`,
`finding_place_idx` is `finding_occurrence_idx`, `told_outside_record_idx` is
`told_outside_incident_idx`, and `claim_build_target_fk` is
`decision_build_build_fk`. `job_set_aside_idx`, listing failed jobs, is
`job_failed_idx`. Tables v0.11.0 creates, `decision_stamp` among them, are
declared under the new names.

| Rule | Reason |
|---|---|
| A rename changes the catalog alone | No row is read or written and no index built on the three servers |
| A name moves only once its holder has moved | `decision` becomes `decision_occurrence` before `claim` becomes `decision`. PostgreSQL holds an index name once per schema, MySQL and MariaDB a foreign key's |
| Each rename waits at most 3 seconds for its table, logs what holds it, and tries again until it runs or the upgrade stops | PostgreSQL and MySQL otherwise wait without bound behind a reading session, and every request queues behind the rename |
| What holds a table is read from the engine | PostgreSQL's granted locks; on MySQL and MariaDB granted metadata locks where recorded, else every other session on the database. MariaDB records none by default |
| PostgreSQL renames inside the upgrade's one transaction | A failure leaves every name. A rename that waited out its bound rolls back to a savepoint and retries, since a failed statement otherwise ends the transaction |
| MySQL and MariaDB step over a rename already made, and log it | A table is stepped over where its new name exists, anything else where its old name is gone |
| MySQL and MariaDB rename a foreign key by declaring it again | Dropped and declared under the new name in one statement, foreign keys unchecked so no row is read. Where its index bore the key's name, the index is renamed first and serves the new key, because MySQL otherwise builds another index reading every row |
| SQLite builds a renamed index again | It has no statement renaming one |
| SQLite keeps v0.10.0's constraint names | A constraint name is part of the table's text, which only a rebuild rewrites, and SQLite reports none |
| PostgreSQL renames each renamed table's sequence after it | `response_window_product` is keyed by the rows it joins and has none |

The stored values the renames reach then take the new words.

| Stored value | v0.10.0 | v0.11.0 |
|---|---|---|
| A bulk decision's `kind` on `decision` | `together` | `bulk` |
| `kind` on `notification` and `outbound` | `claim-waiting`, `claim-lapsed`, `obligation-open`, `obligation-near`, `obligation-passed` | `decision-waiting`, `decision-lapsed`, `response-window-open`, `response-window-near`, `response-window-passed` |
| A notification's `link` to a decision's row at one occurrence | `/decisions/{id}` | `/decision-occurrences/{id}` |
| A change's `kind` on `admin_change` | `exploited-here` | `incident` |
| A failed job's `state` on `job` | `dead` | `failed` |
| A kept filter's `query` on `saved_filter` | `claim`, `claim_state`, `tag`, `sort=places` | `decision`, `decision_state`, `label`, `sort=occurrences` |
| The bulk action limit's `name` on `application_setting` | `triage.together-cap` | `triage.bulk-decision-cap` |
| The minimum severity's `name` on `application_setting` | `triage.floor` | `triage.minimum-severity` |
| The assignment batch's `name` on `application_setting` | `routing.batch` | `assignment.batch` |
| An assignment rule change's `kind` on `admin_change` | `routing` | `assignment-rule` |
| The assignment sweep's `kind` on `job` | `routing.sweep` | `assignment.sweep` |

| Rule | Reason |
|---|---|
| Each step writes only rows still holding a v0.10.0 value | A second start changes only what the first missed. On MySQL and MariaDB the renames committed the transaction, so each statement commits as it runs |
| PostgreSQL and SQLite rewrite inside the upgrade's one transaction | A failure leaves every value |
| A kept filter is rewritten in Go, one query-string part at a time, every other part byte for byte | A word matched in SQL also matches inside a value, and the list recognizes an open kept filter by comparing addresses |
| Only a link at the v0.10.0 address of a decision's row is rewritten | v0.11.0 gives that address to the decision. A link to `/claims/{id}` is forwarded by the interface |
| A setting's row moves only where none is under the new name | The new name outranks the former |
| A setting is read under its former name while the new one is unset, and each start logs a warning naming both | A v0.10.0 binary still running writes the former name |
| Changing a setting replaces and removes the former row in one transaction, the trail recording the former value as replaced | The API refuses the former name, so this is the one way to clear it |
| A waiting condition's and a response window condition's identity keep the words v0.10.0 hashed | An open condition is matched by that hash, and a new one would notify everybody again |
| The administrative trail keeps the former setting name and what each change was about | It records the name the setting had. Its kind is rewritten, because the API filters on a fixed list |
| A decision's record of how its set was chosen is kept as written | It records what somebody asked for |

| Table | Change |
|---|---|
| `flaw_report` | Gains a title, who holds it and since when; loses the acknowledged moment and who acknowledged. Each acknowledgement is first written as a message sent, dated its recorded day, by its recorder, with no text; a report already holding a sent message is stepped over. Then the unanswered list's index is dropped, the acknowledger's foreign key on the servers, then the columns. The holder's foreign key is added wherever the table lacks it, since a stop can leave columns changed and the key missing |
| `flaw_report_revision` | New: what a report said before each edit |
| `report_message` | New: the correspondence with a reporter |
| `report_note`, `report_note_revision` | New: the notes on a report, and each earlier wording |
| `report_assignment` | New: every change of who holds a report, with the rule that assigned it |
| `assignment_rule` | Whether it places vulnerability reports, false for every rule, stepped over where present |

A new table already present gains each of its indexes it lacks.

| Rule | Reason |
|---|---|
| Neither the renames nor the stored values grow with a table's rows | A measurement under the `measure` tag upgrades databases of 1,000 and 1,000,000 rows a table, each with the same 1,000 rows to rewrite, and fails a phase more than twice as long on the larger, each time taken as at least half a second |
| A stored value is found through an index leading with its column | Except a decision's kind, a kept filter's address and a notification's link, read from their tables. A million decisions read in under half a second on every engine; the link prefix, which no index serves, took 734 ms on MySQL over a million notifications |
| SQLite's renames and the changes phase are logged, not held to the bound | Both build indexes, which grow with the rows |

`design-docs/database-measurements.md` § The v0.11.0 upgrade has the phase
times on each engine.

| Check, on each engine | What it holds |
|---|---|
| A v0.10.0 database holding an acknowledged report | The acknowledgement reads back as the first message sent, on its day, by its recorder |
| A v0.10.0 database holding a decision with a row at an occurrence, a revision, an approval, a comment and its earlier wording, a build and a commitment | Each row reads back under its v0.11.0 name pointing where it did, each renamed declaration describing the built table |
| A v0.10.0 database holding an incident, a release carrying its fix, a notice outside, a window counted from another and limited to a product, and a finding the incident ranks first | The same, and a window declared after it numbered after the existing rows |
| The same two, stopped after each rename in turn, each start resuming the last: tables, columns, indexes, and on the servers unique constraints and foreign keys | On MySQL and MariaDB what was renamed stays renamed; on PostgreSQL and SQLite nothing does. Started again, it leaves what an unstopped upgrade leaves. One database per engine takes every stop in rename order, because migrating a fresh database to v0.10.0 is most of each run |
| A v0.10.0 database holding a finding on a branch's build | The finding reads back through `build` and `branch_or_tag` on its branch |
| A routing rule and a supplier, upgraded whole and stopped after each of their renames | An assignment rule placing findings and a supplier advisory feed, each declaration describing the built table |
| A rename whose table another session holds, on the servers | It waits, logs the holding session, and runs once released |
| A bulk decision, a notification and a destination of each renamed kind, a link to a decision's row and one to a claim, a failed job, a kept filter naming renamed words, the bulk action limit, a trail change of the renamed kind | Each value in its v0.11.0 spelling, every value beside it unchanged |
| The same, stopped after each value-rewriting step in turn | Started again, it leaves what an unstopped upgrade leaves |

## Limits

| Limit | Detail |
|---|---|
| An image with no package identifier in a v0.8.0 database is not merged | v0.8.0 kept nothing saying the format called it a container. Its next upload stores it by name, once, as a version moving would |
