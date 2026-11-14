# Exports

Which lists export as files, how a file streams, and what each file states and
holds.

Satisfies REQ-30, REQ-50.

## Contents

- [Exports](#exports)
- [File contents](#file-contents)
- [Limits](#limits)

## Exports

Any list that can be read exports as CSV or JSON, through the visibility it was
read with (REQ-50): the findings list, the cross-product findings list, the
audit log, the review queue, what became of the reader's own decisions, the
by-component view, what is running out of time, the last upload per build, what
is out of support, a comparison of two builds, a comparison of two builds'
inventories, the planned upgrades of a product and of one build, the code
finding queue, the code finding trend and figures, what keeps being put off, the backlog over time, the findings
burndown, administrative changes, what a build holds that the scanner cannot
match, and the disposition register.

A file is the list's own query with the same subject, written as it is read; no
complete list exists to filter afterwards. A file is read one of three ways.

| Way | Files |
|---|---|
| Paged at the screen's page size, every page inside one read-only snapshot of the database | The findings list and its code findings, the cross-product findings list, the audit log, the review queue, the reader's own decisions, the by-component view, what is running out of time, the planned upgrades of a product, the code finding queue, administrative changes |
| One cursor over the whole answer | The disposition register |
| Read whole before the first byte | A comparison of two builds or their inventories, the backlog over time, the findings burndown, the code finding trend and figures, what keeps being put off, the last upload per build, what is out of support, one build's planned upgrades, what a build holds that the scanner cannot match |

| Rule | Reason |
|---|---|
| A list and its file are built from one function | |
| A file takes its screen's filters, declared once; an undeclared filter is refused | An export dropping a filter showed eight rows on screen and seven thousand in the file |
| Paging is kept apart from the filters | A file pages internally and offers no page size |
| A file over a period says each bound back as the day asked for; an open end as the moment the file was asked, and a rolling window's start as its moment | A bound inside a day said as that day names a period the file does not cover: the end is not itself in the period, and a window starts partway through its first day |
| A screen's file link carries its filters with each value of a list as its own repetition of the name, and never its page | The server reads `a,b` as one value named `a,b` |
| Every page of a paged file, and every name a page carries, is read through one snapshot | Each page is its own statement, and a row written between two of them moves every later row, so the file repeats or skips a row and says it is complete |
| Every page of a paged file reads at the moment the file states it was taken: a deadline, a date run out and an end of life | A deadline passing between two pages sorts a row into a page already written, which repeats or skips a row as a write between them does |
| A list grouped in the application from everything it reads is read whole, once | Paged, every page repeats the whole read: what keeps being put off is grouped from every deferral |
| A failure part-way writes a line saying the file is incomplete, and is logged | The 200 has gone out, so nothing else tells an operator; a reader that went away, or one too slow for the stall bound or the ceiling, is a warning |
| A stream's cursor and a paged file's snapshot are held ten minutes at most, then cut with the incomplete marker | A slow reader otherwise holds a connection about 41 hours for 249,288 occurrences read in 1.9 s; on a pool of one connection, the whole pool. A snapshot also holds back the engine's clean-up of old row versions, and on SQLite a checkpoint of the write-ahead log past it. On PostgreSQL, MySQL and MariaDB it holds a shared lock on every table it has read until it ends, so a migration altering one of them waits for the file in attempts of a few seconds, and another session's statement on that table waits only while an attempt is under way (`design-docs/database-migrations.md` § Statement lock waits). Ten minutes beside 100 write transactions a second grew MySQL 8's history list to 139,646 and MariaDB's to 154,061. A findings file of 12,000 groups reads in 42 s on MySQL, the slowest engine (`design-docs/analytics-measurements.md` § Export snapshots) |
| Files reading the database as they are written are a fifth of the pool at once, at least one; one more is refused with 503 and a time to ask again | A file read whole holds no connection and takes no place |
| A refusal is answered before the first byte | After it, a refusal sits inside a 200 |
| The deadline report pages by offset, with the build in the ordering | An arbitrary order repeats one row and skips another |
| A comparison is one file, a column naming which of the three parts a row is in, read whole | |
| The inventory comparison is read whole, a name's several versions joined in one cell per side | |
| The findings list offers its file whether or not a product is picked; the spanning file drops what a single build resolves | |
| The cross-product file states no single line | Each product applies its own |

## File contents

| Rule | Reason |
|---|---|
| Every file says what it is and when it was taken, written where every file is written | |
| A file states what narrowed or computed it, one label and value per fact, leaving out a fact with nothing to say | Nothing else says everything below medium was never in it (REQ-30), what threshold a column used, or which builds compare |
| What narrowed it is the request's own query | It reproduces the file |
| The register states no line, and names its build | |
| Every CSV record is the header's width, statements and markers included | CSV has no comment convention |
| One document uses one key convention | |
| A field with no value, or one the list leaves out, is an empty cell, never zero; every signal the list carries is a column | An unscored finding as zero sorts with the 0.0-rated |
| A cell a spreadsheet reads as a formula is neutralized | Component names arrive from others, and the files are opened by the most privileged |
| The queue's file is the list the screen shows, with the deferral's end, the promised fix date and the target version | |
| The audit log's file carries who agrees now, standing agreements only, and the whole agreement record with dates, carried and withdrawn marks, in a column of its own | What was agreed and then withdrawn is what an audit looks for; one column mixing the two is the answer it must not be given |
| The audit log's file includes decisions about code findings, under the same visibility (REQ-50) | |
| The code finding queue's file is the queue, under its visibility, with no source text | `design-docs/analysis-queue.md` § Queue file |
| The burndown's file is one row per day from day 0, with the running totals of added and done beside the day's counts, and states day 0, the severity and the prefix asked | The totals are what the second panel draws |
| The disposition register holds no code finding | It is the Register consumer's (`design-docs/kinds.md` § Consumers) |

### Code findings in a findings file

A findings file holds, below its findings, every open code finding of the same
selection, in the queue's order and under its visibility (REQ-50;
`design-docs/kinds.md` § Consumers).

| Rule | Reason |
|---|---|
| Readers of disclosed or undisclosed work alone get none | |
| Code findings a decision waits on are held; those open only in releases past end of life are not | |
| The cross-product file holds each product's queue in turn, by product name | |
| Any filter but the order narrows them all out, and the file says it holds none | The filters ask what a code finding mostly does not carry: a rating, an upstream, a decision or a deadline |
| Three filters keep them: the minimum severity widened, work no promised upgrade covers, branches in support | Each answers alike for every code finding; the screen writes all three into the exported address |
| A file states which code findings it holds | |
| A code finding row uses the findings columns: the rule as the issue, the component it is placed on and its version, empty where it is the build itself, the newest build's opened date, branch or tag and variant, then a marker, path, line, function and message; other columns empty, and these empty on other rows | One header keeps one table |

## Limits

| Limit | Detail |
|---|---|
| A file is read with the reader's subject throughout | Visibility applies row by row as it streams, never to a list built first |
