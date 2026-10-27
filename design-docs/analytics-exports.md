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
finding queue, what keeps being put off, the backlog over time, administrative
changes, what a build holds that the scanner cannot match, and the disposition
register.

A file is the list's own query with the same subject, written and paged as it
streams at the screen's page size; no complete list exists to filter afterwards.

| Rule | Reason |
|---|---|
| A list and its file are built from one function | |
| A file takes its screen's filters, declared once; an undeclared filter is refused | An export dropping a filter showed eight rows on screen and seven thousand in the file |
| Paging is kept apart from the filters | A file pages internally and offers no page size |
| A failure part-way writes a line saying the file is incomplete | |
| A stream holds its cursor ten minutes at most, then is cut with the incomplete marker | A slow reader otherwise holds a connection about 41 hours for 249,288 occurrences read in 1.9 s; on SQLite, the whole pool |
| Streams at once are a fifth of the pool, at least one; one more is refused with 503 and a time to ask again | |
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
| The code finding queue's file is the queue, under its visibility, with no source text | `design-docs/analysis.md` § Queue file |
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
| Any filter but the order narrows them all out, and the file says it holds none | A code finding carries no rating, component, upstream, decision or deadline |
| Three filters keep them: the minimum severity widened, work no promised upgrade covers, branches in support | Each answers alike for every code finding; the screen writes all three into the exported address |
| A file states which code findings it holds | |
| A code finding row uses the findings columns: the rule as the issue, the newest build's opened date, branch or tag and variant, then a marker, path, line, function and message; other columns empty, and these empty on other rows | One header keeps one table |

## Limits

| Limit | Detail |
|---|---|
| A file is read with the reader's subject throughout | Visibility applies row by row as it streams, never to a list built first |
