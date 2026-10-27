# Exports

Which lists export as files, what every file states about itself, how a file is
streamed, and what each file holds.

Satisfies REQ-30, REQ-50.

## Contents

- [Exports](#exports)
- [File contents](#file-contents)
- [Limits](#limits)

## Exports

Any list that can be read exports as CSV or JSON, through the visibility it was
read with (REQ-50). The files: the findings list, the cross-product findings
list, the audit log, the review queue, what became of the reader's own
decisions, the by-component view, what is running out of time, the last upload
per build, what is out of support, a comparison of two builds, a comparison of
two builds' inventories, the planned upgrades of a product and of one build, the
code finding queue, what keeps being put off, the backlog over time,
administrative changes, what a build holds that the scanner cannot match, and the
disposition register, which an auditor asks for first.

The subject travels through the stream: a file is the list's own query with the
same subject, written as it goes and paged as it streams at the screen's page
size. No complete list exists to be filtered afterwards.

| Rule | Reason |
|---|---|
| A list and its file are built from one function | A screen gains a column and a second renderer does not |
| A file takes the same filters as its screen, declared once; a filter the file does not declare is refused | A second parameter list drifts. An export dropping a filter showed eight rows on screen and seven thousand in the file |
| Paging is kept apart from the filters | A file answers the whole narrowing and pages internally, and offers no page size it does not honor |
| A failure part-way writes a line saying the file is incomplete | A file that stops reads as whole |
| A stream holds its cursor ten minutes at most, then is cut with the incomplete marker | A reader draining just fast enough holds a connection: about 41 hours for 249,288 occurrences, against 1.9 s to read them. On SQLite that is the whole pool |
| Streams at once are a fifth of the pool, at least one; one more is refused with 503 and a time to ask again | The rest of the pool serves every other request |
| A refusal is answered before the first byte | After it, a refusal can only be said inside a 200 |
| The deadline report pages by offset, with the build in the ordering | An arbitrary order between pages repeats one row and skips another |
| A comparison is one file with a column naming which of the three parts a row belongs to, read whole | It is one answer computed from two builds |
| The inventory comparison is read whole; a name at several versions has them joined in one cell per side | A row is one name |
| The findings list offers its file whether or not a product is picked | The two endpoints take the same filters; the spanning file drops what a single build resolves, as its screen does |
| The cross-product file states no single line | Each product applies its own |

## File contents

| Rule | Reason |
|---|---|
| Every file says what it is and when it was taken, written where every file is written | Two files six months later are two spreadsheets of rows |
| A file states what narrowed or computed it, one label and value per fact; a fact with nothing to say is left out | Nothing else says that everything below medium was never in it (REQ-30), what threshold a true/false column used, or which two builds compare |
| What narrowed it is the request's own query | A field-by-field description misses the filter that matters, and the query reproduces the file |
| The register states no line, and names its build | It applies none |
| Every CSV record is the header's width, statements and markers included | CSV has no comment convention, and a narrow record is refused by a conformant reader |
| One document uses one key convention | |
| A number column is empty where there is no number | An unscored finding as zero sorts and filters with the 0.0-rated |
| A field the list leaves out is an empty cell, never zero, and every signal the list carries is a column | Planned upgrades for one build omit the build count; zero says the upgrade is in no build |
| A cell a spreadsheet reads as a formula is neutralized | Component names arrive in somebody else's inventory, and these files are opened by the people holding the most access |
| The queue's file is the list the screen shows, with what each promised: the deferral's end, the promised fix date, the target version | The approvals leave out your own decisions; expired deferrals and missed fix dates hold everybody's you may decide on |
| The audit log's file lists only standing agreements, and states apart whether a second person has one | An agreement taken back is not somebody who agrees |
| The audit log's file includes decisions about code findings, under the same visibility (REQ-50) | |
| The code finding queue's file is the queue, under its visibility, and no row carries source text | `design-docs/analysis.md` § Queue file |
| The disposition register holds no code finding | It is the Register consumer's (`design-docs/kinds.md` § Consumers) |

### Code findings in a findings file

A findings list's file holds, below its findings, every open code finding of the
same selection, in the queue's order and under the queue's visibility (REQ-50),
because the finding exports include every kind the reader reads
(`design-docs/kinds.md` § Consumers).

| Rule | Reason |
|---|---|
| Readers of disclosed or undisclosed work alone get none | They read no code finding |
| Code findings a decision waits on are held; those open only in releases past end of life are not | The list leaves those releases out unless asked |
| The cross-product file holds each product's queue in turn, by product name | Each is its own read under its own visibility |
| Any filter but the order narrows the code findings out, and the file says it holds none | A code finding carries no rating, component, upstream, decision or deadline |
| Three filters keep them: the minimum severity widened, work no promised upgrade covers, branches in support | Each answers alike for every code finding. The last is the list's default, and the screen writes all three into the exported address |
| A file states which code findings it holds | An empty list otherwise reads as none existing |
| A code finding row uses the findings file's columns: the rule as the issue, the newest build's opened date, branch or tag and variant, then a marker, path, line, function and message after the variant; every other column empty, and the code finding columns empty on other rows | One header keeps one table, filtered by one column |

## Limits

| Limit | Detail |
|---|---|
| A file answers the question its list answers | Embedding the list's filters is what keeps the two the same population |
