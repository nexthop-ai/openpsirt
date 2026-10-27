# The scanner

The scanner as a subprocess: what it is given, what its report may hold, the
ratings and evidence kept from it, and the offline data it reads.

Satisfies REQ-12, REQ-13, REQ-31, REQ-69.

## Contents

- [Scanner environment](#scanner-environment)
- [Scanner output](#scanner-output)
- [Ratings a report carries](#ratings-a-report-carries)
- [Scanner warnings](#scanner-warnings)
- [The offline scanner database](#the-offline-scanner-database)
- [CVE records](#cve-records)
- [Limits](#limits)

## Scanner environment

| Given | Reason |
|---|---|
| Program path, home, scratch space, time zone | Any program needs them |
| The certificate bundle and proxy, in either case | Its data needs them |
| Variables under the scanner's own prefix | Its settings |
| Its own update check, off unless an operator set it | An unconfigured request an air gap cannot reach |

Nothing else is given: this deployment's settings hold the database password,
sign-in secrets, mail password and object store keys.

## Scanner output

The report is read into the API process, bounded like a scan file from the same
budget, every bound configurable. Its size is components × matches ×
references, and a producer controls the first.

| Bounded | Rule |
|---|---|
| Report size | Past it the run fails, never read in part: half a report reads as fewer problems |
| What the scanner said while running | The beginning is dropped and the end kept; the run stands |
| Matches per report | Charged as each is read |
| Addresses per match | Bounded apart, since the two multiply |
| One execution's wall-clock time | A stalled scanner fails as a run; the bound stays under one hold (`design-docs/queue.md`), and the process refuses to start otherwise |

## Ratings a report carries

A report states ratings of one issue from several sources and two scorable
generations (`design-docs/ingest-measurements.md` § Rating mixture).

| Rule | Reason |
|---|---|
| One rating per generation is kept: the worst stated with both score and vector | The worst is independent of arrival order, and 3 and 4 are two judgments |
| The issue's number is the newest generation's rating, copied whole; its findings re-rank when it moves | An older generation's higher rating is held beside it and moves nothing |
| A rating's number, vector, version, publisher and rank come from one rating | |
| A number with no vector is no rating, raising the number only on an issue with none | |
| A rating with no stated generation is not held | A version 2 vector names no scheme |
| The generation is recorded beside the number | The generations' numbers do not compare |
| Numbers are hundredths, rounded | 8.2 is 819.999… hundredths as a float |
| The publisher's number is recorded as given, never recomputed | |

| Vector shape | Measured |
|---|---|
| Version 3 carries base metrics alone | None of the 1,838 version 3 ratings those 1,772 issues carry states another |
| Version 4 carries every metric, with placeholders | 694 of 694 |
| A version 4 vector stating an exploit maturity is published with a non-base number, though the field calls it base | 163 of 694 |

Scoring here is over base metrics, so a score from a recorded version 4 vector
differs from the publisher's wherever exploitation was claimed.

## Scanner warnings

Warnings are recorded on the run, apart from any failure, and travel with the
receipt. None is captured: the scanner reads an inventory written here from the
components held (name, version, package identifier, CPE), so it lacks what it
warns about. Given the producer's document it warns that Go binaries carry no
symbols; given ours it says nothing, with the same findings.

| Kept per match | Use |
|---|---|
| The version range the match fired on | A range naming no packaging revision cannot see a backport, the whole argument in a line (REQ-13) |
| The body of data that answered | Finer than the match kind |

Both are kept as written, never parsed: a range needs an ordering per
ecosystem.

## The offline scanner database

`make scanner-db` writes a bundle and its checksum (REQ-12).

| Rule | Reason |
|---|---|
| Built with the scanner the image carries | The format is the scanner's |
| Verified by that scanner with the network off and auto-update refused, by a target of its own | That is the far side of the gap, where it runs |

## CVE records

A scan narrows its matches with a snapshot of CVE records, kept beside the
scanner's data and read whole (REQ-12, REQ-31); what a scan does with it is
`design-docs/findings-closure.md` § CVE record ranges.

| Source | |
|---|---|
| The CVE List | A repository whose hourly releases carry an archive of every record at a midnight |
| The archive read | The day's from the newest release, else the day before's from the midnight release |
| What is kept | Each record with an orderable unaffected line, whole: 22,481 of 402,541 on 2026-10-07, 534 KB |
| What the snapshot describes | The newest update among records read, kept or not, withdrawn or not; a run records it |

| Rule | Reason |
|---|---|
| A connected deployment checks hourly, reading the newest release by its page's redirect | The host's API allows sixty anonymous requests an hour |
| Only the repository host and its two download hosts are reached, the one redirect followed only to those (REQ-69) | |
| An air-gapped deployment is carried a snapshot from `make cve-records`, read back before declaring it, and copied in with fetching off | |
| `openpsirt records import` reads an archive fetched another way | |
| The snapshot is replaced by rename | A scan reads old or new, never half |
| An unreadable snapshot is an error, never no records | |
| An unreadable record is left out and the rest built; the count and first are logged; no readable record builds nothing | The record narrows nothing, which is conservative |
| An update moment without offset is UTC | |
| It lives on the scanner's volume, per replica or shared | |
| Scratch files over two hours old are removed when a fetch starts | A younger one may be an import in progress |
| Writing refuses what reading refuses, a missing moment included | An unreadable snapshot stalls every scan |
| What an archive keeps counts against the snapshot's bounds as read | |
| A build past a bound fails before the rename, and is logged | |

| Bound | Value |
|---|---|
| Download | 8 GiB, against 622 MB on 2026-10-07, removed past it |
| Archive inside | 8 GiB, on disk, removed once read |
| Files in an archive | Four million, counted by walking entries before opening, which holds every entry in memory |
| One archive record | 16 MiB |
| Snapshot records | A million |
| One snapshot record | 4 MiB as encoded |
| Snapshot | 128 MiB decompressed, against 534 KB compressed on 2026-10-07; the bound is on what reading it holds in memory, and a carried bundle is a file from outside |

## Limits

| Limit | Detail |
|---|---|
| A day's 622 MB archive is downloaded to keep half a megabyte | The hourly change files are not read; the scanner's own data is a day behind |
| Behind a proxy, no CVE records are fetched | The guarded client dials directly; such a deployment imports |
