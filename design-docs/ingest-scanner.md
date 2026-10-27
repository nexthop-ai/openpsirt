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

The scanner is somebody else's program, and it starts helpers of its own.

| Given | Reason |
|---|---|
| Where to find programs, home and scratch space, the time zone | What any program needs |
| The certificate bundle and the proxy, in either case | What reaching its vulnerability data needs |
| Every variable under the scanner's own prefix | Its own settings, set by an operator |
| Its check for a newer release of itself, off, unless an operator set it | A request every run to its publisher's host, which nobody configured and an air-gapped deployment cannot reach |

Nothing else is given, this deployment's settings included: they hold the
database password, the sign-in client secrets, the mail password and the object
store's keys, and what the scanner is not handed it cannot disclose.

## Scanner output

The report is read into the process serving the API, bounded the way a scan
file is, from the same budget, every bound configurable. Its size is components
× matches × references, and a producer controls the first by uploading.

| Bounded | Rule |
|---|---|
| The report's size | Past the ceiling the run fails, never read in part: half a report reads as a product that stopped having problems |
| What the scanner said while running | Past the ceiling the beginning is dropped and the end kept, and the run stands. A failing scanner says why on its last lines |
| Matches per report | Charged as each is read, because a bound stops the walk |
| Addresses per match | Bounded separately, because the two multiply |
| One execution's wall-clock time | A scanner that stopped making progress fails as a run instead of holding a worker. It stays below the ceiling on one hold (`design-docs/queue.md`), and the process refuses to start where it does not |

## Ratings a report carries

A report states several ratings of one issue from different sources and
generations of the scheme. Both generations are ordinary: of 5,037 issues
published in two weeks, 1,939 carry a rating, 527 of them under both 3 and 4.

| Rule | Reason |
|---|---|
| One rating per generation is kept: the worst any report states with both a score and a vector | The worst is the one answer independent of arrival order, and a version 3 and a version 4 rating are two judgments |
| The issue's number is the newest generation's rating, copied whole, and its findings are ranked again when it moves | A screen shows it beside its scheme and the order ranks by it. A higher rating under an older generation is held beside it and moves nothing |
| A rating is kept whole: number, vector, version, publisher and rank | The vector never explains a number somebody else published |
| A number with no vector is not a rating, and raises the number to the worst claimed only on an issue holding no rating | |
| A rating whose generation nothing states is not held beside the others | A version 2 vector names no scheme; filed under a guess it stands in for a generation it may not be |
| The generation is recorded beside the number | The two scorable generations' numbers are not comparable |
| A number is taken as the hundredths it states, rounded, never cut | 8.2 is 819.999… hundredths as a float |
| The number is the publisher's, recorded as given, and nothing recomputes a recorded rating | Recomputing answers a different question |

| Vector shape | Measured |
|---|---|
| A version 3 vector carries the base metrics alone | None of 1,838 version 3 ratings states a temporal or environmental metric |
| A version 4 vector carries every metric, with a placeholder where nothing was stated | 694 of 694 |
| Where a version 4 vector states an exploit maturity, the published number is not a base score, though the producer's field calls it one | 163 of 694 |

Scoring here is over the base metrics, so a score worked out from a recorded
version 4 vector differs from the publisher's wherever exploitation was claimed.
`design-docs/ingest-measurements.md` § Rating mixture has the reference
calculator and a scanned estate.

## Scanner warnings

Warnings read only on failure lose the run that answers and says its answer is
coarse, so they are recorded on the run, apart from the failure, and travel with
the receipt.

| Rule | Reason |
|---|---|
| A scan runs over an inventory written here from the components held (name, version, package identifier and CPE), never over the document that arrived | |
| Kept per match: the version range the match fired on, from the detail its kind was decided by | For a distribution's package reached by identifier, a range naming no packaging revision cannot see a backported fix, and beside the shipped version it is the whole argument in a line (REQ-13) |
| Kept per match: the body of data that answered | Finer than the match kind's two words |
| Both are kept as the scanner wrote them and never parsed | Placing a version in a range needs an ordering per ecosystem |

## The offline scanner database

Produced by a build target (REQ-12): `make scanner-db` writes a bundle and its
checksum. Instructions somebody follows by hand are discovered broken by the
operator who most needs them.

| Rule | Reason |
|---|---|
| Built with the scanner the image carries | The format is the scanner's, and the version that produced a finding is part of what it means |
| Verified before it is declared, by that scanner run against the bundle with the network off and auto-update refused | That is the configuration across the gap |
| The verification is a target of its own | It runs on the far side, where "it loads" is the claim that matters |

## CVE records

A scan narrows its matches with a snapshot of CVE records, kept on disk beside
the scanner's data and read whole (REQ-12, REQ-31).
`design-docs/findings-closure.md` § CVE record ranges holds what a scan does
with it.

| Source | |
|---|---|
| The CVE List | Every CVE record, published as a repository whose hourly releases each carry an archive of every record as it stood at a midnight |
| The archive read | The day's own from the newest release, or, where absent, the day before's from the release tagged for midnight |
| What is kept | Each record with an unaffected line it can order, in any container, whole: 22,481 of 402,541 on 2026-10-07, a 534 KB snapshot |
| What the snapshot describes | The newest moment any record read was updated, kept or not, withdrawn or not, since a withdrawn record changes what the snapshot does. A run records it as the snapshot it read |

| Rule | Reason |
|---|---|
| A connected deployment fetches it, checking hourly, reading the newest release from where its page redirects | The repository host's API answers sixty unauthenticated requests an hour per address |
| Only the repository host and the two hosts it hands a download to are reached, and the download's one redirect is followed only to those | Every other outbound request goes to a host the application names (REQ-69) |
| An air-gapped deployment is carried a snapshot: `make cve-records` fetches one with the image's binary and reads it back before declaring it, and it is copied in with fetching off | |
| `openpsirt records import` reads an archive downloaded some other way into the same place | A deployment's route out may differ |
| The snapshot is replaced by a rename | A scan reads the old file or the new, never half |
| A snapshot that cannot be read is an error, never no records | A damaged bundle read as none closes nothing and says so nowhere |
| A record in the archive that cannot be read is left out and the snapshot built from the rest; the count and the first are logged, and an archive with no readable record builds nothing | Failing the archive keeps the last snapshot closing findings on what records said before. Left out, the record narrows nothing |
| A moment of update with no offset is UTC | The record format defines it so |
| Kept on the scanner's volume: each replica's own on scratch space, or one shared where the replicas mount one claim | The rename keeps a shared one safe |
| Scratch files over two hours old are removed when a fetch starts | A killed fetch leaves hundreds of megabytes, and a younger file may be an import being written |
| Writing a snapshot refuses what reading one refuses, a snapshot with no moment included | An unreadable snapshot stalls every scan and is fetched again every hour |
| What an archive keeps is counted against the snapshot's bounds as it is read | It is held in memory until written |
| A build past a bound fails before the rename, and is logged | The snapshot held stays the last readable one |

| Bound | Value |
|---|---|
| The download | 8 GiB, against 622 MB on 2026-10-07, removed once past it |
| The archive inside it | 8 GiB, written to disk before it is read and removed after |
| Files in an archive | Four million, counted by walking the archive's directory before opening it, which holds every entry in memory; the count is of entries walked, never the stated count |
| One record in an archive | 16 MiB |
| Records in a snapshot | A million |
| One record in a snapshot | 4 MiB, as the snapshot encodes it |
| A snapshot | 128 MiB decompressed, against 534 KB compressed on 2026-10-07; a carried bundle is a file from outside |

## Limits

| Limit | Detail |
|---|---|
| No scanner warning is captured | The scanner reads the inventory written here. Given the producer's document, it reports that Go binaries carry no function symbols and falls back to module granularity; given ours it says nothing, since ours has no notion of a binary. The findings are the same. Carrying a producer's metadata to the scanner changes what an inventory is here |
| A day's whole archive is downloaded to keep half a megabyte of it | 622 MB on 2026-10-07. The List's hourly change files are not read: the scanner's own data is a day behind, and a second path is unmeasured |
| A deployment reaching the internet only through a proxy fetches no CVE records | The guarded client dials directly, so the address checked is the host reached. Such a deployment imports an archive |
