# Opening and closing

How a scan opens and closes findings, why each closure happened, and the claims
and records that close a finding without a version change.

Satisfies REQ-11, REQ-14, REQ-20, REQ-21, REQ-31, REQ-88.

## Contents

- [Scans as separate work](#scans-as-separate-work)
- [The authority of a run](#the-authority-of-a-run)
- [Interval storage](#interval-storage)
- [Closure reasons](#closure-reasons)
- [Closure by a person](#closure-by-a-person)
- [Affected build sets](#affected-build-sets)
- [Build-declared claims](#build-declared-claims)
- [CVE record ranges](#cve-record-ranges)
- [Replaced inventories](#replaced-inventories)
- [Limits](#limits)

## Scans as separate work

An inventory is read once, when it arrives, and scanned again as vulnerability
data moves, so reading one leaves a scan to do.

| Rule | Reason |
|---|---|
| The scanner is given what was stored, never the file sent | The file is not kept for a moving line |
| What a later inventory states reaches its own product's scanner | A qualifier, CPE or source package on the build's node fills what another build of the product omitted (`design-docs/data-model-components.md` § Duplicate descriptions); another product's never does |
| A distribution stated as a name and version is told to the scanner as the `distro` qualifier; the stored identifier is untouched | Docker Scout and BuildKit write `os_name` and `os_version`: 3 matches as written, 66 with the qualifier, on one 142-package image |
| The product itself is left out of what the scanner sees | Its name may collide with a real package |
| A build holding only itself is not handed to the scanner; the run names the scanner it would have asked, with no version or database | The scanner errors on an empty inventory |
| Every run is recorded: scanner, version, database, where it ran, and a failure with its reason (REQ-13) | A broken scanner otherwise looks like a product with no problems |

## The authority of a run

A run is the authority on what it reported: it opens what it found and closes
everything open it no longer reports (REQ-21).

| Rule | Reason |
|---|---|
| The sweep covers only the kind a scan produces (REQ-14) | A flaw recorded by hand would close silently on the next run |
| Closing a recorded flaw by hand is asked of the rows at that build the caller may read; an unreadable row is left out first, so it answers as nothing open | A readable recorded row the caller may not triage is refused |

## Interval storage

Findings are open until closed and never deleted. A row carries when it opened
and when it closed, and beside the moment, what closed it: the run, or the
person and their reason (REQ-20). A run finding the same things writes nothing.

| Rule | Reason |
|---|---|
| Every index answering "is this open" carries the moment, never the run | A finding no run will close must still close |
| The run is recorded where there is one, and counts what a run changed | |
| One writer per build: recording a run starts by taking the build row | Two runs would both write the same difference. A test overlaps two applications and fails on all three server engines with the hold removed |
| An open finding still moves: fix state, upstream refusal, the build's answer, each stamped when it moved | Only those parts are compared; the rest is what makes it that finding |
| Findings moving to the same values are one write, grouped by every written value except the order | Each row gets what it would alone |
| The order is chosen per finding inside the statement | Likelihood is close to unique per issue |
| Fix, match and the build's answer are written only where one moved | |
| An open finding is read in the comparison's columns only | Every open row is read on every scan |
| What closed before at an occurrence is read as its latest row | A moving version gathers a closed row per move |
| The intervals are the change record: every node, edge, finding and claim records the run that opened and closed it | No second table duplicates them |

On a 324,508-finding image the day a feed moved every likelihood: 651 update
statements, against 324,508 a finding at a time, and no row re-ranked twice.
`design-docs/findings-measurements.md` § Interval storage has every engine.

## Closure reasons

| Reason | Meaning |
|---|---|
| Removed | The component left the build |
| Upgraded | Its upstream version moved |
| Revised | The shipped version changed and the upstream version did not: a carried patch |
| Patched | The build declares a patch fixing it (§ Build-declared claims) |
| Superseded | The upstream version moved and the issue came along: the same issue is open at the new version |
| Fixed | A person declared a recorded flaw fixed here; the one closure a person writes |
| Unexplained | The component is present and unchanged, and the scanner stopped reporting it |
| Invalid | The record should not have existed: never shipped, wrong product, a duplicate, or a check's match on an issue published after the replacement |
| Unaffected | The issue's CVE record excludes the upstream release held (§ CVE record ranges) |
| Disclaimed | A supplier says its product, at the shipped version, is unaffected and every route up runs through it (`design-docs/triage-evidence.md` § Evidence from publishers); or a trusted upstream says the component at the shipped version is unaffected or fixed (`design-docs/upstream.md` § Statements applied) |

| Rule | Reason |
|---|---|
| Superseded is apart from Upgraded | Opposite answers to "was this fixed" |
| Invalid and Unaffected say it was never present: no resolution, out of every trend step's open set, and a release holding nothing else is not counted as holding the issue | |
| "Exists but does not apply here" is a `not-applicable` decision with a second person, never a closure | A closure absorbing it routes dismissals around approval |
| Disclaimed is no fix, and the release counts as having held the issue | Another party's judgment must not rewrite this deployment's release notes. It is applied as a build's own patch is (REQ-31, REQ-84); a decision at the occurrence overrides it there |
| Unexplained is always reported, never suppressed; several in one scan add a scan-level warning, by count | A handful unexplained on a large image is not ordinary |
| The reason is worked out from what the build now holds against what the finding was about, reading the departed component from the catalog | |
| What counts as a fix is one list (`design-docs/findings-issues.md` § Report contents) | |

## Closure by a person

A recorded flaw has no scan evidence, so only a person closes it; computed
resolution would leave it open forever.

| Rule | Reason |
|---|---|
| A scanner's finding is refused | Resolution comes from scans |
| Closed per build, across every occurrence the issue has there | A fix ships in a release |
| Carries who, when, and a required reason | |
| The reason is published on the register, never in a release note | The register is read years later; a comparison already says what was fixed. A scan's closure carries a category and no sentence |
| Asks the right recording asked, per row | |
| Nothing reopens one | Undoing needs a table of undone closures |

A build holding no contents, a name reaching nothing or several, and a
whitespace-only summary are the caller's to fix and say so.

## Affected build sets

A recorded flaw's builds are stated as a whole set; the difference is worked
out.

| Rule | Reason |
|---|---|
| Widening opens findings; narrowing closes them `invalid`, counted as no fix and in no release note | A corrected filing mistake must not raise the fix rate |
| A reason is required to take a build out, and no second person | Requiring review keeps wrong records in place |
| Only a flaw recorded here | A scanner's builds are what the scans found |
| The editor reads where the flaw sits in its own product alone, as many rows as one read answers, and offers no write where that answer is cut short or names more builds than one write takes | The whole set is sent, so a set from a capped page closes every build past the cap, and a set past the write's bound is refused |

## Build-declared claims

A build sends what it has decided does not apply to it, with its inventory or
as a separate document naming the build's root (`design-docs/triage-evidence.md` §
Statements about the build). Claims are stored as data when read (REQ-11); the
file is discarded and the scan reruns on a schedule.

| Stored claim | Rule |
|---|---|
| One claim per subject; held over intervals; re-sending writes nothing; withdrawing closes | What a release argued is asked years later |
| A statement's reasoning is stored once and shared; every reader joins it | One statement can name five thousand components |
| Reasoning is cut to a typed markdown field's bound on a character; NUL dropped, invalid UTF-8 replaced, before keying | One long explanation is no reason to refuse a scan |
| Issue identifier and justification are cut to an indexed name's width | |

A supplier's statement is stored the same way (`design-docs/triage-evidence.md` §
Evidence from publishers). A covered finding is kept, never dropped: one that
never arrived looks like a scanner fault.

| The build says | Effect |
|---|---|
| It carries a fix | Closes as patched on the first scan seeing the claim (REQ-11) |
| Not affected | Stays open, marked, not anybody's work; only a dismissal agreed here closes it |
| Affected, or undecided | Nothing suppressed; still work |

| Case | Recorded |
|---|---|
| An open finding a patch now fixes | Closed as patched, naming the claim |
| A finding first seen patched | A closed row, so comparisons and outbound VEX have it; no deadline, in no count of opened, closed or time to fix |
| A bump onto a build declaring the patch at the new version | Old version closes patched; new version recorded closed patched |
| A bump that drops the patch | Opens at the new version, recording the version it came from |
| A rescan still declaring it | Nothing; re-argued on new grounds, the closed row names the standing claim |
| The build stops declaring it | The claim closes; the next scan opens a new row |

| Rule | Reason |
|---|---|
| Every finding names the claim covering it, whatever it says | An affected claim carries the build's workaround |
| A suppressing claim beats an informing one | |
| A patch on the component and a `fixed` statement both close | |
| A claim attached to the component beats one naming something to match; otherwise a stable order | The second may name a whole source tree |

`design-docs/ingest-claims.md` § Build-declared suppressions holds the matching.

## CVE record ranges

A version-matching source keeps part of the issue's CVE record; each scan reads
the record itself and closes what it excludes as unaffected (REQ-31).

| Source | Leaves out | False positive |
|---|---|---|
| NVD's CPE configuration | The fix on each stable branch | A release already carrying the backport |
| A distribution tracker | Where the bug arrived | A release older than the bug |

| Build | Kernel issues open | Excluded | Findings closed |
|---|---|---|---|
| ONIE, upstream 6.18.55, CVE List of 2026-10-07 | 183 | 37, 36 fixed on 6.18.y at or before 6.18.55 | 37 |
| SONiC, Debian 6.12.41-1 and `linux-perf` 6.12.107-1, CVE List of 2026-10-15 | 6,833 | 174 at one occurrence or more, 121 at every one | 7,790 |

### Entries

The entries read are the numbering authority's and every third-party container;
a third party narrows and blocks narrowing the same way. An entry is read
against a component only where tied to it.

| Tie | Read against |
|---|---|
| Entry CPE names the component CPE's vendor and product | That component, as upstream's release |
| Entry package identifier names the component's type, namespace and name | The same |
| Neither, and its vendor and product are a known name | The components listed for the name |
| A distribution's or vendor's own CPE or identifier | Nothing; its lines are in the distribution's numbering |
| A distribution's or vendor's entry carrying upstream's CPE | Nothing (REQ-31) |

| An entry is another's statement where | Example |
|---|---|
| It names neither the CPE's vendor nor product, compared case-insensitively on letters and digits | `Red Hat` / `Red Hat Enterprise Linux 10` carrying `gnu:grub2` |
| It carries another vendor's operating-system CPE | |
| Never where vendor and product are both empty or `n/a` | Assigned on a project's behalf |

Of 163,913 CPE-carrying entries in the CVE List of 2026-10-14, the two signs
refuse the tie for four, none of them kernel entries.

| Known name | Components |
|---|---|
| Vendor `Linux`, product `Linux` | An upstream release with CPE `linux:linux_kernel`; Debian's `linux` source packages |

Ubuntu's and Red Hat's kernels keep one base version across stable releases and
are not listed.

### Versions

The version read is the upstream release: a distribution package without epoch
and revision, anything else as given less a leading `v`. It must be release
numbers only; `6.18.55-onie` is not read.

| A line | Read as |
|---|---|
| A version alone | That version |
| A version and a strict upper bound | Up to the bound |
| A version and an inclusive bound | Up to and including; `.*` covers the prefix; `*` covers all |
| No type, or `semver` | Release numbers (`design-docs/remediation-versions.md` § Version ordering) |
| A commit range | Nothing |
| Typed as a fix's origin commit, with a release number | Release numbers: the kernel writes the mainline release a fix first reached this way, 15,026 of 17,117 such lines |
| Typed as a fix's origin commit, with a commit | A commit range |
| Any other type, or with status changes inside | Not ordered; where it states affected, nothing narrows |

### Narrowing

| Rule | Reason |
|---|---|
| Closed where a tied entry's unaffected line contains the version and no tied line that could contain it says affected | A line nothing can order might contain it |
| An entry's default status is never read | |
| Narrowing only | A record removes a scanner's match, never adds one |
| The record under the issue's identifier, or an alias where it has none | |
| A patch the build declares is asked first | |
| On an upstream release, the fix on the component's own branch replaces the scanner's | |

| Case | Recorded |
|---|---|
| An open finding now excluded | Closed unaffected by the run, with the lines |
| First seen excluded | A closed row; no deadline, in no opened count |
| A bump onto an excluded release | Old version closes upgraded; new version recorded closed unaffected |
| Rescan, record unchanged | Nothing |
| Rescan, still excluded on other lines | The closed row takes the current lines |
| The record stops excluding | Opens again on the next scan, as a new row |

The lines are kept on the closed row in the record's shape, and the run records
which snapshot it read beside the scanner's data version (REQ-13). Unreadable
kept lines are stated on the register row and logged.

| A scan without a snapshot | |
|---|---|
| One that cannot be read | Waits, saying why |
| None held, where any run of the build read one | Waits, naming the newest snapshot read. Run anyway, a restarted replica reopens every finding a record closed. Any run, not the last: a failed run has still closed findings |
| None held, and no run of the build ever read one | Runs and narrows nothing |

A scan that waits is asked before its run begins. Its job returns to the queue for five minutes without spending an
attempt (`design-docs/queue.md` § Failure handling). The register lists these
closures under their reason with the lines, judged against no deadline.
`design-docs/ingest-scanner.md` § CVE records holds where the snapshot comes from.

## Replaced inventories

A branch inventory a later one replaced is checked once more, against issues
published while it was current, so an exposure fixed before any scan saw it is
still recorded (REQ-88).

| Rule | Reason |
|---|---|
| Each branch inventory replaced after the upgrade that introduced the check owes one check, recorded when a check run of it finishes; no lookback window | How long it was current does not matter |
| An inventory already replaced at that upgrade owes none, marked by the upgrade; a fresh install marks nothing | Its history would be checked only against today's data |
| A tag is never checked | A tag is scanned against today's data already |
| The replaced inventory and its replacement are rebuilt from the graph's intervals at their two scans and given to the scanner as one inventory | Nothing a build sent is kept, and one scan answers both |
| The check covers issues published from the settle delay before the data date of the last successful scan that started while the inventory was current, until the replacement arrived | Data dated a moment need not yet carry an issue published just before it; a match that scan did report is covered already |
| An inventory no scan reached is checked against every issue published before its replacement | |
| A data date is the scanner's database build time, or the run's start where it names none | |
| It runs on the first scanner data dated at least the settle delay after the replacement, a setting shipping at two days; data dated earlier hands the job back for six hours | An issue reaches the scanner's data up to a day after publication |
| The scheduling pass asks for checks owed by the newest data any scan has used, fifty at a time, newest inventory first | A backlog never holds the queue |
| The scheduling pass asks for checks whether or not asking for re-scans failed, and reports both failures | The two share nothing |
| A check whose job ran out of attempts is not asked for again until an operator puts the job back | One that always fails would hold the worker with a scan of two inventories every cycle |
| A scan of what a build holds is always claimed before a check | |
| An issue is dated by its published date from OSV (`design-docs/findings-issues.md` § Issue dates), or by when this deployment first carried it where OSV has none | |
| An issue nobody here has carried is filed, and the check waits an hour at a time while any issue it reports has not been asked of OSV, for up to a day after the later of that issue's first sighting and the check falling due; then it is dated by that sighting | Bounded from the check falling due, so a backlog the date pass has not reached does not spend the one check; bounded at all, so an OSV outage holds no check |
| A match is written closed: opening at the later of publication and the inventory's arrival, closing at the replacement | |
| A match on an issue OSV was asked about and gave no date, first carried here at or after the replacement, is written too, marked publication date unknown | Dropping it loses an exposure that may have been real |
| A marked match opens at the later of the last scan's data date and the inventory's arrival, the widest stretch it could have been held over | A day in that stretch counts it open |
| An issue nobody asked OSV about is never marked; it is dated by its sighting | With the date pass off, every issue new here would otherwise read as undated |
| The marker is worked out, never stored: a check's match whose issue has no published date and was first carried at or after the match's closing | A date arriving clears it |
| The marker is shown on the findings list read on a day, as `publication_unknown` and on the row | The finding screen reads open findings |
| The date pass recording a first published date rewrites the issue's marked matches in the same retryable transaction, and only those | A person's decision is never rewritten |
| A date inside the check's window moves the opening to the later of that date and the inventory's arrival | The row becomes what the check records for a dated issue |
| A date at or after the replacement withdraws the match as `invalid` (§ Closure reasons) | It was never exposed: out of every open set and of found after fixed |
| A date before the window, the settle delay before the last scan's data date, withdraws the match as `invalid` | The check would not have recorded it; that scan was the authority. Whether a match exists never depends on when OSV answered |
| The window is worked out again when the date arrives, from the runs and the settle delay then | |
| A merge rewrites the marked matches of either issue before they are read as one: by the date either held, otherwise by the earlier first sighting where it moved, leaving marked a match closing at or before it | `design-docs/findings-issues.md` § Merged issues |
| A match on an issue with a known date counts as opened and fixed in the remediation figures, timed from its opening to the replacement (`design-docs/analytics-program.md` § Remediation metrics) | It was open over that stretch |
| A marked match, and one withdrawn, counts in no remediation figure | A marked duration is a guess; a withdrawn match was never exposed |
| Its closure reason is the replacement's: patched or disclaimed where the replacement's claims say so there, unaffected where its record says so, otherwise upgraded, revised, removed or unexplained as for a run (§ Closure reasons) | |
| A match closed patched names the claim it stands on, one closed disclaimed the statement, one closed unaffected the record | Where it is the latest row at its occurrence, the VEX document and the disclaimer reads take their evidence from it |
| The latest row at an occurrence is the one closed last, its identifier breaking a tie, for the VEX document, the decidable findings, a release comparison's reason and a run's read of what closed there before. That read takes the latest row a scan wrote at each occurrence beside the latest of all, so a match never hides the replacement's row from the order | A match is written after the replacement's own rows about a stretch that ended before them, so it never outranks them |
| Where the replacement is affected at the same occurrence, nothing is written | The replacement's own scan reports it |
| A match the replaced inventory had patched, cleared or disclaimed is not written | It was never exposed |
| A match any row of the build already covers at that occurrence identity over any part of the stretch is not written | A run stays the authority on what it reported |
| The check is a run of its own, naming the inventory it checked, and opens and closes every row it writes | Every row keeps its provenance (REQ-13) |
| It takes the build by writing a fresh value into its row, and writes in one retryable transaction | A scan and a check of one build never interleave; a write of the value held is skipped on MySQL and MariaDB, so never certified on a cluster |
| It takes the issues it read with no date by writing a fresh value into their rows, repeating that each has no date and is its own issue, and goes again where one gained a date or merged away since; the date pass and a merge take an issue before rewriting its matches | A date or merge committed between the check's read and its commit is either read by the check or finds the match to rewrite |
| Nothing is notified, assigned or given a deadline | Nothing is left to act on |
| The replaced upload's receipt counts what it found as found after fixed, less any match withdrawn; no other receipt answers from it | |
| A check run is never a build's last scan: rescheduling, readiness and the latest run ignore it | |

The cost, measured in `design-docs/findings-measurements.md` § Replaced inventory check, is the scanner's run plus about a second.

## Limits

| Limit | Detail |
|---|---|
| A CVE record is trusted equally whoever wrote it | A wrong record hides a real finding, as a wrong fix version already can |
| A vendor patch backporting a bug into a release older than the record's arrival is not seen | Fix-version matching misses it too |
| A corrected record reaches findings at the next scan | The run is the one writer of what it closes; a snapshot arriving between scans writes nothing |
| The finding screen reads open findings; an unaffected closure is read in the register with the lines | |
| A wrong record cannot be overridden here. Not built | A run consults no decision before closing. Correcting it is correcting the record, which the next snapshot carries |
| An issue OSV never dates that this deployment carried before the replacement is dated by that sighting, unmarked | One first seen here late is recorded from a later opening than its publication |
| A check that recorded nothing is still the one check | Data published to the scanner after the settle delay is not seen |
| A settle delay changed between a check and its issue's first date moves the window that date is judged against | The window is worked out, never stored |
| The outbound VEX document says nothing about an unaffected closure | Telling customers a release is unaffected is a decision, never a closure |
