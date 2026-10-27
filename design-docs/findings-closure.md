# Opening and closing

How a scan opens and closes findings, why each closure happened, and the claims
and records that close a finding without a version change.

Satisfies REQ-11, REQ-14, REQ-20, REQ-21, REQ-31.

## Contents

- [Scans as separate work](#scans-as-separate-work)
- [The authority of a run](#the-authority-of-a-run)
- [Interval storage](#interval-storage)
- [Closure reasons](#closure-reasons)
- [Closure by a person](#closure-by-a-person)
- [Affected build sets](#affected-build-sets)
- [Build-declared claims](#build-declared-claims)
- [CVE record ranges](#cve-record-ranges)
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
| Invalid | The record should not have existed: never shipped, wrong product, or a duplicate |
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

## Limits

| Limit | Detail |
|---|---|
| A CVE record is trusted equally whoever wrote it | A wrong record hides a real finding, as a wrong fix version already can |
| A vendor patch backporting a bug into a release older than the record's arrival is not seen | Fix-version matching misses it too |
| A corrected record reaches findings at the next scan | The run is the one writer of what it closes; a snapshot arriving between scans writes nothing |
| The finding screen reads open findings; an unaffected closure is read in the register with the lines | |
| A wrong record cannot be overridden here. Not built | A run consults no decision before closing. Correcting it is correcting the record, which the next snapshot carries |
| The outbound VEX document says nothing about an unaffected closure | Telling customers a release is unaffected is a decision, never a closure |
