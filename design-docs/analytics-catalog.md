# Analytics catalog

The catalog of named reports, how a report page behaves and prints, the pages
the catalog owns, and the unmatched components report.

Satisfies REQ-52, REQ-53, REQ-79.

## Contents

- [The analytics catalog](#the-analytics-catalog)
- [Unmatched components](#unmatched-components)
- [Limits](#limits)

## The analytics catalog

A report is a question asked often enough to have a name, each a page of its
own. The catalog screen also holds the files reachable nowhere else.

| Rule | Reason |
|---|---|
| A named report is a page at its own address | Printable, linkable and quotable |
| A report about the thing you stand on stays on that screen and is listed; one spanning things lives only in the catalog | A second copy drifts |
| An entry may point at a screen with the scope applied: release comparison, release readiness, unmatched components, carried patches, the exception report, standing corrections, administrative changes | |
| An entry pointing at a build's screen asks for a whole build | |
| An entry needing a scope says "Needs a product" or "Needs a build" beside its name, which opens the scope picker | |
| One address is one entry | Known issues at release is part of the comparison's entry |
| A rail screen answering a named question is listed under "Also on screens" | |
| Grouped by the question each report answers | |
| A report's address follows its name; an earlier address opens it under its name now, with its window | Links sit in sent messages and stored notifications |
| The unnamed question is asked on the findings list | |
| Every report states what it was asked of and when it was taken | |
| A sheet taking a period offers both ways of asking; naming dates drops the rolling window. Its header says what it covers, and every link carries it | |
| A rolling window is asked as the date it began | The audit log reads from midnight |
| A link out carries the period and product the figure was computed with, as a parameter of its own | The audit log reads its narrowing from the address; a second `?` joins a branch's name |
| Every figure opens the list it counts, and that list exports | |
| A figure counting anything closed opens nothing | The findings lists hold what is open; "Appeared" counts openings closed since too |
| A list exports as CSV and JSON; a report of figures prints | |
| The catalog offers only the files reachable nowhere else: what is running out of time, and the VEX document | Every other file is on its own screen with its filters |
| A section or sheet counted by product alone says so, naming the product, every branch and variant, or every product | Triage times, repeated deferrals and dismissals; effort, advisories issued, approval quality and code findings by analyzer |
| Every narrowing the sheet's controls apply is in the printed header | Controls do not print |
| What is about to go out of support is asked for, and returns as its own list | |
| No PDF is generated; printing is the browser's, with the audit log's stylesheet | |
| A printed record is drawn in the light look | |
| The frame does not print, and the grid flattens with no empty rail column | |

### Catalog groups

| Group | Entries |
|---|---|
| Program | Program overview, backlog over time, deadline compliance, effort by component |
| Controls | Approval quality, the exception report, standing corrections, administrative changes |
| Coverage | Last upload per build, code findings by analyzer, unmatched components, carried patches |
| Releases | Release comparison, release readiness, releases out of support |
| Records | Disposition register, advisories issued |
| Also on screens | Assignments (holder workload), Disclosure deadlines (what is running out of embargo), planned upgrades (what a build waits on) |

### Pages of the catalog's own

| Page | What it answers |
|---|---|
| Program overview | Fixed against appearing, aging and whether anybody looked, the two triage waits, what keeps being put off, what was argued away. Seven, thirty or ninety days or two dates, named in the printed header |
| Last upload per build | The estate, longest silent first: builds scanned, gone quiet, or declared and never filed against |
| Releases out of support | Releases past their date and, asked for, those about to pass: how long ago or left, and issues still open, ordered by what is open. Past end of life nothing is overdue, so asking is the only way to see it. An inherited date says so |
| Backlog over time | `design-docs/analytics-program.md` § Trends |
| Approval quality | `design-docs/analytics-controls.md` § Approval quality |
| Effort by component | `design-docs/analytics-program.md` § Effort by subject |
| Deadline compliance | `design-docs/analytics-program.md` § Deadline compliance |
| Disposition register | `design-docs/analytics-controls.md` § The disposition register, asked for a whole build |
| Code findings by analyzer | Code findings of each analyzer series of one product per state, across its builds, each opening the code finding list. Only for `security-testing-read` on the product; anybody else gets no count. `design-docs/analysis-queue.md` § Code findings by series |
| Advisories issued | What went out about our own flaws over a period, and what went out twice. A row carries the digest it hashed to, for comparison with what would be generated now, its issue and product counts as stated, and its title; an issue taken off since is still named. An issuance without its bytes counts from the advisory's coverage today |

| Last upload rule | Reason |
|---|---|
| Five states: out of support, out of use, never scanned, quiet, scanned | |
| Out of support or out of use is listed and marked, never counted quiet | Otherwise it stops catching the product that dropped out |
| "Being scanned" counts scanned builds in support and in use, here and on the front page | |
| Gone quiet counts a never-scanned build declared longer than the quiet span, and its tile says so | |
| The front page names the three quietest; the Uploads screen answers for one product | |

An issuance carries no visibility, so an advisories-issued row is narrowed by
every issue the advisory covers now and every issue it covered at that issuance,
which the document names; a directory's documents are narrowed the same way.

## Unmatched components

A component the scanner cannot match reports no findings, as a clean one does.
Each build says which are unmatchable and why (REQ-79); the tree's header counts
them and links to the list, and the catalog carries it for a whole build.

| Reason | The component |
|---|---|
| No package identifier | Has none. A CPE alone matches nothing |
| Nothing published for this kind | Is a container image or a source repository |
| No version | States none, or `UNKNOWN` or `(devel)` |
| No distribution | Is a Debian, RPM or Alpine package naming no distribution release through `distro` or through `os_name` and `os_version` |
| Generic, no CPE | Is of the generic type with no CPE |

| Rule | Reason |
|---|---|
| Read from what the scanner is given, the distribution worked out as its inventory works it | `os_name` and `os_version` are rewritten into `distro` |
| One reason per component, the first in the order above | Counts sum to the total |
| Worked out when asked | Reading a qualifier parses an identifier |
| Each reason is a shape the scanner was measured matching nothing for | |
| The tree's count and this list are one function | |

Measured with grype 0.119.0 against its database of 2026-09-28, one component
per inventory:

| Shape | Matches |
|---|---:|
| Debian `openssl` with `distro=debian-12` | 44 |
| The same with no distribution, with or without a CPE, or with `os_name` and `os_version` alone | 0 |
| A SONiC kernel image with `distro=debian-13&upstream=linux` | 6,613 |
| The same with `distro` and no `upstream`, or with neither | 0 |
| RPM or Alpine with no distribution | 0 |
| Alpine with `distro=alpine-3.18.0` | 19 |
| Generic `openssl` 1.1.1a with a CPE | 54 |
| The same with no CPE, with no package identifier and a CPE, or with the version `UNKNOWN` or none | 0 |
| Go, PyPI, Cargo and npm packages at a version | 17, 5, 12 and 6 |
| The same with no version, or Go at `(devel)` | 0 |
| A container image, a GitHub repository | 0 |

A real SONiC broadcom inventory of 7,088 components reads as 3,268 matchable and
3,820 not:

| Reason | Components |
|---|---:|
| No version | 3,581, nearly all kernel modules stated `UNKNOWN`, which the kernel's package answers for |
| No distribution | 174, SONiC rebuilds of Debian packages |
| Nothing published for this kind | 40 |
| No package identifier | 25 |

## Limits

| Limit | Detail |
|---|---|
| A distribution binary named differently from its source matches nothing without `upstream`, and is not listed as unmatched | The identifier does not say whether the names differ. A SONiC kernel image with `distro` alone matched 0 |
