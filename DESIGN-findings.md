# Findings

What a scan run found, where it sits, and how it is ranked and closed.

Satisfies REQ-08, REQ-11, REQ-13, REQ-14, REQ-15, REQ-17, REQ-18, REQ-19,
REQ-20, REQ-21, REQ-22, REQ-24, REQ-25, REQ-27, REQ-28, REQ-32, REQ-33, REQ-37,
REQ-78.

## Contents

- [Fan-out](#fan-out)
- [The row a person reads](#the-row-a-person-reads)
- [Issue identity](#issue-identity)
- [Report contents](#report-contents)
- [Component suppliers](#component-suppliers)
- [Component licenses](#component-licenses)
- [Report merging](#report-merging)
- [Derived addresses](#derived-addresses)
- [Index responses](#index-responses)
- [Patch branches](#patch-branches)
- [Match methods](#match-methods)
- [Declared dependency scope](#declared-dependency-scope)
- [Component interning](#component-interning)
- [Recorded flaws](#recorded-flaws)
- [Reports](#reports)
- [Scoring](#scoring)
- [Affected build sets](#affected-build-sets)
- [Closure by a person](#closure-by-a-person)
- [The authority of a run](#the-authority-of-a-run)
- [Interval storage](#interval-storage)
- [Closure reasons](#closure-reasons)
- [Build-declared claims](#build-declared-claims)
- [Fan-out cost](#fan-out-cost)
- [Decision state on a row](#decision-state-on-a-row)
- [Urgency](#urgency)
- [Work across builds](#work-across-builds)
- [Incomplete upgrades](#incomplete-upgrades)
- [Scans as separate work](#scans-as-separate-work)
- [A year of nightly scans](#a-year-of-nightly-scans)
- [The total above a list](#the-total-above-a-list)
- [The severity ladder](#the-severity-ladder)
- [The rating in force](#the-rating-in-force)
- [File organization](#file-organization)
- [Limits](#limits)

## Fan-out

A scanner reports that a package at a version is affected and stops. It never
saw the dependency graph — it was given a list.

Fanning one reported issue out across the places it occupies is this
deployment's work, derived from the edges the inventory described. It is the
step where one line in a report becomes the number of decisions somebody has to
make.

A place is the component and what directly pulled it in. One issue in a shared
library used by two things is two findings, because different consumers use
different parts of what they depend on.

Something reported against a component this deployment does not hold is counted
and reported rather than dropped. It means the two documents describe different
builds.

## The row a person reads

Store expanded, present collapsed. Every place is stored, because the graph has
to stay answerable and the exact record has to name the artifact that shipped.
What a person reads is the fold: one issue at one source package, at the version
it was built at.

| | |
|---|---|
| Rows on the demo, by issue and component | 7,648 |
| Rows by issue and fold | **6,775**, 11.4% fewer |

Concentrated rather than uniform. Most rows are untouched; what collapses is the
work that was already one thing — `util-linux` was fourteen rows of the same
judgment, the same upgrade and the same routing rule.

Every number a person sees is counted in the unit they acted in. A row says how
many packages of the fold sit here and how many things pull them in, because
deciding on the row decides about all of them. The place count is still stored
and still what the bulk cap is measured against and what the disposition
register expands to — it is not a figure a reader is asked to reconcile with the
two above.

## Issue identity

The same vulnerability arrives as a national identifier from one database and an
advisory identifier from another. Which one a report calls primary is a
preference of whichever source the scanner consulted, so **identity spans the
names**: every name resolves to one row, and a decision holds across all of them.

| Rule | Reason |
|---|---|
| The lookup covers every name a report supplies, not the one it led with | One scanner reports the national identifier alone; another reports its own and knows the first as an alias. Matching only the leading name makes those two issues. The test pins that ordering, because the other ordering passes either way |
| An issue is filed under the most widely recognized of its names | What a person sees is the name they will find in an advisory. The rest are kept, and any of them finds the row |
| Identifiers are compared in one case | Every scheme treats them as case-insensitive and reports disagree about which case to write |
| A report that would merge two held issues is refused | That is a merge of findings and decisions already made against both, and reading a scan is the wrong moment to do it quietly |
| The filed name, folded, is what makes one issue one row | It was a hash of the unfolded name in a column of its own, which nothing read and which only one of the two paths that refile an issue under a better-known name maintained — so the key drifted away from the row it identified, and the collision when it came named a name neither issue was filed under |
| The fold is what a screen reports about | The rows a finding screen shows are the whole fold, so who holds it, what rule placed it and everything else reported beside them is asked of the fold too. Asked of one component, a rule that placed a third of a fold reported as no rule under one name and as the whole thing under another — while the guarantee those reads state is "one name for the whole group, and empty where its places disagree" |
| **Recording a name by hand asks for triage in every product the issue is open in** | Identity is deployment-wide, so from that moment a scan of any product reporting the name resolves to this issue and inherits its decisions and its approvals. Held at a role on the product in the path alone, somebody who reaches nothing in another product changed what a finding there means. Refused whole rather than partly done, and at the visibility each place carries |

## Report contents

Everything a report says about an issue is kept. None of it is recoverable
later, because a report is not kept once read.

Measured on a public switch operating-system image, per scan of 7,917 findings:

| Field | Present in |
|---|---:|
| Known to be exploited | **5** |
| Published likelihood of exploitation | 7,835 |
| Where the issue is written up | 7,917 |
| Description | 7,879 |
| Severity as a number, with the vector it assumed | 6,136 |
| When a fixing version became available | 5,390 |
| References | 11,593, of which **420 are patches** |

The first row is the reason for the rest. Five of nearly eight thousand are being
exploited, and that number turns an impossible queue into an afternoon. It was
being parsed and thrown away.

| Field | Treatment |
|---|---|
| Severity | Stored as a word, which is what ranks and what sets a deadline. A number is taken where the report carries one — the first rating stating both a score and its vector, worst claim winning. The vector travels with the number |
| What counts as a fix | One list, named once. A closure not on it is churn or a correction, never progress — it was a positive list of four words spliced into SQL, a negative list of three in Go, and a third list of the same four as a switch returning prose, none of them checked by the compiler and all three disagreeing about any closure added later |
| Fix state | Three situations, not two: no fix available, upstream declined to fix, and a fixed version exists. "Upstream will not fix this" is a permanent condition that changes the outcome somebody should reach, and is invisible if the only record is that a fix is absent |
| A group whose places disagree says so | A row is an issue at a component across the builds shipping it, and asking what upstream did is asking about the whole of that. The mixed state is read from both ends of the group rather than from a minimum, and the fix version is left empty there: a version taken from one of two disagreeing places is a fix attached to a group that does not have one |
| Weakness classification | Kept where the data carries it, deduplicated and ordered, with the one the data calls the root cause first. It groups findings by the shape of the mistake rather than the package it landed in, and a published advisory states one of them — which is what the order says |

## Component suppliers

An inventory often says who supplied a component — a distribution, a vendor, a
project — and that is kept, because a bare name is not enough for a dependency of
a dependency somebody has never heard of.

| Rule | Reason |
|---|---|
| From the inventory, never from an index | It is what the producer of this build said, not what a registry says about a package in general. Index responses have their own section below and carry different fields |
| Absent for most of it, and said so rather than filled in | Measured on a switch image: 759 of 6,866 components carry one. A screen states that nobody said rather than showing a blank |
| Two ways of saying it, resolved after the whole description is read | One format states an object and a plainer string beside it, and the object wins where a producer fills in both. Resolved while reading, whichever key the producer happened to write first won — and key order is the producer's choice |
| A party's kind is dropped, its name kept | The other format prefixes it — "Organization: Debian" — and one of the two words is a label rather than a name. The word that format uses for "nobody stated one" is treated as nobody having stated one |
| Never part of identity | Two producers describing one component name its supplier differently or not at all, and an identity that moved with it would take every triage decision attached along with it |
| A later report fills it in where the row has none | The rule the section below states for everything else two reports can disagree about. Written only on the insert instead, a component first seen through a producer that stated none never got one, however many later scans said who it was |

## Component licenses

An inventory often says what license a component is under, and that is kept
beside the supplier and shown on the component's page. Measured on a switch
image: 4,483 of 6,866 components declare one. Asking a build which licenses it
ships — a listing, a filter or an export across its components — is not built.

| Rule | Reason |
|---|---|
| From the inventory, as the producer wrote it | An SPDX expression where the format carries one, and a producer's own name where it wrote one — a distribution's copyright file says "GPL-2+" rather than an identifier. Nothing is translated, because a translation is a license judgment nobody here made |
| Declared first, concluded where nothing is declared | A declaration is what the package says about itself. A real producer declares NOASSERTION for most language packages and concludes a license from the source, and that conclusion is the only answer the inventory holds |
| NOASSERTION and NONE are nothing stated | They are the format's words for not knowing and for there being none, and neither is a license |
| Several licenses listed for one component are one conjunction | A package listing several is under all of them. Joined with AND, repeats dropped, in the producer's order. An entry joining licenses with AND, OR or WITH is parenthesized unless it is one group already; a name with spaces in it is one license and is left as written |
| An identifier stands over a name given beside it | It is the one another tool can match |
| A license element is resolved after the whole document is read | One format states a license as an element of its own that the package points at, in no fixed order, and may point at the license list's own address without describing it |
| Never part of identity, and a later report fills it in where the row has none | The two supplier rules above, for the same reasons |
| Bounded to 4,096 characters, cut on a character | A document is bounded in bytes alone, and one component can list licenses to the size of it. The supplier is bounded the same way (REQ-69) |
| Absent where nothing is stated | A screen says so rather than showing a blank. A component scanned before the column existed carries none until a scan of a build that ships it |

## Report merging

Reports disagree and arrive in an order nobody controls. A later one fills in
what an earlier one did not know and **overwrites nothing**, or what is stored
would depend on which scan ran last.

| Field | Rule | Reason |
|---|---|---|
| Known-exploited | Moves forward only | It is a claim about the world rather than a description of an issue: a later report not mentioning it is a gap in that report |
| Score | Keeps the worst anybody claimed | A maximum is the only answer that comes out the same whatever the order. A report saying something is worse is news; one saying it is milder is a gap |
| Likelihood | Keeps the newest, by the day the estimate is about | It is a thirty-day forecast recomputed every day and it legitimately falls, so a maximum makes the order answer "was ever risky" rather than "is risky" — a spike read as the issue's value for ever. What makes it order-independent is the day rather than which scan wrote last: a dated estimate beats an undated one and an older dated one, and two undated reports are last-seen |
| Likelihood, where a report carries none | Left alone | Silence is a gap in that report. A feed omitting the estimate is not a feed saying it is zero |

A test puts the same two reports through in both orders and asserts they agree.

The score carries where it came from. Which scoring system it is on, who
published it and whether it is the primary rating or a secondary one, filled
where a report knows and never overwritten. Everything else a scan says is
recorded with its provenance — what found it, what it was matched from, what it
was matched in — and the one number a deadline is set from had none.

The estimate carries what it means and when. Where it stands among all
published ones, and the day it was computed for. The probability alone is
unreadable — nobody acts on 0.00042 — and the percentile is the same fact a
reader can use.

The maximum is written out rather than using the engines' greatest-of function,
which is not agreed on when one side is absent: two of the four answer "unknown"
where the useful answer is the number that is known.

## Derived addresses

Reading a finding offers addresses worked out from the two identifiers already
held (REQ-18): the issue's own record and the record under each other name it
goes by; where a distribution packages the component, that distribution's
answer; and the package's page in its own ecosystem.

Derived at read time and stored nowhere. An address worked out from two names
cannot go stale while the names are right, and storing it would put a second copy
of the templates somewhere to fall behind the first.

One table, and the interface reads its answer. The component screen had a
second table of its own, in a second language, with a different membership —
neither a superset of the other — and different answers for the same
identifier: it sent every Debian-family package to Debian's tracker, so an
Ubuntu package's link landed on a record for different code with a different
version history and a different advisory status, while the same finding's
server-computed link went to Launchpad. A link that lands on a record for the
wrong thing costs more than no link, because it is followed before it is
disbelieved. The package's page travels on the component's own read now, and
the second table is gone.

Kept apart from the references a report carried, because the provenance is a
different claim. On this deployment's own image, the references for a package
matched by identifier were a vendor bulletin, two gists and two mailing-list
attachments; the issue's write-up was another distribution's tracker; and the
record for the identifier on the screen appeared nowhere.

Nothing here fetches any of them. They are addresses handed to a person, so the
restriction on outbound network access is untouched (REQ-69).

References list patches first. Somebody deciding whether to backport rather than
upgrade needs the change itself. What is a patch is guessed from the shape of
the address — a commit, a pull request, a diff — and the guess errs toward
saying less: an unrecognized address is reported as discussion rather than
asserted to be a patch.

Patches are usually on another record. A Debian package matches Debian's record,
which points at Debian's tracker; the commits that carry the fix sit on the
upstream record, which the scanner reports alongside as a related vulnerability.
The parser declared the related records as carrying an identifier and nothing
else, so a kernel CVE whose upstream record lists eight `git.kernel.org` commits
showed one tracker link and no patches. References from every identifier an
issue answers to are kept, deduplicated against the matched record's own.

## Index responses

A bare name is not enough for a dependency of a dependency. Where an ecosystem
publishes an index, what it says about a package is asked for alongside the
newest version — one line saying what the package is, and where it is developed.

| Rule | Reason |
|---|---|
| One line, never the long description | What some indexes call a description is the package's whole README, measured at 2,894 characters for one ordinary package. That is a document; a row of a table wants a label |
| The first paragraph of a description written in markup, on one line | A Maven project document's description sits inside an XML element, indented and broken across lines. nuget.org's summary is usually empty and its description is a paragraph, because the readme is a file of its own there |
| Absent is the ordinary case, not a gap | The module protocol for one ecosystem has no such field anywhere, and no index is asked about a distribution package, so a version with no summary beside it is normal. A screen shows what there is rather than a space where something failed |
| The address the index states beats one worked out from the name | A publisher said where the project lives; a template guessed. Where the index says nothing, the name still yields one, so there is usually an address either way |
| The project's own pages before its repository | Most of the indexes carry both and publishers fill in whichever they bothered with, so they are asked for in the order a reader wants rather than by picking one |
| Bounded and judged before it is stored | Both arrive over the network from a third party and are rendered to staff holding the most access. The summary is cut to a label on a rune boundary, and the address is judged against the two schemes anything else here may link to — at storage as well as at rendering, because a value that should never have been stored is one somebody later reads out by another route (REQ-66 and REQ-69) |
| An unusable half does not cost the rest | A refused address leaves the version and the summary recorded. One field a publisher filled in badly is not a reason to know nothing about the package |

Asking is the same pass that asks for the newest version, and for most indexes
it costs no extra request: this is reading more of an answer already fetched.
Maven Central is the exception. Its metadata document names versions and
nothing else, so the project document of the newest release is a second
request, and the date comes from it too. It is off unless a
deployment turns it on, like everything else that reaches the network.

What no index gives is a distribution package's description. Those live in a
distribution's own package index, which is one file per release rather than one
request per package — a different shape from the per-package asks here, and not
built.

## Patch branches

A patch link to a commit is labeled with the branches of its repository that
contain the commit (REQ-78). One fix is backported as a separate commit to
each maintained branch, and a report lists the commits as bare links: one
kernel issue carries five, for 6.1, 6.6, 6.12, 6.16 and the mainline, and
nothing in the report says which is which. The repository's history does, so
a copy of it is kept and asked.

Off unless the deployment turns it on, in its configuration rather than under
Settings (REQ-78). It reaches out, and a scan needs none of it (REQ-12).
Turning it on needs memory for git, a volume for the copies and a list of hosts
no fetch may reach, and only whoever deployed it can provide those. Read at
startup, so turning it off is a restart.

### Link shapes

| Shape | Hosts |
|---|---|
| `/{owner}/{repo}/commit/{hash}` | GitHub, Gitea, Forgejo, Gogs |
| `/{owner}/{repo}/pull/{n}/commits/{hash}` | A commit inside a GitHub pull request |
| `/{group…}/{repo}/-/commit/{hash}` | GitLab |
| `/{path…}/commit/?id={hash}` | cgit |
| `/stable/c/{hash}`, `/linus/{hash}` | git.kernel.org's short links, which name the stable and mainline trees |

| Rule | Reason |
|---|---|
| The repository address is built from the parts recognized, never copied from the link | What reaches git is an address of a known shape. A path segment outside a narrow character set, a port, or credentials in the link name no repository |
| A hash is seven to sixty-four hexadecimal characters, lowered | Shorter is as likely a pull request number as a commit. An abbreviation is kept as written and resolved by the copy |
| A pull request, a merge request, a patch tracker and a mailing-list post name no commit | Each describes a fix without saying where it landed. A guessed repository is a request to somewhere the link never pointed |
| A cgit site that serves its pages and its repositories at different addresses has its links read as the repository address | The address a page is on is not one git can fetch |
| A repository address is the one git reaches without a redirect | A fetch follows none |

| cgit site | Page | Repository |
|---|---|---|
| git.kernel.org | `/cgit/{path}` | `git.kernel.org/pub/scm/{path}` |
| git.savannah.gnu.org, cgit.git.savannah.gnu.org | `/cgit/{repo}` | `https.git.savannah.gnu.org/git/{repo}` |
| git.savannah.nongnu.org, cgit.git.savannah.nongnu.org | `/cgit/{repo}` | `https.git.savannah.nongnu.org/git/{repo}` |
| cgit.freebsd.org | `/{repo}` | `git.freebsd.org/{repo}` |
| sourceware.org | `/cgit/{repo}` | `sourceware.org/git/{repo}` |

A repository a retired site's links still name is read at the address it moved
to, where that move is known and the new address has been checked to clone.

| Link reads as | Fetched from |
|---|---|
| `cgit.freedesktop.org/drm/drm-misc` | `gitlab.freedesktop.org/drm/misc/kernel` |

Any other repository on a site no longer serving it, such as the rest of
cgit.freedesktop.org, is read as the address its link names. Fetching it fails,
and the failure is shown with the reason git gave. A repository row recorded
under an address no link reads as any more is left out of the report.

Measured on this deployment's own demonstration data: 36,625 patch links, of
which 36,000 are `git.kernel.org/stable/c/`.

### Keying

A row per repository, a row per commit in it, and a row per branch a commit
was found on. Keyed on the commit, because one fix is linked from several
issues' records and in several spellings, and the branches it is on are a fact
about the commit in its repository.

| Recorded per commit | |
|---|---|
| When it was last looked up | Null is never, which is what a visit takes first |
| Whether the copy held it | A commit in an unmerged pull request, or one a history rewrite dropped, is linked and on no branch |
| How many branches held it, and the names of up to a hundred | A mainline commit is on every branch cut since it landed. The count stays whole; a name wider than the column is counted and not kept, because a cut name is another branch |

| Recorded per repository | |
|---|---|
| When a visit last began, when one last finished, and what stopped the last one | A visit that failed still happened, and how long a repository has been out of reach is the gap |
| How large its copy was when a visit last finished | What an operator sizing the cache reads |

The copies themselves are one replica's disk, and nothing in the database
records which replica holds which.

### The pass

One replica works, settled by a lease taken again as a visit runs: a first visit
to a large tree takes hours. Each wake records any commit a patch link names
that has no row, then visits repositories one after another, the next chosen
as each finishes, and sleeps once none has a commit due.

| Pace | Reason |
|---|---|
| Visits follow each other with no wait while work is due | A visit to a small repository takes about a second. A five-minute wait between visits puts the 48 copies held on the demonstration images four hours ahead of the kernel's stable tree, which holds 35,990 of the 36,463 linked commits |
| The wake ends on nothing due, a lost lease, a failure of this deployment, or shutdown | A repository that could not be read is left for a day and the next one is chosen |
| The same repository chosen twice running ends the wake | A visit looks up what was due or puts the repository out for a day, so choosing it again means the visit changed nothing |

| Order | Reason |
|---|---|
| A repository whose copy is on this disk and that has commits never looked up | Bringing a held copy up to date is a small fetch, and every lookup after it costs a fraction of a second |
| Then the one holding the most urgent commit never looked up | Urgency is the worst rating among the issues linking to the commit, then the score behind it |
| Then the most urgent commit due again | A commit is due again a week after it was looked up |
| Never a host an administrator excluded, and not for a day after a failed visit | A host having a bad hour and a repository that is gone look the same from here |

A visit fetches the repository's branches, writes git's commit-graph index,
and looks up every due commit in it, most urgent first.

| How a visit ends | Recorded |
|---|---|
| Every due commit looked up | The moment it finished and the size of the copy |
| The repository could not be fetched or read | What stopped it, in the repository's own words. Retried a day after the visit began |
| The lease was lost, or the process is shutting down | Nothing. The repository is left as it was before the visit began, a failure from an earlier visit included |
| This deployment failed: the database or the lease | Nothing, and the failure is logged. A dropped connection is not the repository's fault, and recorded as one it would put the repository out of reach for a day |

The lease is taken again every minute for the whole of a visit, the fetch and
the index write included. A first fetch of the kernel from
kernel.org takes a quarter of an hour, and the lease is half an hour. A
process shutting down in the middle of a visit hands the lease back, so the
next one carries on at once.

A lookup is read as git prints it, one branch at a time. Every branch is
counted and the first hundred in version order are kept, so a repository with
a hundred thousand branches holding one commit costs the server a hundred
names. A name that is not valid UTF-8 is counted and not kept: git allows any
byte in a name, and two of the four engines refuse such text.

Only commits a report still links to are due. A commit no issue names any
more keeps what was last recorded about it.

| Measured on the kernel's stable tree | |
|---|---|
| Commits in it | 2,024,354 |
| Copy without file contents, from a host that sends one | 1.1 GB, 90 seconds to fetch, 160 MB of memory |
| Full copy, from git.kernel.org, which sends no other kind | 5.1 GB and 15 minutes to fetch. Indexing it: 2.4 GB of memory at git's defaults, 1.3 GB with the pack windows below |
| Commit-graph index | 116 MB. 22 to 35 seconds to write; 1.7 GB of memory at git's defaults, 0.6 GB with the pack windows below |
| One lookup | 28 seconds without the index, 0.12 to 0.22 with it |
| Every commit the demonstration data links into it | About 25,000, so about ninety minutes of one core |

The branches a backport sits on do not change. A mainline commit gains a branch
each time one is cut, every few months. A week between lookups of the same
commit keeps that current for about a seventh of the daily cost.

### Fetching

Git makes its own connections, so the dialer every other outbound request goes
through never sees them. Git is pointed at a proxy on the loopback interface
instead, and that proxy is the one way out.

| Rule | Reason |
|---|---|
| A tunnel only, to the https port of the one host the repository is on | A redirect, a submodule or a lazily fetched object elsewhere has no route |
| The host is refused where an administrator excluded it by name, or by a network holding its address | An internal name on a public address is excluded by name, and a public name pointing inward by network |
| Loopback, private, link-local and shared address space is refused regardless, and so are the two NAT64 prefixes | The same check every other outbound request here makes, on the address a name resolved to, at the moment of connecting (REQ-69). On a network with DNS64, a NAT64 address is an IPv4 address inside it |
| Git reads no system or personal configuration, no credential helper, no hooks, no terminal | Any of those would change where git goes or what it sends |
| https only, no redirects, and a transfer below 1 KB a second for two minutes is abandoned | A stalled host does not hold a visit for the three hours a first fetch is allowed |
| One thread for packing and indexing, and small windows onto the pack files | Git runs inside the server's memory limit. The windows are what brought the commit-graph write from 1.7 GB to 0.6 GB, and indexing the kernel's full history from 2.4 GB to 1.3 GB |
| A copy holds commits and no files where the host will send that | A host that cannot sends everything, and the warning it prints is not a failure |
| Objects the copy lacks are never fetched on demand | That fetch would happen outside the guarded, bounded one |

A copy's directory is named by a digest of the repository address, so a report
never chooses a path on this disk (REQ-66).

### The cache

| Rule | Reason |
|---|---|
| The copies share a quota, 20 GB unless configured | Room for the full kernel tree and several ordinary repositories beside it |
| The least recently used copy is removed first | A copy is used when it is visited, and each visit writes that down beside it |
| Room is made while a copy is written, not after | Whether a new copy arriving or a fetch into one already held. The directory stays within the quota plus fifteen seconds of transfer |
| A copy that alone outgrows the quota is stopped and removed, and the visit fails | Retried a day later, which is the moment a raised quota takes effect. A host that sent a small first copy and then an endless fetch is stopped the same way |
| A copy removed to make room stops counting towards the size the report shows | The report reads the size recorded at the end of each visit, and that record is cleared when the copy goes |
| An update of a copy asks the remote the copy was made from, not the address | The copy records how it was made beside that remote. Asked by address, a host sends whole trees on top of commits the copy holds without them, and the fetch fails for want of them |
| A copy left half made by a process that died is removed before the next one starts | It is named apart from finished copies, so nothing mistakes it for one |

### Display

A finding's patch links carry the branches, the count, and whether the copy
held the commit. A link not yet looked up carries nothing, and a screen shows
nothing for it. Branches are listed in version order: `linux-6.6.y` before
`linux-6.12.y`.

The System screen reports the whole of the work: patch links, the commits they
name, how many are looked up and held. Administrators only, like the rest of
that screen. Repositories are listed in working order.

| Part | What it holds |
|---|---|
| The visit under way | The repository, its step, and the commits looked up since the visit began against those still due |
| What comes next | Each repository with a commit due, numbered in the order the pass takes it, with how many are due and the worst rating behind them |
| Failed | What stopped the last visit and when it is tried again, a day after it began |
| Excluded | The hosts nothing is fetched from |
| Done | When each finished and the size of its copy |

| Rule | Reason |
|---|---|
| The order is the pass's own, from the one plan | A report sorted another way describes work nobody is doing |
| A copy counts as held where the last visit recorded a size | Any replica answers the report, and only the one working can see its disk. After the lease moves, the two can disagree until the next visit |
| A commit linked since the last wake is counted as never looked up | The report writes nothing, and the pass records it first thing on its next wake |
| The step is read from the commits: fetching until the first commit of the visit is looked up, then looking up | Each commit is recorded as it is looked up, so the count moves during a long visit with nothing else stored. Fetching covers the index write |

## Match methods

A scanner reaches a finding one of two ways, and on a distribution's package they
mean very different things (REQ-13).

| Method | Meaning |
|---|---|
| By advisory | The people who package it published one for this package in this ecosystem. It counts the packaging — "fixed in 1.37.0-r15" — so what it says about a fix concerns the version actually installed |
| By identifier | A published identifier compared against an upstream version range. It knows nothing about packaging, and a distribution backports fixes without moving the upstream version, so the match fires whether or not the patch is in. Neither confirmed nor refuted |

That distinction is the first question anybody asks about a distribution's
packages, and the scanner answers it in every result. Discarded, it leaves a
finding nobody has confirmed looking exactly like one the packagers have.

The range and the source are kept with the finding, because "somebody has to
look" is easier to act on with the thing to look at in hand. Neither is compared
against anything, which would need an ordering per ecosystem.

| Rule | Reason |
|---|---|
| Unrecognized reads as the weaker of the two | A word this does not know is a word whose strength nobody has checked, and reading it as authoritative hides something |
| Unknown is not unconfirmed | Where a scanner said nothing, nothing is claimed. A working list that quietly holds everything nobody classified is one nobody can work down |
| Kept on the finding, not the issue | One issue reached through two ecosystems has two answers and the issue can hold only one. An issue first seen in a Debian image and later matched in an Alpine one showed Debian's tracker against the Alpine package |
| One answer per group | Every place of an issue at a component comes from the same line of a scanner's report |

## Declared dependency scope

What a producer said a dependency's scope is, stored on the graph edge, in the
producer's own word. Recorded, and read by nothing that decides anything.

| Where it is stated | Words |
|---|---|
| A CycloneDX component | `required`, `optional`, `excluded` — stated on the component and carried to the edges arriving at it, because the graph is where a scope can be asked about |
| An SPDX 3 relationship | `build`, `design`, `development`, `other`, `runtime` — stated on the relationship, which is the ordinary dependency |
| An SPDX 2 relationship type | `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF` and `OPTIONAL_DEPENDENCY_OF`, recorded as `build`, `development`, `runtime` and `optional`. One fact under two spellings, and a filter cannot be made to ask for the same thing twice — so every relationship that names a phase is here, not a subset of them |

"Not in the runtime path", "build-time only", "test-only" is the largest
defensible deferral class a vendor has. Without the producer's declared scope
it cannot be expressed at all: a component marked `excluded`, which the
specification defines as not distributed, produces findings identical to one
that ships.

| Rule | Reason |
|---|---|
| **Nothing acts on it** | Not a rank input, not a prefilled outcome, not a default narrowing, and nothing is hidden by it. Reading `build` as "does not ship" is the inference that looks obvious and is wrong for every compiled language — a crate or a module linked into a binary is stated as a build-phase dependency and is inside what the product ships |
| Recording is not inferring | The tree went from *do not infer* to *do not record*, and those are different. What a producer declared is a fact about the document received, in the same class as which scanner found a finding and what it matched on |
| The producer's own word, from whichever vocabulary | One format states a scope on the component and the other on the relationship, and neither uses the other's words: `required` and `run` both say the target is there when the product runs. Folding them onto one vocabulary is a reading, which is what this is deliberately not doing |
| A word neither format defines is not recorded | A producer inventing one has said something no reader can interpret, and a column of arbitrary strings is a filter nobody can offer |
| The scope is part of what identifies the edge | A producer that starts describing the same pair differently has said something different. The earlier edge closes and the new one opens, which is what every other change to a graph does here and what keeps a scan's reported counts true |
| A pair declared twice takes the stated scope | A document naming a dependency plainly and again with a scope has said the scope. Where two differ, the first is kept: the producer said two things and one is recorded |

A test dependency places nothing, and carries no word. Both readers drop
that edge — SPDX 2's `TEST_DEPENDENCY_OF` and SPDX 3's `test` scope — because a
test dependency is not part of what ships. The component is still held, stored
and scanned, which is what a component the producer could not place gets too.
So there is no edge for a word to sit on, and the one scope with the strongest
case for deferral is the one not recorded.

Dropping that edge is not acting on a finding. What it changes is where the
component sits, not whether it is tracked, which is why the rule above and this
exception agree rather than contradict.

### Surfaces

| Surface | What it does |
|---|---|
| A filter on the findings list | The only way to ask about the deferral class at all. Asked of the component's incoming edges in the build, so one reached from two consumers scoped differently answers to both words — a place is a pair of columns, and no engine here compares a pair against a set the same way |
| An evidence line on the finding's dependency path | Beside the place it is about, in the producer's word, next to what the build's own VEX said. Which is where somebody deciding reads it |

It appears nowhere else: not in the urgency ranking, not as a prefilled
outcome on a claim, and not as a default narrowing on any list. A person deciding that a
build-time dependency does not ship is making a judgment, and the judgment stays
theirs.

## Component interning

A component identified by its content is one row whoever writes it, so two
scans describing the same library at the same version are agreeing rather than
colliding.

| Rule | |
|---|---|
| The lookup is inside the writing transaction | A retry runs against a database that has moved |
| **A row another writer got to first is left alone** | The lookup says nothing about another transaction, against another target, finding the same component absent at the same moment — and a unique violation is not a retryable failure, so the loser did not retry: its whole scan apply failed and the producer was told its upload could not be read, for a component that is now present. Two replicas reading two scans at once is the shipped arrangement |
| The identifiers are read back rather than taken from the rows | A row somebody else wrote carries their identifier, and a row this statement skipped carries none |

## Recorded flaws

A vulnerability in what this deployment ships is usually known here before it is
known anywhere. It is a finding of a different kind (REQ-21), triaged, assigned,
decided, clocked and reported like everything else.

Filed under an identifier this deployment mints (REQ-19): the product's name,
the year, and a number — `SONIC-2026-481907` — which is the shape a vendor
advisory takes. A flaw nobody has published has no CVE, and waiting for one
means the record of what was known starts after the work does. Nothing is
configured for that prefix: the product has a name people type.

The number is drawn rather than counted. Counted from one it is a running total
of what the product has kept quiet: ask for the first, walk upward until the
answers change, and both how many undisclosed flaws exist and when the last was
recorded fall out of the names alone. Six digits, so every identifier reads the
same length. A collision is answered by drawing again inside the same
transaction, which also stops two people recording at the same moment being
handed the same one.

The width is not what makes it safe to probe. That is the routes answering a name
somebody holds and a name nobody holds identically (REQ-43).

| Rule | Reason |
|---|---|
| A CVE assigned later is another name for the same issue (REQ-18) | Identity is the issue rather than what it is called, so nothing moves: not the finding, not the decisions, not the approvals. The issue is then filed under the better-known name and the minted one stays an alias |
| A name another issue already answers to is refused, checked before the write | A constraint violation cannot distinguish "already recorded" from "that would merge two issues" |
| It starts undisclosed, and recording one asks for the private triage right (REQ-37) | Defaulting the other way makes the dangerous mistake the quiet one. Somebody who may argue about known issues in shipped components has not been handed the ones nobody has announced. Already-public is a flag on the request, asking the ordinary right |
| Every flaw is recorded with a report | One recorded from a report accepts that report. One recorded without names where it came from on the same request, and a report is written from it, already accepted. The Inbox is then the one list of where every flaw came from, whether somebody sent it or somebody here found it |
| A flaw found here is marked so on its report | It carries no disclosure date (REQ-37) and nobody is owed an answer. Unmarked is a report from outside, because that is the case with somebody counting down to a publication |
| Its deadline uses the windows for our own products, counted from its first severity (REQ-33) | `DESIGN-remediation.md` § Recorded flaws holds the rule. Recorded without a severity, it is listed and assignable with no deadline, and the reason given is `not-rated` |

One identifier, one finding per place in every build. The same code goes out on
several lines and as several variants at once, so a flaw in it is not a fact
about one build. This is the shape a scanner's findings already have, so it
lists, ranks, comes due, carries decisions, groups across variants and appears
in a comparison exactly as a reported one does.

| Rule | Reason |
|---|---|
| Every build is resolved before anything is written | A component name one build holds and another does not is a question about which builds are affected, so it is refused and names the build rather than recorded against some of them and silently not the rest |
| One product | The identifier is minted per product, so a flaw in two products is two records |
| Every row gets the same embargo, rank and deadline | They are the same flaw. A build added later copies them, or the newest build would get a later deadline for the same flaw |
| What carries it is a component of the build, or the build itself | Naming nothing puts it on the root, which is honest where the flaw is in how the pieces fit together. Naming something the build does not hold is refused |
| It is a component at a place, keyed exactly as a scanned one is (REQ-17) | The place is derived from the build's own graph rather than asked for: the entry path has already resolved the component there, and a component can sit in more than one place at once, which a form question could not express and which is why one recording opens one finding per place. Recorded as sitting directly under the product whatever the graph said, a flaw a person recorded and the same flaw a scan found were two places and two decisions — triaging either did nothing for the other |
| Recorded against the build itself, the place is the build's root, which has no name of its own | The product's name differs per variant, so a place keyed on it is a different place in each of them: one flaw across three variants was three places and three decisions. The scan path collapses a root parent for the same reason |
| A name the build holds more than once is refused with the choices | A name is not unique within a build and not rarely: a real switch image ships three vendored copies of one library, and thirteen names in it are held at one version by two components. The resolution goes through the same lookup every other component reference takes — it did not, and took the first row a name matched |

## Reports

A report is the record that a claim arrived. It stands whether or not the claim
turns out to be a flaw, because the evidence that it was received and answered
is the record itself.

Recorded only by minting an issue, a claim nobody believes either fills the
findings with a flaw nobody believes or goes unrecorded — and an unrecorded
claim destroys the evidence the record exists for. Slop reports are generated
and arrive in greater numbers than real ones, so this holds before a security
contact address is published rather than at some volume of them.

| Rule | Reason |
|---|---|
| A report exists without an issue | Whether a claim is a flaw is a judgment somebody makes afterwards, and the record has to stand before it is made |
| It carries what was claimed | A report holding only who wrote in records that a mail arrived, which nobody can evaluate, answer or find again. The issue's own description carries the claim once there is one |
| Everything about the reporter is optional | A claim arriving anonymously is an ordinary claim, and a flaw found by whoever is typing has no reporter at all. A form demanding one asks them to invent an answer |
| A report says whether it was found here | The one fact that separates a flaw somebody here found from a claim that arrived. It decides the disclosure date and whether an answer is owed, and nothing else: the same fields, the same judgment and the same rulings apply to both |
| One row per issue, not per finding | A flaw recorded against four builds is one report from one person, and four copies of their address is four places for it to be wrong |
| **It records the product it was reported against, and that is who may read it** | Read with the right every read of a report asks, reading undisclosed work in that product, on the issue as on the report itself: one reporter has one rule. Answering them is working the report and asks for triage there. An issue's identity spans its aliases, so the moment a CVE is recorded the same issue is open in every product a scan reports it in. Keyed on the issue alone, the reporter's name, address and received date were readable by anybody holding triage rights in any of those — and acknowledging from one of them cleared the unanswered condition out of another product's queue. The unanswered list stops fanning one letter out across every product the name reaches |
| Credit preference is kept apart from the name reported under | "Anonymous" is a real answer, and so is a handle that is not the name on the mail |
| The received date is what the embargo runs from (REQ-37) | A report that arrived a fortnight before anybody typed it in no longer puts this clock behind the reporter's. It falls back to when the record was made, and a date nobody can read is treated as one nobody gave. A report found here starts no embargo |
| The acknowledged date records that somebody answered, rather than answering | What reaches a researcher is a mail from an address somebody already has. Acknowledging twice keeps the first date, and the condition it raises fires at once rather than after a period |
| What was claimed goes through the submission policy typed text does | It is rendered as markdown where it is read back and it quotes somebody outside this deployment, which is the case the policy exists for (REQ-67) |

A public intake form is out of scope. This is the inside half.

### Report references

Minted here: the product, an `R`, the year and a six-digit number drawn at
random. The letter is what keeps the two namespaces apart, so a reference and
a recorded flaw's identifier cannot be read for each other.

Drawn rather than counted, for the reason a recorded flaw's identifier is:
counted from one it is a running total of how many claims this product has
received and when the last one arrived, which is a disclosure made by the name
alone. A collision draws again inside the same transaction.

A reference is a name people type, so it is matched without regard to capitals
— the stored form is the minted one and the typed one is folded to it, which
compares the same under any engine.

### Three roles

The person who transcribes a mail is not the person who answers the reporter,
and neither is the person who decides what the claim is worth. A record that
cannot tell them apart evidences none of them.

| Recorded | Written by |
|---|---|
| Who wrote it down, and when | Recording the report |
| Who answered the reporter, and when | Acknowledging it |
| Who judged the claim, and when | Accepting it as an issue, or a ruling taking effect. On a ruling, the proposer and the moment they proposed it |

A flaw recorded without a report already here is written down and judged in one
act, because whoever typed it in said what the flaw is as they did.

### Judgment

A report is pointed at an issue that already exists here, or recorded as a new
flaw. Recording a flaw carries the builds it ships in, the severity and the
embargo, so it asks for those where accepting a report as an existing issue
does not.

A flaw recorded here already has its report, so a second claim about it is a
duplicate. Accepting a report as an existing issue reaches the issues a scan
reported.

Half of that is not built. A claim from outside ruled a duplicate of a flaw
found here starts no disclosure date, although its reporter may be counting
down to a publication.

| Refusal | Reason |
|---|---|
| The report has already been judged | Two people judging at once would both succeed, and the second would overwrite who decided and when. Asked in the write as well as before it |
| Another report is already that issue's record | One report is one issue's record. A second pointed at the same issue is a duplicate, which is a ruling of its own |
| A ruling holds the report | A report waiting to be rejected and accepted by somebody else in the meantime would be two things when the approval lands. Asked in the write |
| The issue is not one the judge may be told of here | Resolving first and refusing after makes the refusal informative: an identifier nobody has filed and one filed on work this person cannot see would come back differently, which turns this into a way to ask which identifiers are open here |
| A flaw may be recorded from a report | The claim turned out to be a flaw nobody had recorded. Recording it from the report accepts that report as the new flaw in the same write, so one report is the record rather than two, and who told us and when are read from it — naming a reporter as well is refused. The embargo counts from the day the report says it arrived. A report already judged, or under a ruling, is refused |
| The judge may not work reports here | Asked before the issue's name is resolved. Asked after, an identifier nobody has filed and one filed here come back in different words to somebody who may not judge a report at all. The same holds for the issue a duplicate names, and, for somebody who may not read reports, for the issue whose duplicates are listed |

### Report visibility

A claim is undisclosed: there is no issue to be public about, and nobody has
decided the claim is safe to repeat. This is the **report rule**.

| Act | Asks for |
|---|---|
| Reading a report, listing a product's reports, reading what arrived with one, reading a ruling and the duplicates on an issue | The right to read work nobody has announced in that product |
| Recording a report, answering it, judging it, attaching to it, proposing or withdrawing a ruling | The right to triage work nobody has announced there |
| Agreeing to somebody else's ruling | The approver capability or that triage right, over the right to read |

Reading and working are apart because somebody who reads every embargoed issue
in a product already reads what a stranger's claim could point at, so the claim
is no more than they hold. Working one is a write, and the rule that writes
ask for a writing role is the one every other surface here follows.

Asked before any reference is resolved. Somebody who may not read the
product's reports is told a named report or ruling is not there, the answer
one nobody minted gets; somebody who reads them and may not act on one is
refused in words, since they can open it.

Every reader of the row, including the one that reaches it through the issue
it turned out to be. Asked there as the issue's own visibility, judging a
claim handed what a stranger wrote to everybody who triages announced work,
which is a widening by the act of filing.

Judging a claim does not widen that. What a stranger sent is what a stranger
sent, reviewed by nobody, so saying the claim is a disclosed issue must not
hand it to everybody who reads that product. Anything meant to be read there
is attached to the issue, which is an act somebody takes.

That is the one place a report and an issue differ, and `DESIGN-attachments.md`
§ Fetch authorization holds the attachment half of it. A file on an issue
follows the issue, including an embargo ending; a file on a report follows the
report.

A reference is reached in the product it was recorded against and nowhere
else. A reference nobody minted, one recorded against another product, and one
the reader may not see all answer alike — told apart, the pair of answers says
which products hold claims.

Somebody brought onto a single case reaches no reports. A case grant is about
one issue, and a product's claims are not.

### Dispositions

A judged report carries one of five dispositions. Accepted is written by
pointing the report at an issue. The other four are written by a **ruling**:
one act, with one reason, covering one or more reports in one product.

| Disposition | Second person | Reason required | Meaning |
|---|---|---|---|
| Accepted | No | No | The claim is an issue here. The issue carries it from then on |
| Duplicate | No | No | The claim is an issue already open here. The ruling names that issue |
| Not reproducible | No | Yes | Nobody could make it happen |
| Out of scope | Yes | Yes | It is about something this product does not answer for |
| Rejected | Yes | Yes | It is not a flaw |

| Rule | Reason |
|---|---|
| Rejecting and declaring out of scope wait for a second person (REQ-24) | Both set a claim aside with nothing left anywhere to work on, which is hiding risk. The proposer never approves their own, with no override |
| A duplicate needs nobody else, and names an issue open in this product | The work exists elsewhere, so nothing is hidden. The target is resolved against what the proposer may be told of, and one they may not answers as one that is not here |
| Not reproducible needs nobody else | It records that an attempt failed rather than that the claim is false. The reporter is still owed an answer and the report is raised as unanswered until they have one, and a reply carrying a way to reproduce it is met by withdrawing the ruling |
| A duplicate of an issue not open here is refused at submission | Nothing is left to work on, so it buries the report with nobody having agreed. Open is a place not closed, not suppressed by what the build said, and not dismissed by a decision in force; a deferral or a promised upgrade is work that comes back, and counts as open. The refusal says to reject it instead, which takes the second person |
| A reason is required on everything but a duplicate, and goes through the submission policy | A reviewer and a reporter asking why are owed a sentence. A duplicate's reason is the issue it names |
| A reason is never edited (REQ-28) | An approval is of particular words. Different words are a new ruling |
| A ruling covers many reports and is approved, sent back or undone as one act (REQ-28) | Twenty slop reports rejected in one sentence take one approval. An approver facing one row per report is given "select all", which is not review |
| A ruling is bounded by the bulk-judgment setting, counted in reports written (REQ-27) | Nothing re-checks a rejection. Naming one report twice writes it once, and a reference typed in another case is the same report |
| Every report named is in the product and unanswered, or nothing is written | A ruling that half applies is one nobody agreed to. Asked in the write, so two people ruling at once cannot both succeed |
| A waiting ruling holds its reports | Nobody accepts them as an issue or rules on them again until it is approved or withdrawn |
| A report under a waiting ruling reads as unjudged | Who judged it is written when the ruling takes effect. Before then one person has said it and nobody has agreed |
| Withdrawing needs nobody else | It returns every report the ruling covered to the inbox unanswered, which re-exposes risk. Sending a waiting ruling back and undoing one in force are this one act, and the proposer may withdraw their own |
| A withdrawn ruling stays on record with the reports it covered | The live pointer on each report is cleared; the list of what the ruling covered is kept apart from it |
| Rulings are read and approved under the report rule | A ruling says what a stranger's claim is, and reading it reads the claim. The approver capability over reading undisclosed work may agree to one, as a triager of undisclosed work may; the capability alone reaches none. Listed across products, a product the reader may not read reports in contributes nothing, not even to the count |

#### Duplicates on the issue

The reports ruled duplicates of an issue are listed on that issue, with what
arrived with each. A duplicate often carries the screenshot that makes the
issue clearer. The list is read under the report rule: the issue being
readable says nothing about whether what a stranger sent is.

#### The unanswered condition

A ruling answers what a claim is. It does not answer the reporter. A rejected
report nobody acknowledged is still raised as unanswered. A report found here
is never raised: there is nobody outside to answer.

## Scoring

| Rule | Reason |
|---|---|
| A score is never taken alongside a vector | Two values a caller states separately can disagree, and afterwards nothing says which was meant. The number sorts and the vector is what somebody can argue with |
| Base metrics only | Temporal and environmental scores describe a moment and a deployment, and the deployment reading a finding is not the one it is about |
| The formula is here and nowhere else | A screen composing a vector shows what it will score by asking, rather than holding a second copy: two implementations of a score disagree eventually, and what somebody saw while choosing would not be what was stored. That is what the scoring operation is for — it reads nothing, writes nothing and is reachable by any recognized credential, because a vector is not a secret |
| Version 3.0, 3.1 and 4.0; anything else refused by name | Version 2 is a different scheme, and a vector scored with the wrong formula produces a number nothing downstream can tell from a real one |
| Each scheme rounds its own way | Version 3 rounds up to a tenth, in integer arithmetic, because floating point gets a different answer for some inputs: a value that should be exactly 8.6 is not representable, and a naive ceiling returns 8.7. Version 4 rounds to the nearest tenth |
| An unstated vector is not a score of zero | Zero says "harmless", a judgment nobody made during early triage |
| A severity may be left unstated (REQ-18) | Making somebody choose a word to get the record written is how a guess ends up stored as a judgment. On a flaw recorded here it carries no deadline until somebody rates it, and says so as `not-rated` (REQ-33) |
| A person's severity is checked against the words rather than folded | A report's is folded, because a scanner that rated nothing is silent and silence is not a claim that something is mild. A person typing "urgent" is not silent; they are wrong, and folding would replace their judgment with one nobody made |
| The scheme a score is on travels with it | A number alone is not readable across schemes. It is recorded from the vector on a flaw assessed here, and from what the report states on one a scan brought in |
| The screen shows the newest generation's rating and names the others beside it | A report commonly rates one issue under version 3 and version 4. The number beside the issue is the newest generation's rating, whole, so a list and the finding screen show the same number on the same scheme. `DESIGN-ingest.md` holds which rating in a generation is kept |
| Weaknesses are recorded as given, against no catalog | Trimmed, upper-cased, de-duplicated. A list refusing an identifier it had not heard of would refuse next year's. Where a published document has to name one, the name is looked up then rather than checked now, and an identifier no catalog assigns is left out of that document rather than out of the record |
| Which one is the root cause is carried rather than picked | A published advisory states one weakness and an issue is commonly classified as several. The feeds say which they call primary, and a person recording a flaw names theirs first — the same statement made by hand. Choosing the lowest number or the earliest string instead is an answer with nothing behind it, and the two disagree: `CWE-20` is the lower number and `CWE-119` the earlier string |

### Version 4 classes

The version 4 base score is a lookup. Every vector falls into one of a few
hundred equivalence classes, each carrying a published score, and a vector
scores its class less how far it sits from the worst member of that class. The
distance is taken one class at a time, scaled by the drop to the class below,
and averaged over the classes that have something below them.

| Rule | |
|---|---|
| The classes carried are the ones scoring a base vector consults | Sixty of the published two hundred and seventy: the class a vector falls in, and the class below it wherever that contributes a distance. The rest are read once the threat and environmental metrics are scored, and the table grows with the code that reads them — a transcribed number nothing runs is a number nobody would find wrong |
| Exploitation contributes no distance | It is unstated on every base vector, so a vector has travelled none of the way down that class. The class counts toward the mean and adds nothing to it, and the score of the class below it is never read |
| A flaw with no impact anywhere scores zero before the tables | The lowest class is worth more than zero, so the one honest zero has to be recognized ahead of the lookup |
| A distance is measured from the first worst vector the class lists | Every member of a class that has a step below it is the same distance from the class floor. A class with nothing below it contributes no distance, and two of those list members that disagree |

### One ladder for every scheme

The five severity words over the same five ranges, in version 3 and version 4
alike. That is the whole of what makes a list holding both orderable.

| Rule | |
|---|---|
| Two scores under different schemes compare as bands, never as numbers | The schemes weigh reachability and impact differently, so 7.5 under version 3 and 7.5 under version 4 are two different judgments that are both high |
| A score is shown with the scheme it is on | A reader comparing two rows needs to know whether they are the same kind of number. Ranking treats them as one ladder, which only holds while the bands are the common ground |
| The back catalog never moves | A scan over a distribution base turns up issues rated under whichever scheme was current when they were published. Both scorers stand indefinitely, so the ladder is load-bearing for as long as the deployment runs |

## Affected build sets

Stated as a whole and the difference worked out. A set somebody can read back and
check is not the same as a stream of additions and removals.

Widening opens findings. Narrowing closes them as `invalid`, which counts as no
fix — the fix rate would otherwise improve every time somebody corrected a filing
mistake — and appears in no release note.

| Rule | Reason |
|---|---|
| A reason is required whenever a build is taken out, and no second person is | Removing a build with no explanation is the state a history exists to prevent. Requiring review to correct a filing mistake is how wrong records stay in place, and this narrows this deployment's own claim about its own product |
| Only a flaw recorded here | Which builds hold an issue a scanner reported is what the scans found, and setting it by hand would overwrite that |

## Closure by a person

Resolution is computed from scans everywhere else, which removes the gap between
somebody marking work done and the work being done. It needs evidence, and for a
recorded flaw there is none: the one path that closes a finding is a scan
applying what it found, and it passes over anything a person recorded.

So the computation has no input, and what that produces is not "not yet
resolved" but a finding that stays open for ever: a fix that shipped three
releases ago still reading as present, invisibly.

| Rule | Reason |
|---|---|
| A scanner's finding is refused | The evidence exists, and overruling it is what computing resolution was chosen to prevent |
| Closed per build, across every place the issue sits at there | A fix ships in a release |
| It carries who, when and why | A closure with no reason is refused |
| The reason is published, on the register | What is required of a person is readable: the category says a fix happened, the sentence says what the fix was, and the second is what somebody has years later. The refusal is a promise to whoever typed it that the sentence goes somewhere. A closure a scan performed carries a category and no sentence, because nobody typed one. It is not in a release note: a person's internal words are not a customer document, and a comparison of two builds already says what was fixed in the terms a release note needs |
| It asks the same right recording it asked, checked against each row | Somebody who may argue about disclosed findings has not been handed the undisclosed ones |
| Nothing reopens one | Undoing a closure needs somewhere to keep the closure that was undone, which is a table rather than a column |

Each refusal is the caller's to fix and says so: a name that reaches nothing, a
name that reaches several, a summary of nothing but whitespace, and a build with
no contents. The third is worth naming — a minimum length passes whitespace, so
it arrives from a request and is refused rather than answered as a server fault.

## The authority of a run

A run is the authority on what it reported. It opens what it found and closes
everything open that it no longer reports, which is how a component leaving a
build stops being a finding without anybody saying so.

The sweep is bounded by what a scan can have an opinion about. A finding carries
a kind saying what produced it, and the sweep covers only the kind a scan
produces. Without that bound, a flaw somebody recorded by hand is closed by the
first run after it is written — silently, with a closure reason reading as
though the issue went away, and nothing reporting it.

The kind exists ahead of the second thing to put in it for that reason: a model
assuming every finding came from a scan cannot take one that did not without
changing how closure works.

## Interval storage

Findings are open until closed and never deleted. Re-scanning happens nightly
against a vulnerability database that has barely moved, so a run finding the same
things writes nothing.

A finding carries when it opened and when it closed, rather than reaching the
run for a timestamp.

Three passes did the reaching, all as inner joins: the trend, the deadline
rewrite when the policy changes, and the urgency recount when a rating moves. A
finding with no run appears in none of them — not wrongly, but absent, which is
the worse failure. A number that is wrong invites somebody to check it; a row
that is missing looks like there was nothing to say.

Closure carries one more reason. Spelled as "a run closed this", the column
saying a finding is over can only be filled by something that never looks at
it, so a finding a run will never close cannot be closed at all. The row
carries the moment, and what closed it sits beside as provenance: the run, or
the person and their reason. Every index answering "is this open" carries the
moment rather than the run.

The run is still recorded where there is one, and it is what "what did this run
change" is counted by.

| Rule | Reason |
|---|---|
| One writer at a time, per target | Recording what a run found begins by taking the target row. Two runs in flight would both read the same open findings, compute the same difference and write it, leaving two open rows for one finding. An ordinary update is a lock every supported engine honors. The test runs two overlapping applications and was checked by removing the hold, which reproduces the double-open on all three server engines |
| A finding that is already open still moves | A fix appears, upstream declines to fix it, the build answers it. A run compares what it found against what is recorded and updates the parts that can move, stamping when they moved. Only those parts are compared: everything else is what makes it that finding |
| The intervals are the change record | Every node, edge, finding and claim records the run that opened it and the run that closed it, so asking what changed between two points is a query over those. There is no second table duplicating them |

## Closure reasons

| Reason | Meaning |
|---|---|
| Removed | The component is not in the build any more |
| Upgraded | Its upstream version moved — the version a vulnerability is matched against |
| Revised | The shipped version changed while the upstream version did not, which is what a carried patch looks like from outside |
| Superseded | The upstream version moved and the issue came with it: this row closed and the same issue is open against the new version |
| Fixed | Somebody declared a recorded flaw fixed here. The only closure a person writes |
| Unexplained | The component is present and unchanged, and the scanner stopped reporting it |
| Invalid | The record should not have existed: this build never shipped it, the entry named the wrong product, or it duplicates an issue already tracked |

Superseded is told apart from Upgraded because they are opposite answers to "was
this fixed", and conflating them put one issue in a release comparison as both
fixed and newly present.

Invalid is on a different axis. Every other reason answers "why did this stop
being present"; this says it was never present, so it is neither a resolution
nor a disappearance. It never means the finding exists but does not apply
here — that is a triage decision of `not-applicable` with the justification
that fits, agreed by a second person and exported as VEX. Letting the closure
absorb that case would route dismissals around approval.

Unexplained is always reported and never suppressed. There is no volume at which
"we cannot account for this" stops mattering. Several in one scan additionally
raise a scan-level warning, which says nothing the individual flags do not —
only that the likely fault is one broken scan rather than a dozen independent
oddities. A count rather than a proportion: on a large image a handful of
genuine disappearances is ordinary and a handful of unexplained ones is not.

The reason is worked out from what the build now contains, compared against what
the finding was about. That comparison reads the departed component from the
component catalog rather than the current build, because the reason it is closing
is usually that it is no longer there.

## Build-declared claims

A build sends what it has already decided does not apply to it. Those claims
are kept as data when the scan is read, not left in the document.

A nightly scan's documents are discarded once read, the vulnerability scan runs
after that, and it runs again on a schedule. A claim that lived only in the file
would be gone by the time anything needed it, and every carried patch would come
back as an outstanding vulnerability on the first re-scan.

A statement naming several packages becomes several claims, one per subject.
Claims are held over intervals, so re-sending them writes nothing; withdrawing
one closes it rather than deleting it, because what a release argued is a
question asked years later.

A covered finding is marked, not dropped. This is why claims are applied here
rather than upstream: a finding that never arrived is indistinguishable from a
scanner fault.

| The build says | Effect |
|---|---|
| It carries a fix, or the vulnerability does not apply | The finding is marked with the claim and is not work anybody has to do |
| It is affected, or it has not decided | Nothing is marked. The build is stating that it looked, which is information rather than an answer |

Where two claims cover one finding, the one attached to the component wins over
one that named something to be matched: the first knows exactly what it is about,
while the second may name a whole source tree. Where neither is attached, the
claims are read in a stable order.

## Fan-out cost

Measured on one real switch image, scanned live:

| | |
|---|---:|
| Components scanned | 8,523 |
| Distinct vulnerabilities | 5,652 |
| Components carrying at least one | 437 |
| **Findings** | **335,021** |
| …of which one kernel | **305,487** |

The kernel is 91% of it: 4,849 issues in it, and 62 modules built against it.
Those edges are real and the producer emits them deliberately, so anyone can
reason about kernel-ABI risk — but which module is loaded does not change whether
the kernel has a bug.

The model is not wrong: a finding is a component at a place, and those are the
places. What the number settles is that grouping cannot be an afterthought in
presentation. What is read back is one row per issue in a component, carrying
how many places it occupies and how many the build has already argued about. The
same image reads as 7,906 rows rather than 335,021.

The grouping is done by the database. A page of fifty grouped rows read out of a
third of a million findings is not a page of fifty findings, and counting in the
application would mean reading all of them to show any of them. Only the names
are fetched in a second pass, because aggregating text is spelled differently on
every engine.

## Decision state on a row

Each row carries how far it has been decided, in the same four words the state
filter takes and by the same definition:

| State | Condition |
|---|---|
| Undecided | Nothing stands, waits or has lapsed at any place |
| Waiting | A claim stands proposed and nobody has agreed |
| Agreed | Every place is answered by a standing decision |
| Lapsed | A decision here stopped applying and nothing replaced it |

Some places approved and the rest never decided, with nothing waiting or lapsed,
is none of the four: the row carries no state, and the interface labels it partly
decided.

Undecided is nothing standing, not nothing ever said. Read as "no decision row
covers this place" it leaves a withdrawn claim in no state at all: the row a
withdrawal leaves behind covers the place, deliberately, so that "lapsed" can
be said about a claim holding no key. A finding somebody claimed and took back
is then neither undecided nor any of the other three, disappears from the count
above the list as well as from the list, and is never offered as work again —
with the product's own totals counting it the same way and agreeing.

The word on the row and the filter's own buckets are one rule, not two
spellings of it. Two spellings come apart: a filter counting a place as waiting
without asking whether the claim still holds its key, against a row that
requires it, puts a claim proposed and withdrawn in the waiting list with a
blank state column; and a row asking "was anything ever said" for undecided
against a filter asking "does anything stand" makes one group undecided to one
and nothing to the other. Both ask the filter's question.

A live decision covers a place at the versions it was keyed on and no other.
These counts match a live decision by product, issue, place and both versions,
and match a lapsed or withdrawn one — which holds no key — by place alone.
Matched by place alone, a decision approved against one build's version read as
agreed over the next build shipping another.

A row also states when a live claim at one of its places is with its author, sent
back for more. That is the row a proposer is looking for, and the one the queue
no longer shows.

The page is read in two statements:

1. Group every open finding in the build by issue and component and keep the
   fifty most urgent, reading only the columns a covering index on the finding
   table holds. The total rides on the same statement as a window count over the
   groups, so it is counted through exactly the page's narrowing.
2. Read what the page shows about those fifty groups and no others: likelihood
   and score, the four decision counts, how many ways down there are, the fix.

Every filter narrows both statements through the same clauses, and none needs the
issue or the component joined under the grouping — a rating or a name is asked as
a membership test against the table that holds it. The decision-state filter is
built from the decisions outward, joined to the grouping by the finding's
identifier rather than a lookup per open row.

Measured on the full-size build, 241,479 open rows in 7,329 groups: the page
went from 2.0 s to 0.12 s, and asking for what is undecided from 2.3 s to 0.18
s.

## Urgency

Each finding carries an urgency, worked out when a scan is applied and read back
as written. Computing it while reading would mean joining every signal it is made
of, for every row, on every page of every list.

Ordering by how many places something occupies puts whatever is most widespread
at the top, which on a real image is the kernel.

It is worked out from what is on record about the issue, not from the report
being applied. A report is one source's account of one moment: it may omit that
something is being exploited, or carry a score lower than last week's. What the
issue holds is the worst anybody has claimed for the two that are claims, and
for the likelihood the newest anybody has published — see the table above for
why those differ.

Two of the signals belong to a product (REQ-29). The rating is the product's
own where somebody there has made one and the published word otherwise, and the
record that this product was exploited through the issue belongs to the product
it was recorded against; the rest are properties of the issue and reach every
product holding it. So the same issue can sit at two different places in two
products' lists. A finding opened later reads both at the moment it opens,
rather than carrying a copy something has to remember to refresh.

And it is rewritten wherever the issue is open, not only in the build being
scanned — once per product holding it, each against that product's rating. A
nightly branch scan raising one of the issue's signals left every other build
carrying a number worked out from a world that had moved — a known-exploited issue in a shipped tag below
the triage line, answering no exploited filter, on no exploited clock, at the
bottom of the list, until somebody rescanned that tag, which for a tag is never.

| Rule | |
|---|---|
| The signals that moved are what decides who is re-ranked | The write that raises them reports whether any of them actually rose, so nothing is recomputed for a report that told us nothing new |
| Only learning something is exploited moves a clock | Neither the score nor the likelihood is in the deadline, and a clock reset by a revised number would never arrive |
| The clock runs from when it was learned | Counted from when the finding opened, an issue that became exploited after six months lands three days before it was known — a deadline nobody could have met |
| The moment it was learned is kept on the row | Nothing else holds it, so every later recount had to guess and fell back to the opening — which moved the deadline back to a date already in the past, on any assessment, agreement or withdrawal that touched the issue, with nothing logged |
| It is not a cache being refreshed | The stored order describes an issue rather than a moment, so it is rewritten when the signals move. What is stored because it cannot be worked out again is a different thing |

Five signals, in this order:

| Signal | Reason for its position |
|---|---|
| This product recorded as exploited through it | A person here saying this product was attacked. Above the signal below it, which is a feed's word about somewhere that may not be here at all. `DESIGN-obligations.md` holds the record itself |
| Known to be exploited in the world | The difference between a risk and an incident |
| Reaches customers | A critical in something only the build system runs matters less than a medium in what people install |
| Severity | How bad it would be if it happened. Scores from two schemes rank against one another as bands — see § One ladder for every scheme |
| Likelihood of exploitation | Which of two equally severe things to look at first |

Severity above likelihood, measured rather than assumed. The original order had
them the other way, and on a real image that put a 2004 negligible with no score
at all above every one of 379 criticals: its likelihood was 0.80 where theirs
topped out at 0.073. Multiplying the two — the published practice where these
scores are well spread — was tried next and reversed on the same image: 95% of
its open issues sit between 0.001 and 0.01 likelihood, so multiplying mostly
amplifies what is inside that spike and mediums jump criticals on noise.

The number is packed rather than weighted: each signal owns a range of digits,
so a signal never trades against a lower one. The reason is explainability — "it
scored 0.4 higher on a weighted sum of five things" is not something anyone
trusts or argues with, and packing gives a rule statable in a sentence.

The two exploitation signals are one band each and are never read apart from
the number. A comparison against the lower of the two answers "is some
exploitation on this", which is what the triage line asks and what lets it stay
on an index holding only the urgency. Which of the two holds is a column, on
the finding, and every list and count that names one of them reads that column:
a feed's word about the world and a person's word about this product are
different facts, and a report that showed one where the other holds is the
confusion the pair exists to prevent.

Both columns are in the covering index the grouping reads, beside the urgency.
A list that aggregates a column outside it fetches a table row per open
finding, which is the cost the index was measured to remove.

Explainability is the packing, not a sentence generated beside it. A function
that turned a rank back into a list of reasons existed, exported and called by
nothing but its own test. What makes a position explainable is that the rule is
statable, and the interface says it from the signals a finding already carries.

A signal reported out of range is clamped. A source sending something
impossible otherwise carries into the band above and ranks as exploited.

The record of being exploited here moves no deadline. How long a fix may take
is a question about the work and about upstream, and being attacked says
nothing about either; what it does is admit the finding to the triage line
whatever the rating says, so a finding that was below the line gains the clock
its severity earns and one whose record is cleared may lose it again. It also
puts an upstream refusal back on that clock, which `DESIGN-remediation.md`
describes beside the other reasons a finding carries none.
`DESIGN-obligations.md` § Windows holds why the clock an obligation runs on is
not this one.

Where a report rates an issue only in words, the word stands in for a number, so
a finding rated in words does not sort below everything rated at all. A group
takes the urgency of the worst place it covers.

What is known changes under a finding that has not:

| Rule | Reason |
|---|---|
| The rank follows the issue | A scan finding the record has moved rewrites the urgency of every open finding of that issue. Held as at opening, the list would order by a number nobody could reconcile with the row beside it. It does not flap nightly, because the stored signals only move toward worse |
| The deadline follows only exploitation in the world | Severity is the flaw, exploitation is a fact about the world, and neither score nor likelihood sets a clock. A clock reset whenever a number was revised would never arrive |
| A recount runs from the scan that learned the fact | An issue that becomes exploited after six months, clocked from the opening, would be given three days that ran out five months ago. This is how the published exploited catalogs work: their due dates run from the date an entry was added |

## Work across builds

A judgment carries no variant: it is keyed on the product, the place and the
upstream versions, so answering it on one build answers it on every build of that
product holding the same code.

Screens asking "what is there to do" show one item per issue in a component in
a product, not one per build (REQ-25). Listed per build, importing a second
variant doubles the list while doubling none of the work — which is what happened
the day a second variant was seeded, and the list went from 7,354 items to
14,681 against the same estate.

| Rule | Reason |
|---|---|
| Genuine differences break out by themselves | A component row is one name at one version, shared by every build shipping it, so two variants at the same version group together and two at different versions do not |
| The product stays in the key | A decision is a claim about one product's code, so two products shipping the identical component at the identical version are two judgments |
| An item still names a build | A screen has to link somewhere. It is one of the builds rather than the only one, chosen stably, with the count of builds beside it |
| Acting on it acts on all of it | Assigning covers every build of the product holding the component. Assigning one build would leave the identical work unassigned beside it |
| Counted in pieces of work | Counted in findings, one kernel flaw assigned to one person read as forty-eight held against her on the summary and as the single item it is in her own list. Late is counted the same way: a piece of work is late when any of its places is |
| The spread over variants is asked on a place's own branch | A place is specific to a variant when no other variant of the branch it sits on holds the issue at the same fold, and common when every build of that branch holds it. Asked over a selection's branches together, a variant built on two branches is compared against the other variants of both: a place nothing shares on its own branch is dropped because a different variant of a different branch has it. A place held at another version is a different row and counts as not held, which is the rule above that genuine differences break out by themselves |
| A group keeps the places the spread admits | The question is about a place rather than about the group, so a group open on two branches keeps the places its variant is alone with and drops the places it is not. Answered for the group, one branch's unanimity would decide the other's |
| A build answers once its first scan has been read | A build exists from the moment a scan is filed against it, so a branch whose newest variant is still being read holds nothing common to every variant until that scan lands. The answer corrects itself as the scan does, which is the conservative half of not yet knowing |

Measured on two variants of one switch image: 7,587 rows on one and 7,610 on the
other, which is 15,197 rows read one build at a time. Across the product it is
7,612 — so 7,585 of those rows were one piece of work seen twice, and 27 were
the genuine differences.

What it gives up across builds is the way down. A dependency chain belongs to
one build's graph, so the column naming the two ends of the chain is empty
rather than filled from whichever build the row named. That is why the screens
*about* a chain still require a whole build, and why narrowing the list to a
subtree is refused rather than answered with the empty list walking no build
would produce.

A finding reads as one row per place. Two of its rows share a place where an
inventory describes one consumer twice — as a source package and as the
distribution's package: two components, one pair of names, and the key is the
names.

| Folding two rows into one place | |
|---|---|
| The way down is whichever of the two the graph could be walked to | Usually only one of them is reachable from the root |
| It is argued away by the build only where the build argued away both | An argument about one of two components is not an argument about the place |
| A claim standing on either row stands at the place, the lowest identifier first | A decision is keyed on the place and expires on the versions, and the two rows need not hold the same versions — a source package and the distribution's package of one name differ by a packaging revision, so a decision matches one row and not the other |

A row names what pulls it in even where the route up is unknown. Where the walk
up reaches nothing, the finding still records its consumer: what is missing is
the route up, which happens where an inventory describes something under a
component not itself reachable from the root. Blank at both ends a row says
nothing records what pulls this in, which is a different statement and a false
one. A row with no walkable chain names
its consumer and leaves the owner empty.

A place names the claim standing on it, not only the decision. At most one live
decision stands per combination of code, so the two reach the same row — but the
claim is what a person acts on, and without it a claim shown there can count its
places and cannot name them.

## Incomplete upgrades

A finding that stays open across a component's upstream version change, where the
shipped version is not the version recorded as fixing the issue, is marked as an
incomplete upgrade. Both inputs are already stored, and the test is inequality.

For a producer that patches and bumps rather than upgrading wholesale, this is
the failure that otherwise goes unnoticed for a whole release cycle. It surfaces
today as a lapsed decision and a finding to judge again, which is aimed at a
triager; the useful reading is aimed at whoever did the bump.

Component identity carries the version, so a bump closes one finding and opens
another rather than updating in place, and both versions are in hand at the
moment of the change. The closed row records `superseded` and the version it
moved to; the new row records the version it arrived from.

The version moved to is written as the scan applies and cannot be derived later,
because the component that carried the issue leaves the inventory when the run
ends. It is recorded only where the version change closed the finding — not for a
removed component, and not for an unexplained closure.

Shown on the finding as the version it arrived from, and in the still-present
column of a release comparison. Not in the review queue, which lists decisions
rather than findings.

## Scans as separate work

An inventory is read once, when it arrives. It is scanned again and again as the
vulnerability data moves underneath it, so reading an inventory leaves a scan to
be done rather than doing it.

| Rule | Reason |
|---|---|
| The scanner is given what was stored, not the file the build sent | That file is not kept for a moving line, so anything not stored can never be scanned. This is the argument for capturing a component's second identifier scheme at ingest |
| A distribution stated as a name and a version is told to the scanner in the qualifier it reads | The scanner matches a distribution's package against that distribution's advisories only when the identifier carries `distro`. Docker Scout and BuildKit write `os_name=debian&os_version=13` instead, and one real image of 142 Debian packages matched 3 times as written and 66 times with the qualifier added. The stored identifier is left as the producer wrote it |
| The product itself is left out of what the scanner sees | It is not a package any vulnerability database has heard of, and including it invites a match on a name that happens to collide |
| A build holding nothing but itself is scanned without the scanner | There is nothing to ask about, and handed an inventory of no components the scanner exits with an error rather than answering none. A services-only inventory, a VEX document sent as an inventory, and a source document naming only itself arrive this way, and each read as a scanner that stopped working |
| A run is recorded whether or not it found anything | Which scanner, which version, which vulnerability database, and whether it ran here. A run that failed is recorded as a run that failed, with the reason — a scanner that stopped working is otherwise indistinguishable from a product that stopped having problems |

## A year of nightly scans

The interval storage is shaped so a rebuild changing nothing writes nothing,
and a test asserts that. The shape after a year is a separate question.

The model, stated because every number depends on it: a build of 700 components,
each sitting in 34 containers, so 23,800 places; 260 issues open at the start;
365 nightly rebuilds; 1% of components changing version each night; three new
issues a night matching something already shipped. A real image at about a tenth
of its size, with the shape kept and the constant shrunk.

The table grew 16.8 times over the year, from 8,840 rows to 148,614. The graph
grew alongside: 23,834 edges to 110,466, and 736 nodes to 3,284, because a
component whose version moves opens a new node and 34 new edges while the old
ones stay as closed intervals. Neither is a leak — every row is an interval
somebody can ask a question about — but a deployment sizing a disk should know
the shape is multiplicative in consumers, not additive in components.

| | findings list | running out | trend | a night, average | a night, worst |
|---|---:|---:|---:|---:|---:|
| SQLite | 27 ms | 72 ms | 419 ms | 0.31 s | 0.51 s |
| PostgreSQL | 24 ms | 75 ms | 136 ms | 0.67 s | 1.11 s |
| MySQL | 65 ms | 100 ms | 259 ms | 4.82 s | 12.56 s |
| MariaDB | 24 ms | 115 ms | 215 ms | 0.32 s | 0.83 s |

Read the read columns as an order of magnitude, not as a benchmark. Each is one
sample, and the harness takes two seconds apart on identical data: MySQL's trend
was 1.19 s and then 259 ms, MariaDB's findings list 212 ms and then 24 ms. What
the run is for is the *growth*, which is stable across both samples.

| Finding | Detail |
|---|---|
| The reads hold up | The findings list grew between 1.5 and 3.5 times while the table grew 16.8, because it is indexed on the target and whether a finding is closed |
| Trend is the one that grows, about linearly | 18 ms to 394 ms on SQLite, 7 ms to 114 ms on PostgreSQL, 15 ms to 1.19 s on MySQL. It reads every interval overlapping the window rather than a page, and the open set grows as issues accumulate. It is the first query to reshape if a deployment reports a slow front page |
| MySQL writes seven times slower than PostgreSQL and fifteen times slower than MariaDB | A nightly scan taking thirteen seconds is not an operational problem; the same code being fifteen times more expensive on one supported engine than on its own sibling is a fact to have before somebody chooses one |
| The cost is per statement, not per row | A night issues **1,699 statements on every engine**. What differs is what one costs: **203 µs on MariaDB, 404 µs on PostgreSQL, 2,835 µs on MySQL**. The lever for making MySQL faster is issuing fewer statements |

Rewriting every deadline walks the identifier range once. The moments a
product's findings opened at ride inside the statement as a case over a batch of
them, rather than one statement per moment. The other way round the count was
moments × bands × identifier slices: a product scanned nightly for a year holds
about 1,800 distinct moments, so five builds and twenty-one slices came to
189,000 statements — almost all matching nothing, because one moment lives in
one slice — and the half-hour the caller allows expired partway, leaving the
estate split between the old policy and the new with nothing to retry it.

A quiet night issues **more** statements than the first — 1,699 against 1,077 —
because the first night is bulk inserts five hundred at a time and a quiet night
is an update per finding that moved.

What that cost is made of is readable from how it responds to churn. Halving
the churn halves MariaDB (0.64 s to 0.32 s) and cuts PostgreSQL by a third
(1.04 s to 0.67 s), and moves MySQL by four percent, from 5.01 s to 4.82 s. A
cost that barely responds to how many rows changed is paid per statement — and
because churn does not scale the four engines alike, a run applying twice the
churn it documents is withdrawn rather than halved.

Two reads grow with the calendar rather than with a build:

| After | receipts, first page | receipts, last page | release counts |
|---|---:|---:|---:|
| night 1 | 0–3 ms | 0–1 ms | 11–17 ms |
| night 365 | 3–4 ms | 2–3 ms | 71–88 ms |

The last page costs what the first does, because the pairing is done over all of
history precisely so it does not depend on which page is read. It grows with the
number of runs and not with the square of it: the uploads and the runs are both
held newest first and walked together once, so the upload a run is attributed to
is looked for from where the run before it stopped rather than from the top of
the list.

The two orderings that walk has to have are worth stating, because neither is
the one the page itself wants. The uploads are ordered by when they arrived
rather than by identifier — two recorded at the same moment take their
identifiers in whichever order they reach the table, and "the newest upload this
run covered" is a question about arrival. The runs are ordered by when they
finished rather than by identifier, which is the order the page reads them in.

Three things it does not measure. It is read as an administrator, who sees
every product, so the queries run with no narrowing by product — the cheapest
plan available. One build, not the several a deployment tracks. And it assumes a
churn rate rather than observing one. `make measure` re-runs it, and the
constants at the top of the harness are the model.

## The total above a list

The figure above a list is what somebody quotes, so it counts the population
the list itself pages through.

| Rule | |
|---|---|
| It rides on the page | Counted after the grouping and before the limit, in the statement that groups, so the number and the rows cannot describe different sets |
| The empty page counts the same way | A page past the end, a deep link somebody kept, or the last page has no row to carry it, so a second statement answers — **grouped exactly as the page groups**. Grouped one step finer, two binaries of one source count as two where the page draws one, and the figure changes with the page being read |
| A separate count is grouped the same way | Where the total genuinely cannot ride on the page, the second statement's key is the page's key spelled again. Where this issue sits counted one row per component and drew one row per component *name*, so a build shipping a name at two versions — which is ordinary — listed nine and said ten. It is also the wrong row to draw: the row carries one version and one fix version, and two versions of a name are two different pieces of work |
| Two overlapping lists are one question | The lapsed queue asked for lapsed decisions and for expired deferrals and added the totals. A deferral that ran out on code that then moved is both, so the figure was larger than the list beneath it and the list itself had to be deduplicated to draw at all. One filter answers both, and the number it comes back with is the number of rows |

## The severity ladder

The severity words are one list in one place. Written out per reader they
acquire names and memberships of their own, and a copy of an ordering is a
chance for a word added to one to be missing from the others.

| List | Purpose |
|---|---|
| The four rated bands | The order a report reads in |
| `negligible` and `none` | Answers a scanner gives and no band holds. The fold reads them as lows, so scoring them anywhere else put them above unrated and below every low — and a stored score turned back into a word came out "low" regardless, which is a word nobody published about the issue |
| `everything` | Not a severity: the absence of a floor, which is why it sits with the floor rather than the ladder |

The ordering in SQL is built from the list rather than written out beside it,
and the mapping back to a word is an index into the same list. The `ELSE` is
the caller's: a cross-product page needs an unrecognized rating to compare
below every band, so that the sentinel for "no line" does.

## The rating in force

What a finding's severity *is* has one rule: this product's word where it has
stated one, the published word otherwise. Being able to say a published
rating is wrong is pointless if the surfaces that count and rank then ignore
us.

Nine queries said it a second way. They selected the published column with no
rating joined at all, so a product that re-rated an issue saw its own decision
in the findings list, the severity filter, the triage floor and the deadline,
and saw the world's in the component tree, the bundle band strip, the build
comparison export, the remediation plan and the triage measures. Nothing
errored; the screens simply disagreed with the list they summarize, and the
comparison export is the copy that leaves the building.

The join and the two expressions live in `internal/rating`, which is a leaf.
That is the whole reason it exists: `internal/finding` imports `internal/graph`
to walk a subtree, so `internal/graph` cannot import `internal/finding` to ask
what a band is — and the band strip on the tree was drawn from the published
rating for exactly that reason. The rating *row* did not move: it is proposed,
agreed and put in force through `internal/finding`, which is where a second
person is asked for. What moved is the spelling a query needs.

| Rule | |
|---|---|
| A query presenting a severity joins the rating | The expression reads a column of the joined rating, so a statement that reads it without the join does not compile on any of the four engines. That is the failure being chosen; the alternative is a query that silently answers for the wrong product |
| It says which product it is asking about | Bound where the scope names one product, read off the row's own stream where the list spans products, read off the decision where the row is a decision. Three named spellings rather than a string parameter, because a placeholder cannot bind a column name |
| A query reading the published word says so | Five do, deliberately: what needs a second person is a rating milder than what the *world* called it, and a product that had already rated it milder would otherwise let the next step down through unwatched. Those alias the column `published`. Aliased `severity` they read as the rating in force, which is the one thing they must not be taken for |

## File organization

The reads had grown into one file of two and a half thousand lines. They are
three questions:

1. **What is open here** — the list every screen pages through.
2. Everything known about one issue at one component — what somebody looking
   at a single row needs. A different question from the list rather than a longer
   version of it.
3. What is open, gathered by the thing that would answer it — by the upstream
   bump that would close it, or by the component it is against.

The split turned up a doc comment describing the component grouping sitting two
hundred lines away, above an unrelated type.

The narrowing, the page and the component view each have their own test file
already, which is what says the seam is real rather than a line count. What is
left beside them is the naming layer they share.

### Deliberate omissions

Recorded because the conclusion is the deliverable: a review that asks the same
question next year should find the answer rather than the question.

| Left alone | Why |
|---|---|
| `Store.Apply` | Applying a scan is one act with four phases that share too much state to separate without passing a ten-field struct between them. It is also the model the rest of the package is held to: every value the closure uses it fetches inside the closure, the target is locked first, the difference is computed in memory and written as bounded batches |
| `Store.Enter` | Fifty lines of refusals, each with its own reason, and one transaction. Both belong to the act; what it needed was the transaction discipline, which it has |
| `fix.go` | Two responsibilities with a clean read-and-write seam, and one subject — upgrade commitments. Splitting it now would be splitting to hit a number. The cut is there when the write half grows |
| The schema migrations | Each is one list of `CREATE TABLE` statements, but for migration 37, which changes v0.1.0's tables and reads v0.2.0's declarations of them. The length is the schema, the comment beside each column is what makes it legible, and splitting a table group across two functions would break the ordering the chain exists to check |
| `sortedBy`, `sortedAcross` and the by-component order | The lookup, the direction and the null-last case are one function the three call. Their tie-breaks genuinely differ and stayed with each list, which is what a reader of one of them needs beside it: a shared function taking the tie-break as an argument would put it back at the call site as an argument nobody can read |

## Limits

| Limit | Detail |
|---|---|
| Incomplete upgrades are stated as inequality, not ordering | Saying that a version moved and is still not the one that fixes it needs no comparison, and the fixed-in field is free text and is sometimes a list. An ordering exists per ecosystem and refuses the rest — `DESIGN-remediation.md` § Version ordering holds it — and it ranks a set of candidates rather than deciding what a finding says |
| The inverse is not detected | A component at or past the named fix while the scanner still reports the issue means the scanner and the fix data disagree. Deciding that needs an ordering for the ecosystem in hand, which exists for some of them, so it is not asked at all rather than asked where it happens to be answerable |
| A component nothing leads to still has a place — itself | It ships, and an incomplete graph is normal |
| Severity is stored on the issue, fix state on the finding | Severity is a property of the vulnerability; whether a fix exists is a property of the version in front of you |
| A place under the product records no consumer at all | Rather than recording the root and excluding it later. The root's name differs per variant, and a key that has to be remembered to ignore is one somebody will forget |
| A derived address refuses a name that is nothing but dots, rather than escaping it | A name and a version become path segments, and "." and ".." are resolved by the browser before the request leaves it. Everything else, separators included, is escaped into its segment (REQ-66) |
| An identifier is matched against an anchored scheme before it resolves | A flaw this deployment recorded is filed under a name it minted, and a loose match sends somebody to a public page about something else |
| A package kind nothing here knows produces no link | A link that lands on the wrong thing costs more than no link, because it is followed before it is disbelieved |
| A patch link is labeled with branches and never with the product's own branch | Matching a branch name to the version a component ships is per project: `linux-6.12.y` and `release-1.4` follow no one convention |
| A code host's API is never asked | Every host answers through git, and only some offer an API that says which branches hold a commit. The same answer from two routes is two things to keep right |
| A repository's copy is fetched from the host the link names | The kernel's stable tree is 5.1 GB from git.kernel.org and 1.1 GB from a mirror that sends commits alone, and nothing here knows the two are one repository |
| The copies are one replica's disk | A second replica taking the lease over starts from none, or from a volume the replicas share |
| A deployment that reaches the internet only through a proxy of its own fetches nothing | git is pointed at the loopback guard and at nothing else, so the guard is the one way out, and the guard dials directly |
| A ruling carries one disposition and one reason for every report it covers | Reports needing different reasons are different rulings. Splitting one is withdrawing it and proposing two |
| Accepting a report takes no ruling and no second person | Accepting re-exposes risk, and an issue already carries its own triage |
