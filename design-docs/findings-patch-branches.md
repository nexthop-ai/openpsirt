# Patch branches

A patch link to a commit is labeled with the branches of its repository that
contain the commit (REQ-78). One fix is backported as a separate commit per
maintained branch, and a report lists them as bare links; the repository's
history says which is which, so a copy is kept and asked.

Satisfies REQ-78.

## Contents

- [Switch](#switch)
- [Link shapes](#link-shapes)
- [Keying](#keying)
- [The pass](#the-pass)
- [Host share](#host-share)
- [Visits](#visits)
- [Fetching](#fetching)
- [The cache](#the-cache)
- [Display](#display)
- [Limits](#limits)

## Switch

Off unless the deployment's configuration turns it on; never under Settings
(REQ-78). It needs memory for git, a volume, and a list of excluded hosts, which
only the deployer can provide. Read at startup. A scan needs none of it (REQ-12).

## Link shapes

| Shape | Hosts |
|---|---|
| `/{owner}/{repo}/commit/{hash}` | GitHub, Gitea, Forgejo, Gogs |
| `/{owner}/{repo}/pull/{n}/commits/{hash}` | A commit inside a GitHub pull request |
| `/{group…}/{repo}/-/commit/{hash}` | GitLab |
| `/{path…}/commit/?id={hash}` | cgit |
| `/stable/c/{hash}`, `/linus/{hash}` | git.kernel.org's stable and mainline short links |

| Rule | Reason |
|---|---|
| The repository address is built from recognized parts, never copied | A segment outside a narrow character set, a port, or credentials names no repository |
| A hash is 7 to 64 hex characters, lowered; an abbreviation is resolved by the copy | Shorter is as likely a pull request number |
| Pull requests, merge requests, patch trackers and list posts name no commit | A guessed repository is a request somewhere the link never pointed |
| A cgit site serving pages and repositories at different addresses is mapped (below) | |
| A repository address is one git reaches without a redirect | A fetch follows none |

| cgit site | Page | Repository |
|---|---|---|
| git.kernel.org | `/cgit/{path}` | `git.kernel.org/pub/scm/{path}` |
| git.savannah.gnu.org, cgit.git.savannah.gnu.org | `/cgit/{repo}` | `https.git.savannah.gnu.org/git/{repo}` |
| git.savannah.nongnu.org, cgit.git.savannah.nongnu.org | `/cgit/{repo}` | `https.git.savannah.nongnu.org/git/{repo}` |
| cgit.freebsd.org | `/{repo}` | `git.freebsd.org/{repo}` |
| sourceware.org | `/cgit/{repo}` | `sourceware.org/git/{repo}` |

A retired site's repository is read at its new address where the move is known
and checked to clone. Any other repository on a retired site fails with git's
reason. A repository row under an address no link reads any more is left out of
the report.

| Link reads as | Fetched from |
|---|---|
| `cgit.freedesktop.org/drm/drm-misc` | `gitlab.freedesktop.org/drm/misc/kernel` |

## Keying

A row per repository, per commit in it, and per branch a commit is on. Keyed on
the commit, because one fix is linked from several records in several spellings.

| Recorded per commit | Detail |
|---|---|
| When it was last looked up | Null is never, taken first |
| Whether the copy resolved it to one commit | Unmerged, rewritten-away and ambiguous abbreviations all show as not found |
| How many branches hold it, and up to a hundred names | The count stays whole; a name wider than the column, or not UTF-8, is counted and not kept |

| Recorded per repository | Detail |
|---|---|
| When a visit last began and finished, and what stopped it | How long it has been out of reach is the gap |
| The copy's size at the last finished visit | What an operator sizing the cache reads |

## The pass

One replica works, under a lease renewed every minute through the whole visit;
a first kernel fetch takes a quarter of an hour, and the lease is half an hour.
A process shutting down hands the lease back. Each wake records any linked
commit with no row, then visits repositories one after another until none has a
commit due.

| Pace | Reason |
|---|---|
| Visits follow each other with no wait while work is due | A small visit takes about a second. A five-minute gap kept the kernel tree, holding 35,990 of 36,463 linked commits, waiting four hours behind the demo's 48 small copies |
| A wake ends on nothing due, a lost lease, this deployment failing, or shutdown | |
| The same repository chosen twice running ends the wake | The visit changed nothing |

| Order | Reason |
|---|---|
| A host still within its share before any past it | § Host share |
| A held copy with commits never looked up | A small fetch, then sub-second lookups |
| Then the most urgent commit never looked up | Worst rating among issues linking it, then the score |
| Then the most urgent commit due again, a week after its lookup | Backport branches do not change; a mainline commit gains one every few months |
| Never an excluded host, nor a repository within a day of a failed visit | The host is read from the stored address, which is whole |

Only commits a report still links to are due; an unlinked commit keeps what was
last recorded.

## Host share

A host's share is three hours of visits in the last day, the longest one fetch
may take. Links come from advisories anybody can write, and a slow repository
holds the pass for as long as a fetch is allowed.

| Rule | Reason |
|---|---|
| A visit's time runs from begin to end, however it ended | |
| A host's time sums its repositories' last visits ended within the day | |
| A host past its share waits behind every host within it; among those past, least-used first; urgency still orders repositories on one host | |
| No host is exempt by name, github.com included | |
| A host waits out a day where a repository on it failed within the day and none on it was reached | One failed visit a day per dead host; one success says the host answers |
| Within one wake, every host gets one never-fetched repository before any gets a second | First fetches are the longest, and scan files choose the hosts |

The report's positions come from the same rule and rows, so any replica answers.
A host waiting out has no position; the one-first-fetch rule is not in them.

## Visits

A visit fetches branches, writes git's commit-graph index, and looks up every
due commit, most urgent first.

| How a visit ends | Recorded |
|---|---|
| Every due commit looked up | Reached and ended, and the copy's size |
| The repository could not be fetched or read | What stopped it in git's words; retried a day after the visit began |
| The lease was lost, or shutdown | Nothing; the repository is left as before the visit |
| This deployment failed (database or lease) | Nothing, and logged. A dropped connection is not the repository's fault |

| Rule | Reason |
|---|---|
| A git that must stop is asked to, and killed a minute later | Killed mid-write, it leaves lock files that fail every later fetch |
| Lock files found before a visit writes are removed | Only this pass writes, one visit at a time |
| A lookup reads git's output a branch at a time, keeping the first hundred in version order | A hundred thousand branches cost a hundred names |

## Fetching

Git is pointed at a proxy on the loopback interface, which is its one way out;
the dialer every other request uses never sees git's connections.

| Rule | Reason |
|---|---|
| A tunnel only, to port 443 of the one host the repository is on | Redirects, submodules and lazy objects have no route |
| A host excluded by name, or by a network holding its address, is refused | |
| Loopback, private, link-local, shared and the local-use NAT64 prefix are refused regardless, on the resolved address at connect time (REQ-69) | The local-use prefix places the IPv4 address where the network chose |
| A well-known NAT64 address is judged by its last 32 bits against both rules | `64:ff9b::a00:5` is 10.0.0.5. Refused whole, an IPv6-only deployment reaches no IPv4-only host |
| Git reads no system or personal configuration, credential helper, hook or terminal | Each changes where git goes or what it sends |
| https only, no redirects; below 1 KB/s for two minutes is abandoned | |
| One thread for packing and indexing, with small pack windows | Commit-graph memory falls from 1.7 GB to 0.6 GB on the kernel tree |
| A copy holds commits without files where the host sends that | A host that cannot sends everything, and its warning is not a failure |
| Missing objects are never fetched on demand | That fetch is outside the guarded one |
| A copy's directory is named by a digest of the address (REQ-66) | A report never chooses a path |

## The cache

| Rule | Reason |
|---|---|
| Copies share a quota, 20 GB unless configured | The full kernel tree and several more |
| Least recently visited is removed first | |
| Room is made while a copy is written; the directory stays within the quota plus fifteen seconds of transfer | |
| A copy that alone outgrows the quota is stopped and removed; the visit fails, retried a day later | |
| A removed copy's recorded size is cleared | The report reads that record |
| An update asks the remote the copy was made from, never the bare address | Asked by address, a host sends trees the copy cannot hold |
| The copies directory is made absolute at start | Git runs inside it |
| A half-made copy from a dead process is removed before the next starts | |

## Display

A finding's patch links carry the branches in version order (`linux-6.6.y`
before `linux-6.12.y`), the count, and whether the copy held the commit. A link
not looked up carries nothing.

The System screen's Patch branch lookups panel, administrators only, reports the
whole of the work (patch links, the commits they name, how many are looked up
and held) in the pass's own order.

| Part | Holds |
|---|---|
| The visit under way | The repository, its step, commits looked up against those still due |
| What comes next | Each repository with a commit due, numbered, with the count and worst rating |
| Failed | What stopped it, and when it is retried |
| Excluded | The hosts nothing is fetched from |
| Done | When each finished, and its copy's size |

| Rule | Reason |
|---|---|
| The order is the pass's own plan | Another order describes work nobody is doing |
| A copy counts as held where the last visit recorded a size | Any replica answers; only the worker sees its disk. After the lease moves the two can disagree until the next visit |
| A commit linked since the last wake counts as never looked up | The report writes nothing |
| The step is fetching until the visit's first lookup, then looking up | Lookups are recorded as they happen |

| Measured on the kernel's stable tree | |
|---|---|
| Commits | 2,024,354 |
| Copy without files | 1.1 GB, 90 s, 160 MB of memory |
| Full copy from git.kernel.org | 5.1 GB, 15 min; indexing 2.4 GB of memory at git's defaults, 1.3 GB with the windows |
| Commit-graph index | 116 MB, 22–35 s |
| One lookup | 28 s without the index, 0.12–0.22 s with it |
| The demo's linked commits in it | About 25,000; about ninety minutes of one core |
| The demo's patch links | 36,625, of which 36,000 are `git.kernel.org/stable/c/` |

## Limits

| Limit | Detail |
|---|---|
| A host's share bounds time, not disk | One arriving copy may fill the quota and evict the rest; they are fetched again as their commits fall due |
| A patch link is labeled with branches, never with the product's branch | Branch naming is per project: `linux-6.12.y`, `release-1.4` |
| No code host's API is asked | Every host answers through git; two routes are two things to keep right |
| A copy comes from the host the link names | The kernel tree is 5.1 GB from git.kernel.org and 1.1 GB from a commits-only mirror, and nothing here knows they are one repository |
| The copies are one replica's disk, and nothing records which replica holds which | A replica taking the lease starts from none, or from a shared volume |
| A deployment reaching the internet only through its own proxy fetches nothing | The guard dials directly |
