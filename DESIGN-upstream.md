# Upstream statements

A product that forks another project may trust that project's published VEX
statements. A statement holding for anybody shipping a component is applied
here by itself, at that component and version; a statement that depends on the
upstream's own build is offered for review.

Satisfies REQ-31, REQ-42, REQ-68, REQ-69, REQ-71, REQ-84.

Neighboring pieces: what this deployment publishes, and how it says whom a
statement holds for, is in `DESIGN-publishing.md`; the evidence layer every
third party's statement lands in is in `DESIGN-triage.md` § Evidence from
publishers; the closure a statement makes is in `DESIGN-findings.md` § Closure
reasons; the outbound client is in `DESIGN-access.md`.

## Contents

- [Trusted upstreams](#trusted-upstreams)
- [Requests](#requests)
- [Reading](#reading)
- [Statements recorded](#statements-recorded)
- [Statements applied](#statements-applied)
- [Offers for review](#offers-for-review)
- [Declined statements](#declined-statements)
- [Failure notices](#failure-notices)
- [Settings](#settings)
- [Measurements](#measurements)
- [Choices beyond the decisions](#choices-beyond-the-decisions)
- [Limits](#limits)

## Trusted upstreams

| Rule | |
|---|---|
| One upstream per product | A fork descends from one project. A product is its own catalog entry, so a fork is a product of its own |
| The upstream is named by its CSAF provider description | The address of `provider-metadata.json`, over https, with a host and no user |
| An administrator inspects it, then trusts it | Inspecting reads the description and the key it names and answers whose statements they are and the key's fingerprint. Trusting sends the fingerprint back, and one other than what the upstream names now is refused naming the one it names |
| The keys are the ones the description names, at the addresses it gives | The keys served must carry the fingerprints the description states; a set that does not is refused. The whole set is trusted, so an upstream rotating from one key to the next is trusted with both, up to four. The armored keys are kept with the upstream |
| An upstream naming no key is trusted unsigned | Documents are then checked against their digests alone |
| The publisher is fixed when the upstream is trusted | What the description named then is whose name every statement carries |
| Trusting the same address again keeps what was read | It clears a key the upstream offered in place of the trusted one, which is how a changed key is trusted again |
| Another address is the same upstream moved | Its fingerprint is not asked for: the key trusted still checks every document, and a different key the new address names stops reading until it is trusted. What the upstream said stands until the first complete read of the new address (§ Reading) |
| A redirect is never followed | An upstream that moved is followed by an administrator naming the new address |
| Stopping trusting sets aside everything it said | The statements stay readable, because a decision citing one has to stay explicable. The product's builds are queued to be scanned again |
| Every one of these is in the administrative trail | Under its own kind, with the address and the key |

## Requests

Every request goes to the host the upstream's address names (REQ-69). The
host is chosen by an administrator, so it is reached wherever it is, inside
this network included: a fork's own deployment of the upstream project is
ordinarily on the same network.

| Rule | |
|---|---|
| Only the configured host, at its port | A description, a feed or a list of changes naming any other host reaches nothing. The request is refused before anything is resolved |
| https only, no redirect followed, no user in an address | The outbound client's rules for an address an administrator typed |
| Two minutes for one request | A listing or a document is read whole within it |

| Bound | |
|---|---|
| A provider description | 1 MiB |
| A feed or a list of changes | 64 MiB |
| A document | 32 MiB, and the bounds every VEX document read here is held to |
| A digest file | 4 KiB |
| A signature | 64 KiB |
| A public key | 1 MiB |
| Documents per pass per upstream | 200. A pass that took that many leaves the upstream due, so a first read drains over several passes rather than one each interval |
| The lease | Asked for again before every document, so a slow read never runs on past it beside a second replica's. A pass that lost it stops, leaves the upstream due and withdraws nothing |

## Reading

A pass reads every upstream that has not been read within the interval the
setting names. One replica reaches out, settled by a lease.

| Step | What happens |
|---|---|
| A read that fails | Withdraws nothing, however it failed: a description or listing answering 404 or another error, a TLS fault, a timeout. What the upstream said stands, and the failure is recorded and raised (§ Failure notices) |
| The description | Read every pass. A set of keys it names other than the set trusted — one added, one dropped, one replaced, or any where none was trusted, or none where some were — stops the read and is recorded as the keys offered, until an administrator trusts the upstream again. Trusting again does not clear what stopped the last read: a read that succeeds does |
| The listings | Each feed labeled WHITE or CLEAR, and otherwise each directory's list of changes. Asked with the entity tag and date each last answered with; where every listing answers that nothing moved, nothing else is asked. Where one moved, every listing is read whole |
| What moved | A document listed at a moment other than the one last recorded is read, and what it says replaces what it said: a statement it repeats stays as it is, declined or not, one it revises is replaced, and one it drops is withdrawn |
| What is gone | A document no listing names is withdrawn only by a complete read: every listing read whole, every entry in it naming a document and a moment, and every document that moved taken and checked. A pass that left any behind, refused one, or met an entry it could not read withdraws nothing, and an entry it could not read is recorded as what stopped the read |
| A moved upstream | Its first complete read reconciles what it said: a document the new address serves under the same tracking identifier replaces the one read at the old address, as a revision does, and one the new address does not list is withdrawn |
| A document | Fetched, compared against the digest served beside it, and checked against its signature where a key is trusted. A document failing either is not taken, and the listings are read whole on the next pass so it is asked for again |
| Its name | The tracking identifier it names itself by. Its statements are recorded under that name and replaced by its next revision |
| A security advisory | Listed beside the VEX documents; read, recorded as read, and nothing kept |

| Outcome recorded | |
|---|---|
| When the upstream was last tried, and when a read last worked | Two moments, so how long one has been failing is the gap between them |
| All of it only while the upstream is trusted at the address the pass read | A pass running against an address an administrator just moved from leaves the move alone |
| What stopped the last attempt, or what it could not take | Bounded, because it carries the upstream's own address and a server's own reason phrase |

Where what the upstream says moved — a document recorded at a new digest, or
withdrawn — every build of the product that holds an inventory and has no scan
waiting is queued to be scanned again.

## Statements recorded

An upstream's document lands where every third party's statement lands
(`DESIGN-triage.md` § Evidence from publishers), as one document among many,
replaced by its own name.

| The document names | Recorded as |
|---|---|
| A component alone, by its package identifier, in a document this deployment's software generated | Holding for anybody shipping that component, at the version the identifier names. The document says so by naming OpenPSIRT as the engine that generated it |
| A component inside something of the upstream's: its build, or what pulls the component in there | Depending on the upstream's own build. It places nothing here |
| A component alone, in a document other software generated | Offered for review. The format has no word for whom a statement holds for, so the shape says it only by this deployment's convention |
| A product named by no package identifier | Evidence, placing nothing |

This deployment's own CSAF VEX document says the first shape for a statement
whose reason holds for anybody, and the second for one whose reason is the
build's (`DESIGN-publishing.md` § Statement scope), and names OpenPSIRT as the
engine that generated it.

| Rule | |
|---|---|
| The publisher is the one fixed when the upstream was trusted | So every statement of one upstream carries one name |
| The document is recorded by the address it was fetched from | Shown as a link to the source document |
| Recorded as brought in by the administrator who trusted the upstream | The one decision anybody made |
| Every statement the document makes is kept | An upstream is the project a fork descends from, so what it ships the fork ships, and a component a build adds later finds the statement already there |

## Statements applied

A statement holding for anybody is applied by the run, beside a supplier's
statement about its own product, and closes the finding as disclaimed, naming
the statement (REQ-31, REQ-84).

| Rule | |
|---|---|
| Only not affected and fixed close | Nothing else an upstream says closes anything, and nothing it says opens a finding |
| The component is matched by its package identifier, its version aside, and then at exactly the version the statement names | A statement about one version says nothing about the next |
| A statement naming no package identifier or no version closes nothing | |
| Wherever the component sits, the build's root included | The upstream speaks for the component, not for what pulls it in |
| A place somebody here decided about stays as they decided, whatever they decided | A local decision stands over an upstream's word. A claim that the match is wrong stands at whatever version the place holds; every other decision at the versions it was made at. A place the statement closed can be decided about, and the next run opens it again |
| A declined statement closes nothing | § Declined statements |
| The build's own patch and the issue's CVE record are asked first | Both say the code is not vulnerable here |
| What closes is worked out on every run | A statement set aside, revised away, declined or of an upstream no longer trusted closes nothing at the next run, which opens what it closed |
| A statement that the component is fixed is not stated as not affected | The VEX document of one build carrying suppliers' statements states a component only where every statement closing a place of it said not affected |

## Offers for review

A statement depending on the upstream's own build is offered for review and
never applied by itself.

| Rule | |
|---|---|
| Offered beside each open finding of the product it speaks about | The same issue, by its name or another it goes by, at a component of the same name and version |
| Listed in the review queue | Beside the claims waiting for a second person, in the product the reader reads |
| Not offered where somebody here decided about the place | A claim proposed or agreed takes it out of the list |
| A component named alone in a document other software generated is offered too | It closes nothing by itself (§ Statements recorded) |
| A declined statement offers no prefill on the finding | |
| Accepting one proposes an ordinary claim, citing the statement | The claim goes through approval as any other, and a later revision of the statement raises the alert a cited statement raises |
| Dismissing one declines it | § Declined statements |
| At most 200, oldest statement first | The list is read by a person |

## Declined statements

| Rule | |
|---|---|
| Somebody who may triage the product declines one, or takes the decline back | Declining opens what the statement closed, which is work coming back rather than going away, so it needs nobody else |
| Only a statement an upstream published | A supplier's statement is answered by deciding about the place |
| To anybody who may not triage the product, the statement does not exist | Authorized before anything about it is told |
| Recorded in the administrative trail, and the product's builds are queued to be scanned again | |
| A decision started from a statement is told when the statement is set aside | Stopping trusting the upstream is said as that, and the notice clears once the upstream, trusted again, says the same thing again |
| A decline stays with the statement while the upstream repeats it word for word | A statement the upstream revises is a new statement, and is not declined |

## Failure notices

| Rule | |
|---|---|
| Raised once the last read failed and nothing has been read for longer than two read intervals | One failed read the next answers raises nothing |
| Told to administrators, in the area inside the application and wherever administrators' notices are carried | The area inside the application is the channel that always exists |
| One notice while it fails, however many reads fail | It is a condition, which clears itself |
| It names the product, the address, the last error and when it was last read | What an administrator needs to fix it |
| Read again, it clears, and whoever held it is told once that it is read again | Stopping trusting the upstream clears it with nothing said |
| The drawer on the product's row shows when it was last read and the last error | |

## Settings

| Setting | Default | What it does |
|---|---|---|
| How often an upstream is read again | One hour | What an upstream withdraws stops closing findings here after the next read. A read whose listings have not moved is one request per listing |

## Measurements

The full-size switch image shipped by the upstream and by a fork on
PostgreSQL, every component with a package identifier carrying one issue:
6,843 issues at components. The upstream agrees 76 of the distribution packages'
issues do not apply because the code is not there, and publishes, signed. The
fork reads it over TLS from a server on the same machine.

| Measured | |
|---|---|
| Documents read and recorded on the first read | 76, every one holding for anybody, each checked against its digest and its signature |
| The first read | 0.40 s |
| A read over nothing that moved | 18 ms, one request for the description and one for the feed, answered that nothing moved |
| The fork's run over its build | 0.58 s before it trusts the upstream, 0.60 s with the 76 statements standing |
| Findings that run closes | 508: the 76 issues at every place the image ships them |

## Choices beyond the decisions

| Choice | |
|---|---|
| A statement applies by itself only from a document OpenPSIRT generated | Another publisher's statements are offered for review |
| OpenVEX documents are not read | A provider description names CSAF documents and nothing else, and nothing standard says where an OpenVEX document is |
| The key is confirmed by sending its fingerprint back | The administrator sees which key the documents will be checked against before anything is read |
| A changed key stops reading and closes nothing new | What was recorded under the trusted key stands until the upstream is trusted again or stopped being trusted |

## Limits

| | |
|---|---|
| What an upstream says is applied at the next scan | A read that moved queues every build of the product, so that is minutes rather than a day; a statement withdrawn stays applied until then |
| An upstream that withdrew everything and stopped serving a description keeps what it last said | A failed read cannot be told from an outage, and withdrawal is taken only from a read that worked; stopping trusting the upstream sets it aside |
| Offers match a component by name and version | The upstream named its own build, and a component of the same name at the same version is where the same reasoning may hold; whether it does is the reviewer's question |
