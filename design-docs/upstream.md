# Upstream statements

A product forking another project may trust that project's published VEX. A
statement holding for anybody shipping a component is applied here by itself,
at that component and version; one depending on the upstream's own build is
offered for review.

Satisfies REQ-31, REQ-42, REQ-68, REQ-69, REQ-71, REQ-84.

What this deployment publishes is `design-docs/publishing.md`; the evidence
layer every third party's statement lands in is `design-docs/triage.md`
§ Evidence from publishers; the closure is `design-docs/findings-closure.md`
§ Closure reasons; the outbound client is `design-docs/access-signin.md`
§ Outbound provider fetches.

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
- [Choices beyond the decisions](#choices-beyond-the-decisions)
- [Limits](#limits)

## Trusted upstreams

| Rule | Reason |
|---|---|
| One upstream per product | A fork descends from one project, and is a product of its own |
| The upstream is named by the address of its CSAF `provider-metadata.json`, over https, with a host and no user | |
| An administrator inspects it, then trusts it. Inspecting answers whose statements they are and the key's fingerprint; trusting sends the fingerprint back, and one other than the upstream names now is refused naming the one it names | The key is seen before anything is read |
| The keys are those the description names, at its addresses; the keys served must carry the fingerprints it states, or the set is refused | The whole set is trusted, up to four, so a rotation is trusted with both. The armored keys are kept with the upstream |
| An upstream naming no key is trusted unsigned | Documents are checked against their digests alone |
| The publisher is fixed when the upstream is trusted, as the description named it then | Every statement carries that name |
| Trusting the same address again keeps what was read, and clears a key offered in place of the trusted one | It is how a changed key is trusted |
| Another address is the same upstream moved, with no fingerprint asked | The trusted key still checks every document, and a different key at the new address stops reading until trusted. What the upstream said stands until the first complete read of the new address (§ Reading) |
| A redirect is never followed | An administrator names the new address |
| Stopping trusting sets aside everything it said, and queues the product's builds to be scanned again | The statements stay readable, because a decision citing one stays explicable |
| Each of these is an administrative trail row, under its own kind, with the address and the key | |

## Requests

Every request goes to the host the upstream's address names (REQ-69). An
administrator chose it, so it is reached wherever it is, inside this network
included, where a fork's own deployment of the upstream ordinarily sits.

| Rule | Reason |
|---|---|
| Only the configured host, at its port; a description, feed or list of changes naming another host reaches nothing, refused before anything is resolved | |
| https only, no redirect followed, no user in an address | The outbound client's rules for an address an administrator typed |
| Two minutes for one request | A listing or a document is read whole within it |

| Bound | Size |
|---|---|
| A provider description | 1 MiB |
| A feed or a list of changes | 64 MiB |
| A document | 32 MiB, and the bounds every VEX document read here is held to |
| A digest file | 4 KiB |
| A signature | 64 KiB |
| A public key | 1 MiB |
| Documents per pass per upstream | 200. A pass taking that many leaves the upstream due, so a first read drains over several passes |
| The lease | Asked for again before every document, so a slow read never overlaps another replica's. A pass that lost it stops, leaves the upstream due and withdraws nothing |

## Reading

A pass reads every upstream not read within the interval the setting names. One
replica reaches out, settled by a lease.

| Step | What happens |
|---|---|
| A read that fails | Withdraws nothing, however it failed: a description or listing answering 404 or another error, a TLS fault, a timeout. The failure is recorded and raised (§ Failure notices) |
| The description | Read every pass. A set of keys other than the set trusted, one added, dropped or replaced, any where none was trusted, or none where some were, stops the read and is recorded as the keys offered until an administrator trusts the upstream again. Trusting again does not clear what stopped the last read; a read that succeeds does |
| The listings | Each feed labeled WHITE or CLEAR, otherwise each directory's list of changes. Asked with the entity tag and date each last answered with; where every listing answers that nothing moved, nothing else is asked, and where one moved, every listing is read whole |
| What moved | A document listed at a moment other than the one recorded is read, and replaces what it said: a statement repeated stays as it is, declined or not, a revised one is replaced, a dropped one withdrawn |
| What is gone | A document no listing names is withdrawn only by a complete read: every listing read whole, every entry naming a document and a moment, every moved document taken and checked. A pass that left any behind, refused one, or met an unreadable entry withdraws nothing, and an unreadable entry is recorded as what stopped the read |
| A moved upstream | Its first complete read reconciles: a document the new address serves under the same tracking identifier replaces the one from the old address, as a revision, and one the new address does not list is withdrawn |
| A document | Fetched, compared against the digest served beside it, and checked against its signature where a key is trusted. One failing either is not taken, and the listings are read whole next pass so it is asked for again |
| Its name | The tracking identifier it names itself by; its statements are replaced by its next revision |
| A security advisory | Listed beside the VEX documents; read, recorded as read, nothing kept |

| Outcome recorded | Reason |
|---|---|
| When the upstream was last tried, and when a read last worked | The gap is how long it has been failing |
| All of it only while the upstream is trusted at the address the pass read | A pass against an address just moved from leaves the move alone |
| What stopped the last attempt, or what it could not take, bounded | It carries the upstream's address and a server's own reason phrase |

Where what the upstream says moved, a document at a new digest or withdrawn,
every build of the product holding an inventory and with no scan waiting is
queued to be scanned again.

## Statements recorded

An upstream's document lands where every third party's statement lands
(`design-docs/triage.md` § Evidence from publishers), replaced by its own name.

| The document names | Recorded as |
|---|---|
| A component alone, by package identifier, in a document OpenPSIRT generated, as the engine it names | Holding for anybody shipping that component, at the version the identifier names |
| A component inside something of the upstream's: its build, or what pulls the component in there | Depending on the upstream's own build; it places nothing here |
| A component alone, in a document other software generated | Offered for review. The format has no word for whom a statement holds for, so the shape says it only by this deployment's convention |
| A product named by no package identifier | Evidence, placing nothing |

This deployment's own CSAF VEX document uses the first shape for a statement
whose reason holds for anybody and the second for one whose reason is the
build's, and names OpenPSIRT as its engine (`design-docs/publishing.md`
§ Statement scope).

| Rule | Reason |
|---|---|
| The publisher is the one fixed when the upstream was trusted | One name per upstream |
| The document is recorded by the address it was fetched from, shown as a link to the source | |
| Recorded as brought in by the administrator who trusted the upstream | The one decision anybody made |
| Every statement the document makes is kept | What the upstream ships the fork ships, so a component a build adds later finds its statement there |

## Statements applied

A statement holding for anybody is applied by the run, beside a supplier's
statement about its own product, and closes the finding as disclaimed, naming
the statement (REQ-31, REQ-84).

| Rule | Reason |
|---|---|
| Only not affected and fixed close | Nothing else an upstream says closes anything, and nothing it says opens a finding |
| The component is matched by package identifier with the version aside, then at exactly the version the statement names | A statement about one version says nothing of the next |
| A statement naming no package identifier or no version closes nothing | |
| Wherever the component sits, the build's root included | The upstream speaks for the component |
| An occurrence somebody here decided about stays as decided | A decision that the match is wrong stands at any version; every other at the versions it was made at. An occurrence a statement closed can be decided about, and the next run opens it |
| A declined statement closes nothing | § Declined statements |
| The build's own patch and the issue's CVE record are asked first | Both say the code is not vulnerable here |
| What closes is worked out on every run | A statement set aside, revised away, declined or of an upstream no longer trusted closes nothing at the next run, which opens what it closed |
| A statement that the component is fixed is not stated as not affected | The VEX document of a build carrying suppliers' statements states a component only where every statement closing an occurrence of it said not affected |

## Offers for review

A statement depending on the upstream's own build is offered for review and
never applied by itself.

| Rule | Reason |
|---|---|
| Offered beside each open finding of the product at the same issue, by any name it goes by, at a component of the same name and version | |
| Listed in the review queue beside the decisions waiting for a second person, in the products the reader reads | |
| Not offered where somebody here proposed or agreed a decision about the occurrence | |
| A component named alone in a document other software generated is offered too | It closes nothing by itself (§ Statements recorded) |
| A declined statement offers no prefill on the finding | |
| Accepting one proposes an ordinary decision citing the statement | It goes through approval, and a later revision raises the alert a cited statement raises |
| Dismissing one declines it | § Declined statements |
| At most 200, oldest statement first | A person reads the list |

## Declined statements

| Rule | Reason |
|---|---|
| Somebody who may triage the product declines one, or takes the decline back | Declining opens what the statement closed, work coming back, so it needs nobody else |
| Only a statement an upstream published | A supplier's statement is answered by deciding about the occurrence |
| To anybody who may not triage the product, the statement does not exist | Authorized before anything about it is told |
| Recorded in the administrative trail, and the product's builds are queued to be scanned again | |
| A decision started from a statement is told when the statement is set aside; stopping trusting the upstream is said as that | The notice clears once the upstream, trusted again, says the same thing again |
| A decline stays while the upstream repeats the statement word for word | A revised statement is new, and not declined |

## Failure notices

| Rule | Reason |
|---|---|
| Raised once the last read failed and nothing has been read for longer than two read intervals | A failure the next read answers raises nothing |
| Told to administrators, in the area inside the application and wherever administrators' notices are carried | The area inside the application always exists |
| One notice while it fails, however many reads fail | It is a condition, which clears itself |
| It names the product, the address, the last error and when it was last read | What fixing it needs |
| Read again, it clears, and whoever held it is told once; stopping trusting the upstream clears it silently | |
| The drawer on the product's row shows when it was last read and the last error | |

## Settings

| Setting | Default | What it does |
|---|---|---|
| How often an upstream is read again | One hour | What an upstream withdraws stops closing findings here after the next read. A read whose listings have not moved is one request per listing, 18 ms (`design-docs/upstream-measurements.md`) |

## Choices beyond the decisions

| Choice | Reason |
|---|---|
| A statement applies by itself only from a document OpenPSIRT generated | Another publisher's statements are offered for review |
| OpenVEX documents are not read | A provider description names CSAF documents alone, and nothing standard says where an OpenVEX document is |
| The key is confirmed by sending its fingerprint back | The administrator sees the key before anything is read |
| A changed key stops reading and closes nothing new | What was recorded under the trusted key stands until the upstream is trusted again or no longer trusted |

## Limits

| Limit | Detail |
|---|---|
| What an upstream says is applied at the next scan | A read that moved queues every build of the product, so minutes; a withdrawn statement stays applied until then |
| An upstream that withdrew everything and stopped serving a description keeps what it last said | A failed read cannot be told from an outage, and withdrawal comes only from a read that worked; stopping trusting the upstream sets it aside |
| Offers match a component by name and version | Where the upstream named its own build, the same reasoning may hold at the same component and version; whether it does is the reviewer's question |
