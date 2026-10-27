# Upstream statements

A product forking another project may trust that project's published VEX. A
statement holding for anybody shipping a component is applied here by itself;
one depending on the upstream's own build is offered for review.

Satisfies REQ-31, REQ-42, REQ-68, REQ-69, REQ-71, REQ-84.

Neighbors: `design-docs/publishing.md` (what this deployment publishes),
`design-docs/triage.md` § Evidence from publishers,
`design-docs/findings-closure.md` § Closure reasons, and
`design-docs/access-signin.md` § Outbound provider fetches.

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
| One upstream per product | A fork descends from one project |
| The upstream is named by the address of its CSAF `provider-metadata.json`, over https, with a host and no user | |
| An administrator inspects it, learning whose statements they are and the key's fingerprint, then trusts it by sending the fingerprint back; another fingerprint is refused naming the current one | |
| The keys are those the description names, at its addresses, and must carry the fingerprints it states, or the set is refused. The whole set is trusted, up to four, and the armored keys are kept | A rotation is trusted with both |
| An upstream naming no key is trusted unsigned, documents checked against their digests alone | |
| The publisher is fixed at trust, as the description named it then | |
| Trusting the same address again keeps what was read, and clears a key offered in place of the trusted one | |
| Another address is the same upstream moved, with no fingerprint asked; a different key there stops reading until trusted, and what was said stands until the new address's first complete read (§ Reading) | The trusted key still checks every document |
| A redirect is never followed | An administrator names a new address |
| Stopping trusting sets aside everything it said, and queues the product's builds to be scanned again; the statements stay readable | A decision citing one stays explicable |
| Each of these is a trail row, under its own kind, with the address and the key | |

## Requests

Every request goes to the host the upstream's address names (REQ-69). An
administrator chose it, so it is reached inside this network too, where a fork's
copy of the upstream ordinarily sits.

| Rule | Reason |
|---|---|
| Only that host, at its port: a description, feed or list of changes naming another host is refused before anything is resolved | |
| https only, no redirect followed, no user in an address | |
| Two minutes for one request, in which a listing or document is read whole | |

| Bound | Size |
|---|---|
| A provider description | 1 MiB |
| A feed or a list of changes | 64 MiB |
| A document | 32 MiB, and the bounds every VEX document read here is held to |
| A digest file | 4 KiB |
| A signature | 64 KiB |
| A public key | 1 MiB |
| Documents per pass per upstream | 200; a pass taking that many leaves the upstream due |
| The lease | Asked for again before every document; a pass that lost it stops, leaves the upstream due and withdraws nothing |

## Reading

A pass reads every upstream not read within the setting's interval. One replica
reaches out, settled by a lease.

| Step | What happens |
|---|---|
| A read that fails | Withdraws nothing, however it failed: a 404 or other error, a TLS fault, a timeout. It is recorded and raised (§ Failure notices) |
| The description | Read every pass. Any set of keys other than the trusted set (one added, dropped or replaced, any where none was trusted, none where some were) stops the read and is recorded as the keys offered until the upstream is trusted again. Only a successful read clears what stopped the last one |
| The listings | Each feed labeled WHITE or CLEAR, otherwise each directory's list of changes, asked with the entity tag and date each last answered. Where all answer that nothing moved, nothing else is asked; where one moved, every listing is read whole |
| What moved | A document listed at a new moment is read and replaces what it said: a repeated statement stays as it is, declined or not, a revised one is replaced, a dropped one withdrawn |
| What is gone | A document no listing names is withdrawn only by a complete read: every listing read whole, every entry naming a document and a moment, every moved document taken and checked. Otherwise nothing is withdrawn, and an unreadable entry is recorded as what stopped the read |
| A moved upstream | Its first complete read lets a document under the same tracking identifier replace the old address's, as a revision, and withdraws what the new address does not list |
| A document | Compared against the digest served beside it, and its signature where a key is trusted. One failing either is not taken, and the next pass reads the listings whole |
| Its name | The tracking identifier it names itself by; its next revision replaces its statements |
| A security advisory | Read, recorded as read, nothing kept |

| Outcome recorded | Reason |
|---|---|
| When the upstream was last tried, and when a read last worked | The gap is how long it has failed |
| Only while the upstream is trusted at the address the pass read | A move made during the pass stands |
| What stopped the last attempt or what it could not take, bounded | It carries the upstream's address and reason phrase |

Where what the upstream says moved, every build of the product holding an
inventory and with no scan waiting is queued to be scanned again.

## Statements recorded

An upstream's document lands with every third party's statements
(`design-docs/triage.md` § Evidence from publishers), replaced by its own name.

| The document names | Recorded as |
|---|---|
| A component alone, by package identifier, in a document naming OpenPSIRT as its engine | Holding for anybody shipping it, at the version the identifier names |
| A component inside the upstream's build, or what pulls it in there | Depending on the upstream's own build; placing nothing |
| A component alone, in a document other software generated | Offered for review: the format has no word for whom a statement holds for, so only this deployment's convention says it |
| A product named by no package identifier | Evidence, placing nothing |

This deployment's own CSAF VEX document uses the first shape where a reason holds
for anybody and the second where it is the build's
(`design-docs/publishing.md` § Statement scope).

| Rule | Reason |
|---|---|
| The publisher is the one fixed at trust | |
| The document is recorded by the address it was fetched from, shown as a link | |
| Recorded as brought in by the administrator who trusted the upstream | |
| Every statement the document makes is kept | A component a build adds later finds its statement there |

## Statements applied

A statement holding for anybody is applied by the run, beside a supplier's
statement about its own product, closing the finding as disclaimed and naming
the statement (REQ-31, REQ-84).

| Rule | Reason |
|---|---|
| Only not affected and fixed close; nothing an upstream says opens a finding | |
| The component is matched by package identifier, version aside, then at exactly the version the statement names | |
| A statement naming no package identifier or no version closes nothing | |
| Wherever the component sits, the build's root included | |
| An occurrence somebody here decided about stays as decided: a wrong-match decision at any version, any other at the versions it was made at. An occurrence a statement closed can be decided about, and the next run opens it | |
| A declined statement closes nothing | § Declined statements |
| The build's own patch and the issue's CVE record are asked first | |
| What closes is worked out on every run, so a statement set aside, revised away, declined or of an untrusted upstream stops closing at the next run | |
| A fixed statement is not passed on as not affected: a build's VEX document states a component only where every statement closing an occurrence of it said not affected | |

## Offers for review

A statement depending on the upstream's own build is offered, never applied.

| Rule | Reason |
|---|---|
| Offered beside each open finding of the product at the same issue, by any of its names, at a component of the same name and version | |
| Listed in the review queue beside decisions awaiting a second person, in the products the reader reads | |
| Not offered where somebody here proposed or agreed a decision about the occurrence | |
| A component named alone in other software's document is offered too | § Statements recorded |
| A declined statement offers no prefill | |
| Accepting one proposes an ordinary decision citing it, through approval; a later revision raises the alert a cited statement raises | |
| Dismissing one declines it | |
| At most 200, oldest statement first | A person reads the list |

## Declined statements

| Rule | Reason |
|---|---|
| Somebody who may triage the product declines one, or takes the decline back | It brings work back, so needs nobody else |
| Only a statement an upstream published | A supplier's is answered by a decision |
| To anybody who may not triage the product, the statement does not exist | Authorized before anything is told |
| Recorded in the administrative trail, and the product's builds are queued to be scanned again | |
| A decision started from a statement is told when the statement is set aside, an untrusted upstream said as that; the notice clears once the upstream, trusted again, says the same again | |
| A decline stays while the upstream repeats the statement word for word | A revision is a new statement |

## Failure notices

| Rule | Reason |
|---|---|
| Raised once the last read failed and nothing was read for longer than two read intervals | One failure the next read answers raises nothing |
| Told to administrators, in the area inside the application and wherever their notices are carried | |
| One notice while it fails, naming the product, the address, the last error and the last read | It is a condition |
| Read again, it clears, and whoever held it is told once; stopping trusting clears it silently | |
| The drawer on the product's row shows the last read and the last error | |

## Settings

| Setting | Default | What it does |
|---|---|---|
| How often an upstream is read again | One hour | What an upstream withdraws stops closing findings after the next read; an unmoved read is one request per listing, 18 ms (`design-docs/upstream-measurements.md`) |

## Choices beyond the decisions

| Choice | Reason |
|---|---|
| A statement applies by itself only from a document OpenPSIRT generated | Other publishers' are offered for review |
| OpenVEX documents are not read | A provider description names CSAF alone, and nothing standard locates OpenVEX |
| The key is confirmed by sending its fingerprint back | It is seen before anything is read |
| A changed key stops reading and closes nothing new | What was recorded stands until the upstream is trusted again or no longer |

## Limits

| Limit | Detail |
|---|---|
| What an upstream says is applied at the next scan | A moved read queues every build, so minutes |
| An upstream that withdrew everything and stopped serving a description keeps what it last said | A failed read looks like an outage; stopping trusting sets it aside |
| Offers match a component by name and version | Whether the upstream's reasoning holds here is the reviewer's question |
