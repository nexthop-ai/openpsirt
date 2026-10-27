# Supplier directories

A supplier's CSAF advisories read on the scan schedule from the provider
description an administrator configured, landing where an uploaded advisory
lands (`design-docs/ingest-claims.md` § Supplier advisories).

Satisfies REQ-31, REQ-69.

## Contents

- [Configuration](#configuration)
- [The pass](#the-pass)
- [The mark](#the-mark)
- [Digests](#digests)
- [Outbound requests](#outbound-requests)
- [Limits](#limits)

## Configuration

The description names the feeds the documents are listed in, the same three
files this deployment writes for its own (`design-docs/remediation.md`).
Choosing the publisher is the deliberate act: which of its hundreds of
documents a year concern a component shipped here is known only once read.

| Rule | Reason |
|---|---|
| Off unless a supplier is configured | Naming one is the switch; a second setting beside an empty list says the same thing twice |
| A supplier is configured against one product | A claim is recorded against a product, so a supplier feeding two is two rows, each read and withdrawn alone |
| Withdrawing a supplier removes nothing they said | Approvals may rest on their claims. Withdrawal stops the reading |
| A supplier's name is stored lowered and matched without regard to capitals | Two spellings are one supplier on every engine |
| A product out of use takes no supplier | It accepts no scan, and nothing lists it, so nothing could withdraw the supplier |
| A claim is recorded as the administrator who configured the supplier | Configuring admitted the publisher's judgment, the one decision anybody made; nothing chose the document |
| Only claims naming a component the product ships are recorded | A feed covers a publisher's catalog: one kernel advisory carries 95,139 claims |
| A new supplier is read from a window before it was configured, a year unless a deployment says otherwise; an older document is taken by uploading it | A distribution's feed lists every advisory it ever issued, tens of thousands of requests at somebody else's service |
| A supplier taken up again at the same address resumes where it stopped, no further back than the window; at another address it starts as a new one does | |
| Red Hat, SUSE, Cisco, Siemens and NCSC-NL are offered as presets that fill the form's name and address, and none is configured | Choosing publisher and product is the deliberate act. One the product already reads, by name or address, is not offered |

What a supplier says closes the finding inside its own product at the next
scan, and everything else is evidence and a prefill, never a decision (REQ-31).

## The pass

| Rule | Reason |
|---|---|
| One replica reaches out, settled by a lease | The politeness kept is a rate per deployment; three replicas keeping it are three times the traffic |
| The lease is taken again between suppliers and before each document, and a pass that loses it leaves the supplier due | A document is up to three requests with a timeout each, so one supplier's pass outlasts a lease sized for the interval |
| Each wake reads a bounded number of documents per supplier, and a supplier that filled its bound stays due | A busy week is no reason for a hundred requests in a minute; left to the interval, a publisher issuing more a day than one pass takes falls further behind daily. Twenty a wake every five minutes drains up to 5,760 a day (`design-docs/ingest-measurements.md` § Supplier directory volume) |
| Both shapes the format defines are read, a feed and a directory, at the labels served to everybody | The largest publisher serves only a directory, and a reader knowing one finds nothing in the other and reports success. A label that has to be arranged is refused every pass |
| How many places a description may point at is bounded | Nothing in the format bounds it, and tens of thousands of addresses outlive the lease |
| A VEX document in the same feed is left alone, and is taken by uploading it | Setting aside a publisher's whole answer is a judgment, which a timed pass never makes |
| A document is recorded even where nothing was kept | That write alone sets aside what an earlier revision said; skipped, a revision dropping the component shipped here leaves the old claim standing |
| A recording is identified by the document and what was kept of it | What the product ships decides which claims are written, so keyed on the bytes, re-uploading an advisory once a build ships a narrowed-away component writes nothing and reports success |
| Whether the supplier is still configured is asked inside the write | A pass takes minutes, and a withdrawn supplier would go on being fetched |
| A supplier that could not be read does not stop the next | One publisher down says nothing of another |
| A pass cut short by shutdown writes how far it reached and leaves the supplier due, with no failure recorded | Written with the pass's own context, the write fails as the process stops; as a finished read, the rest waits a day; as a failure, a healthy publisher reads as unreachable |
| The last attempt and the last success are both recorded | How long one has been unreachable is the gap between them |
| A supplier unread past a set time is raised with administrators, measured from the last success or from configuration, never shorter than two scan intervals | One that stopped answering looks exactly like one that published nothing. `design-docs/notifications.md` holds the condition |
| What stopped an attempt is kept bounded | It carries a publisher's address and reason phrase; unbounded, the write fails on two engines and the supplier is fetched again every wake |

## The mark

A supplier's progress is a mark: the moment of the last entry read and its
address. It moves forward only.

| Rule | Reason |
|---|---|
| The mark is a moment and the address read at it | A publisher stamps a batch with one moment, a date-only stamp a whole day; on the moment alone, a pass stopping inside such a group skips the rest for ever |
| A listing's moment is read to the microsecond, the mark's stored precision | Compared finer, the mark's own entry is read again every pass, and a batch past what a pass takes never drains |
| A stamp far in the future is not read | One entry stamped in 2099 carries the mark past everything until then, while the supplier reads as healthy |
| An entry nobody can date is left alone | It cannot be placed against the mark |
| A listing that could not be reached holds the mark | The mark is shared by every listing, and moved on the others it passes what the unreached one named |
| A listing refused the same way every pass does not stop the others | A restricted label beside a public one is ordinary |
| A listing answered "not authorized" or "forbidden" beside one that reads is stepped over and not recorded as failed; a supplier none of whose listings read fails | A directory carries no label to leave a restricted one out by, so recorded as failed the supplier never reads as answering |
| A document that cannot be read is stepped over: withdrawn and answering 404, too large, malformed, or an address the client refuses (a redirect, an excluded host, a port other than https) | Refused the same way every time, it would stop the supplier for ever |
| A publisher that cannot be reached holds the mark | Nothing behind the mark has been shown. A name resolving inside this network or into an excluded one reads as unreachable, as a filtering resolver or split view answers until corrected |
| A rate limit, a request timeout and "too early" hold the mark | Each asks to be asked again, and a content delivery network answers them for a whole pass |
| A document answered "not authorized" or "forbidden" is stepped over and the attempt recorded as failed, keeping the address and answer, with the last success unmoved | A restricted document answers so every pass; a bot filter does too, and stepping over it silently loses advisories while the supplier reads as healthy |
| A listing or document whose address cannot be made into a request is stepped over | It is refused the same way every pass |

## Digests

| Rule | Reason |
|---|---|
| A document is compared against the digest its publisher serves beside it | A cut transfer, a mirror behind or a replaced file would otherwise stand as the publisher's judgment |
| A mismatch steps over the document, which is not read again until the publisher stamps it again; mismatches are counted apart and logged per supplier | A publisher whose digests keep disagreeing otherwise reads as healthy |
| A document is read before its digest is asked for | A statement set beside the advisories is set aside whatever its digest says, and a distribution lists tens of thousands |
| The digest a feed entry names is read; otherwise the file at the document's address with the algorithm's suffix. One https address per algorithm is taken from an entry | It bounds what one entry can ask for |
| SHA-256 and SHA-512 are both read, and whichever answered is asked first after | Publishers split, each serving one kind, so the other is asked once a pass |
| A publisher serving no digest is read unchecked | The format asks one of its trusted providers only. A refusal, a page in place of a digest, a redirect, an excluded host or nothing means none is served |
| A publisher unreachable for the digest, or answering it with a rate limit, holds the mark | As for a document |
| After two documents in a row with no digest, the rest of the pass does not ask | |

## Outbound requests

| Rule | Reason |
|---|---|
| The hosts a description, its feeds and their entries name are followed | SUSE describes itself on `www.suse.com` and serves its directory from `ftp.suse.com`; a feed entry, its self link and its digest links may each name another host |
| A document named relative to its listing resolves against the listing's address | As a link on the publisher's page does |
| Only the https port, and no user in an address | The addresses come from a publisher's document, and every port on a host would make the pass a port probe |
| A host is a plain name or address | A host in another script maps to one the excluded names would have caught |
| Every request refuses an address inside this network and one an administrator excluded, checked on the resolved address at connect time (REQ-69) | A public name pointing inward gains nothing. The excluded list is the one repository fetches read |
| https only, and no redirect followed | A redirect is somebody other than the description naming where to go |
| A timeout budget of its own | The interactive one is sized for a blank page, and at ten seconds a large document could never arrive |

## Limits

| Limit | Detail |
|---|---|
| A component arriving after an advisory was read has no evidence from it | What the product ships is read as the pass runs, and the mark has passed the advisory. The publisher's next advisory brings it, or the one already issued is uploaded |
| The presets' addresses are shipped in the interface | They are the publishers' own and move when a site reorganizes. Each answered without a redirect on 2026-09-30; one that moves fails its first read and is raised as any unreadable supplier. Debian publishes no provider description, so a Debian-based product has no preset |
| A deployment that cannot reach out loses publishers' judgment | As evidence and as what it would close; an advisory is then taken by upload |
