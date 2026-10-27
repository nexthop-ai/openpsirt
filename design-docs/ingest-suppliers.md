# Supplier directories

A supplier's CSAF advisories read on the scan schedule from the provider
description an administrator configured, landing as an uploaded advisory does
(`design-docs/ingest-claims.md` § Supplier advisories).

Satisfies REQ-31, REQ-69.

## Contents

- [Configuration](#configuration)
- [The pass](#the-pass)
- [The mark](#the-mark)
- [Digests](#digests)
- [Outbound requests](#outbound-requests)
- [Limits](#limits)

## Configuration

The description names the feeds, the three files this deployment writes for its
own (`design-docs/remediation.md`). Choosing the publisher is the deliberate act.

| Rule | Reason |
|---|---|
| Off unless a supplier is configured | Naming one is the switch |
| A supplier is configured against one product | Claims are recorded against a product |
| Withdrawing a supplier stops the reading and removes nothing | Approvals may rest on their claims |
| A supplier's name is stored lowered and matched without regard to capitals | |
| A product out of use takes no supplier | Nothing lists it to withdraw one |
| A claim is recorded as the administrator who configured the supplier | That configuration is the one decision made |
| Only claims naming a component the product ships are recorded | A feed covers a whole catalog |
| A new supplier is read from a window, a year unless set otherwise; older documents are uploaded | A distribution's feed is tens of thousands of documents |
| Taken up again at the same address, a supplier resumes where it stopped, no further back than the window; at another address it starts afresh | |
| Red Hat, SUSE, Cisco, Siemens and NCSC-NL are presets filling name and address, none configured; one the product reads by name or address is not offered | |

A supplier's statement about its own product closes the finding inside it at
the next scan; anything else is evidence and a prefill, never a decision
(REQ-31).

## The pass

| Rule | Reason |
|---|---|
| One replica reaches out, under a lease | Politeness is a rate per deployment |
| The lease is retaken between suppliers and before each document; losing it leaves the supplier due | A document is up to three requests with timeouts |
| Each wake reads twenty documents per supplier every five minutes, and a supplier filling that stays due (`design-docs/ingest-measurements.md` § Supplier directory volume) | Left to the interval, a busy publisher falls behind daily |
| Feeds and directories are both read, at labels served to everybody | The largest publisher serves only a directory; a label that has to be arranged is refused by the publisher on every pass |
| The places a description points at are bounded | Tens of thousands outlive the lease |
| A VEX document in the feed is left alone, for upload | Setting aside a whole answer is a judgment |
| A document is recorded even where nothing was kept | That write sets aside an earlier revision's claims |
| A recording is identified by the document and what was kept of it | Keyed on bytes, re-uploading a narrowed advisory writes nothing |
| Whether the supplier is still configured is asked inside the write | A withdrawn supplier stops mid-pass |
| One supplier unread does not stop the next | |
| A pass cut by shutdown writes how far it reached, leaves the supplier due, and records no failure | |
| Last attempt and last success are both recorded | Their gap is how long it has been unreachable |
| A supplier unread past a set time, never under two scan intervals, from last success or configuration, is raised with administrators (`design-docs/notifications.md`) | Silence looks like publishing nothing |
| What stopped an attempt is kept bounded | Unbounded, two engines refuse the write and the supplier is fetched every wake |

## The mark

A supplier's progress is the moment of the last entry read and its address,
moving forward only.

| Rule | Reason |
|---|---|
| The mark is a moment and an address | A batch, or a whole day, shares one stamp |
| A listing's moment is read to the microsecond, the mark's precision | Finer, the mark's own entry repeats every pass |
| A stamp far in the future, and an undatable entry, are not read | 2099 would carry the mark past everything |
| An unreachable listing holds the mark | The mark is shared by every listing |
| A listing refused the same way each pass does not stop the others | |
| A listing answered "not authorized" or "forbidden" beside one that reads is stepped over, not failed; a supplier with no readable listing fails | Directories carry no label to skip a restricted one by |
| An unreadable document is stepped over: 404, too large, malformed, or an address the client refuses (redirect, excluded host, non-https port) | It would stop the supplier for ever |
| An unreachable publisher holds the mark, including a name resolving inward or into an excluded network | |
| A rate limit, request timeout or "too early" holds the mark | Each asks to be asked again |
| A document answered "not authorized" or "forbidden" is stepped over and recorded failed with address and answer; last success does not move | A bot filter would otherwise lose advisories silently |
| An address that cannot be made a request is stepped over | |

## Digests

| Rule | Reason |
|---|---|
| A document is compared against the digest its publisher serves | A cut transfer or stale mirror would stand as judgment |
| A mismatch steps over the document until restamped, counted apart and logged per supplier | |
| A document is read before its digest is asked | A statement set beside it is discarded regardless |
| The feed entry's digest is read, else the file at the document's address with the algorithm's suffix; one https address per algorithm per entry | |
| SHA-256 and SHA-512 are both read; whichever answered is asked first after | |
| A publisher serving no digest is read unchecked: refusal, page, redirect, excluded host or nothing means none | The format asks it of trusted providers only |
| An unreachable or rate-limited digest holds the mark | |
| After two documents in a row without a digest, the pass stops asking | |

## Outbound requests

| Rule | Reason |
|---|---|
| Hosts named by the description, its feeds and entries are followed | SUSE describes itself on `www.suse.com` and serves `ftp.suse.com` |
| A relative document resolves against its listing | |
| Only the https port, and no user in an address | Otherwise a port probe |
| A host is a plain name or address | Another script maps past the excluded names |
| Addresses inside this network or excluded by an administrator are refused at connect time on the resolved address (REQ-69); the excluded list is the one repository fetches read | |
| https only, no redirect followed | |
| A timeout budget of its own | The interactive ten seconds is too short for a large document |

## Limits

| Limit | Detail |
|---|---|
| A component arriving after an advisory was read gets no evidence from it | The mark has passed it; the next advisory brings it, or the old one is uploaded |
| Preset addresses ship in the interface | Each answered without redirect on 2026-09-30; one that moves fails like any supplier. Debian publishes no provider description |
| A deployment that cannot reach out loses publishers' judgment | Advisories are then uploaded |
