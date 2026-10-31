# Published documents

The security documents this deployment serves to anybody, without signing in,
for the products an administrator chose: its advisories, a CSAF VEX document
per issue, and an OpenVEX document per branch or tag.

Satisfies REQ-15, REQ-31, REQ-37, REQ-39, REQ-42, REQ-43, REQ-63, REQ-69, REQ-74.

What an advisory says is in `design-docs/remediation-advisories.md`, the VEX
document of one build in `design-docs/remediation-vex.md`, the subject anybody
at all reads as in `design-docs/access.md`, the routes beside the API in
`design-docs/api.md`, and another deployment reading these in
`design-docs/upstream.md`.

## Contents

- [Switches](#switches)
- [The served surface](#the-served-surface)
- [Advisories served](#advisories-served)
- [Statements and statuses](#statements-and-statuses)
- [Statement scope](#statement-scope)
- [The CSAF VEX document](#the-csaf-vex-document)
- [The OpenVEX document](#the-openvex-document)
- [Revisions](#revisions)
- [Digests and signatures](#digests-and-signatures)
- [The publishing pass](#the-publishing-pass)
- [Not built](#not-built)
- [Limits](#limits)

## Switches

Nothing is served until the deployment publishes, a product publishes, and the
document is about disclosed work in it (REQ-63, REQ-37).

| Switch | Held | Default | Effect |
|---|---|---|---|
| The deployment publishes | Deployment configuration | Off | Off, every path answers as one nothing is published at, and the pass does not start |
| A product publishes | The product, set by an administrator, in the trail | Off | On, the next pass writes its documents. Off, they are withdrawn at once. On again, nothing is served until the next pass, and an unchanged document returns as the revision it was |
| The statuses published | An administrator's setting | Every status somebody decided | Limited, only not affected and fixed; a document left with none is withdrawn |
| The rate one client may ask at | Deployment configuration | 600 a minute | Past it, 429 with when to ask again |
| The signing key | A configured secret | None | Every document carries a detached OpenPGP signature, and the provider claims the trusted provider role |

| Rule | Reason |
|---|---|
| Publishing requires the deployment's `https` address, a publisher name and a namespace | Every stated address is built from it, and every document names the publisher |
| A deployment also writing the provider directory keeps writing it (`design-docs/remediation-directory.md`) | Advisories then state this deployment's address |
| A key that does not read, is locked with a missing or wrong passphrase, or cannot sign now is refused at startup, naming the setting | |
| A publishing setting set while the deployment does not publish is refused at startup | Nothing would read it |

## The served surface

| Path | Serves |
|---|---|
| `/.well-known/csaf/provider-metadata.json` | The provider description: publisher, one distribution naming the directory and the feed, the role, the public key where there is one |
| `/.well-known/csaf/white/index.txt` | Every CSAF document's path, in path order |
| `/.well-known/csaf/white/changes.csv` | Every CSAF document and its revision's release, newest first |
| `/.well-known/csaf/white/csaf-feed-tlp-white.json` | The same documents as one ROLIE feed, each entry naming both digests and any signature |
| `/.well-known/csaf/white/<year>/<name>.json` | One advisory or CSAF VEX document: the year its first release, the name its tracking identifier under the standard's filename rule |
| `/.well-known/csaf/openpgp/<fingerprint>.asc` | The public key, where there is one |
| `/openvex/index.txt` | Every OpenVEX document's path |
| `/openvex/<product>/<branch or tag>.json` | One OpenVEX document; each name one escaped segment |
| A document's path with `.sha256`, `.sha512` or `.asc` | Its digests, and its signature |

| Rule | Reason |
|---|---|
| No credential is looked at, and no subject resolved | |
| GET and HEAD only; any other method answers 405 naming them, before anything is read | |
| One 404 for nothing: publishing off, no product publishing, a product that stopped, a document withdrawn, never written, or written under wider statuses than now, a path naming no document, an `index.txt` with nothing to list | Nothing tells a reader what exists |
| The description and the feed are not served where there is no CSAF document | Each states the newest release |
| Nothing names a row: paths and identifiers are built from names | |
| Every answer carries an entity tag; a document and its files also the moment it last moved; a request repeating either answers 304 | A list carries no date, since one that shrank is newer than its newest document |
| `Cache-Control: public, no-cache` | A reader asks every time and fetches only what changed |
| A signature is tagged by the document it signs | Its bytes carry a random salt, so an unchanged document's signature is confirmed without signing again |
| A list reads every document's name and dates; a VEX document is read alone. Advisories' bytes are read only for the CSAF lists and for a CSAF path holding no VEX document | A whole-provider reader asks for each document and its files, and none of those lists the rest |
| A VEX document is looked for before an advisory | Where an advisory's tracking identifier folds to a VEX document's path, the VEX document is served |
| The feed and the description state the newest document's release, never the clock | An unchanged provider answers the same bytes |
| A client is its connection's address, or from a trusted proxy the first `X-Forwarded-For` address from the right that is not itself trusted; from anywhere else the header is not read | The trusted proxies are sign-in's trusted sources. Each proxy appends what it received from, so everything left of that hop is the client's writing |
| The allowance is a bucket per client in each process, refilling at the configured rate and holding a minute | The request it limits writes nothing |
| Past ten thousand buckets, those full again are forgotten, then the half holding the most | A flood of addresses never restores a held-back client's allowance |
| An IPv6 client is its /64 | One host may rotate through its /64 |

## Advisories served

An advisory is served from the bytes that went out, by the rule the provider
directory reads them by: the newest revision whose label lets it travel
(`design-docs/remediation-directory.md` § Directory rules).

| Rule | Reason |
|---|---|
| Read as anybody at all: every issue covered, now and when it went out, at a disclosed occurrence in a product the reader reads | Anybody at all reads only publishing products, so an advisory covering one that does not is not served |
| A revision labeled RED is never served, whatever followed it | |
| An advisory generated where the deployment and every product it covers publish, and are in use, states this surface's address; otherwise the directory's where one is written, else none | Issued bytes never change, so earlier advisories keep the address they went out with |

## Statements and statuses

What is stated about one build is what somebody decided, as in the document of
one build (`design-docs/remediation-vex.md` § Statements), with a decision that
an issue applies and stays (affected, upgrade-needed, patch-needed, wont-fix)
stated outright. A component nobody judged gets no statement.

| Status | Stated where | Carries |
|---|---|---|
| Not affected | Every open occurrence of the component stands under an approved, live decision that it does not apply or the match was wrong | The reason, and what stops it where named |
| Fixed | The same, for a decision that the fix is here, or a declared patch closed it | Nothing more |
| Affected | Every open occurrence stands under a decision in force that it applies, will be fixed, or will not be | What a holder can do where named; else that no fix is planned, where every decision says will not fix, or none is available yet |

| Rule | Reason |
|---|---|
| An issue open and undecided, a deferral, and a decision awaiting its second person state nothing; a document left with no statement is not served | |
| Under investigation is never stated | No decision records somebody looking |
| Disclosed findings only, in a product anybody at all reads | An undisclosed flaw of ours is in no statement, document, list or count (REQ-37) |
| Where a flaw of ours about an issue is out of anybody's reach, the issue's other names and description are left out | The flaw wrote its minted name and summary onto the shared issue row |
| A decision in force states affected without a second person | Saying an issue applies hides nothing |
| A supplier's statement about its own product is not passed on | That is the suppliers kind of the build document, chosen on purpose |
| Each branch, tag and variant in use is read at its last scan, once scanned; one out of support is still published (REQ-15) | A reader still runs it |
| A build stating more than one build document carries is refused; its product's documents stay as they were, and the pass logs it | |
| The statuses published apply to both documents, before assembly | |

## Statement scope

A statement holds for anybody shipping the component at that version, or for
this product's build alone. The scope decides whether a fork may take it
(REQ-31).

| Reason | Holds for |
|---|---|
| The match was wrong | Anybody shipping the component |
| The component or vulnerable code is not present | Anybody shipping the component |
| The code ships and is never called | This build |
| Nothing an attacker controls reaches it, or something stops it | This build |
| Already fixed here, a declared patch, will not be fixed, affected | This build |

| Rule | Reason |
|---|---|
| A decision may state its scope when proposed, as part of what the second person agrees to; changing it is proposing again (`design-docs/triage.md`) | |
| A stated scope wins either way | |
| A component is stated alone only where, within one document, every statement about it holds for anybody and says the same; otherwise each is stated about its build | A contradiction tells a reader the cautious half |
| A statement about one occurrence is stated beneath the component pulling it in, whatever its scope, which is not published | Other occurrences of the component disagree |

## The CSAF VEX document

One document per issue per product, across every branch, tag and variant.

| Element | Filled by |
|---|---|
| Category and version | `csaf_vex`, CSAF 2.0 |
| Tracking identifier | `VEX-<product>-<issue>`, fixed while the issue keeps its name |
| Title | The issue and the product's display name |
| Product tree | The publisher, the product, a leaf per named build with the package identifier its inventory gave itself; every component and every component pulling one in, by package identifier; relationships placing each component in a build or beneath its consumer |
| Status | A component holding for anybody by its own identifier, anything else by the relationship; a product under two statuses keeps the more cautious |
| Flags | One per reason for products not affected |
| Threats | What stops the flaw, where named, for a product not affected |
| Remediations | For an affected product, no fix planned or none available, and what to do where named |
| Identifiers | The CVE where the issue has one, and every other name by its prefix |
| Notes | What the issue is, in the reporter's words, else its name |
| References | The document's served address |
| Distribution | TLP WHITE, the standard's word for TLP 2.0's CLEAR |
| Tracking status | Final: every statement stands on an agreed decision or a recorded fact |

| Rule | Reason |
|---|---|
| A value that is not a package identifier is not stated as one | The schema refuses it, failing the document |
| A product identifier is `<product>:<branch>:<variant>` for a build, the package identifier for a component, joined by `\|` for a component within either | |
| Every list is ordered here | The same state gives the same bytes |

## The OpenVEX document

One document per branch or tag, across its variants, at each one's last scan.

| Rule | Reason |
|---|---|
| A statement holding for anybody names the component alone as the product | |
| A statement holding for this build names the build, by its inventory's package identifier or else its names, with the component beneath | |
| A statement about one occurrence names its consumer, with it beneath | |
| One statement however many variants say it, from when it was first true | |
| Its identifier is its served address | A reader keeps documents by it |
| `version`, `timestamp` and `last_updated` are the revision, the first revision's release, and this one's | |
| A branch or tag with nothing stated has no document | |

## Revisions

A revision is a fact about a moment: recorded, and read by requests.

| Rule | Reason |
|---|---|
| A revision is written only where its digest moved: the stated address, the publisher, the title, the product tree and the statements | Moving the deployment's address or publisher revises everything |
| Turning publishing on for a product, or renaming a publishing one, is refused, naming the other, where a product that publishes or has published folds alike | The filename rule folds `edge.os` and `edge os` to one path; a withdrawn document keeps its path |
| The pass refuses a path another product holds, naming the first and saying to turn the second off, and carries on with the rest | Reached only by turning both on at once |
| A rename is refused once a document that may name the part was served, withdrawn ones included | Readers hold documents by names |
| Naming a part: a product, any document about it; a release, its OpenVEX document and, once it has a scanned build, every CSAF VEX document of its product; a variant, every document of its product once it has a scanned build | Which builds a revision named is in its bytes alone. Unscanned, a release or variant may be renamed |
| The next revision is one past the last, with every earlier one in its history; its first release, and so its year folder, never moves | |
| A revision is written in a transaction reading what it replaces | Of two replicas, the second matches nothing and goes again |
| A document with nothing left to say is withdrawn, kept and not served; it continues as its next revision if the issue returns, or as the revision it was if it states the same again | |
| A document written under every status stops being served as soon as the statuses narrow; the next pass rewrites or withdraws it | |
| Only the held revision's bytes are kept | Its history names the rest |

## Digests and signatures

| File | Holds |
|---|---|
| `.sha256`, `.sha512` | The digest of the served bytes, two spaces and the filename, as checkers read it |
| `.asc` | An armored detached OpenPGP signature over the served bytes, dated at the document's release, never before the key became valid |

| Rule | Reason |
|---|---|
| A signature is made per request | Kept, it would store what the bytes and key give |
| Each signature carries a random salt, and each verifies | |
| A signature is dated no earlier than the key's newest self-signature | Extending expiry or adding a name leaves older documents signable |
| Digests are worked out on request | |

## The publishing pass

Every five minutes, on the replica holding its lease, the pass works out every
publishing product's documents as anybody at all would read them, and writes
what moved.

| Rule | Reason |
|---|---|
| Read through the subject the surface reads through | A document holds nothing a reader may not be handed |
| One replica writes, under a lease | The conditional write stops a double revision when a lease is lost mid-pass |
| A product that cannot be worked out is logged and skipped; its documents stay as they were | |
| What has not moved is stepped over on a digest read; what has is decided again in its own transaction | |
| Documents grow with decisions, never with scanner output | A document is an issue somebody decided |
| A pass reads every build's decisions whatever is published, most of its cost (`design-docs/publishing-measurements.md`) | |

## Not built

| Not built | What exists |
|---|---|
| A ROLIE service document and a category document | Both optional; the description lists the one feed, and a checker warns on each absence |
| Directory listings | A folder path answers 404; the index and the changes list name every document |
| A score in a VEX document | None is carried, and the validator's optional test for one on an affected product warns |
| A key held in a KMS or HSM | The key is an armored private key in a configured secret |
| Key rotation | One key is configured and served. Replaced, every document is signed with the new key from the next request, and the old key's path answers as nothing published |

## Limits

| Rule | Reason |
|---|---|
| A document is up to five minutes behind a decision agreed or a scan landing | Turning a product off and narrowing the statuses act at once, being asked on every request |
| Every document of a product is worked out every pass | 3.3 s on a full-size image (`design-docs/publishing-measurements.md`); a record of what moved would copy the findings (REQ-74) |
