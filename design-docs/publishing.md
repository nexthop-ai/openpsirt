# Published documents

The security documents this deployment serves to anybody, without signing in,
for the products an administrator chose: its advisories, a CSAF VEX document
per issue, and an OpenVEX document per branch or tag.

Satisfies REQ-15, REQ-31, REQ-37, REQ-39, REQ-42, REQ-43, REQ-63, REQ-69, REQ-74.

What an advisory says is in `design-docs/remediation-advisories.md`, and the
VEX document of one build in `design-docs/remediation-vex.md`; the subject
anybody at all reads as is in `design-docs/access.md`; the routes beside the
API are in `design-docs/api.md`; another deployment reading these documents is
in `design-docs/upstream.md`.

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
document is about disclosed work in that product (REQ-63, REQ-37).

| Switch | Held | Default | Effect |
|---|---|---|---|
| The deployment publishes | Deployment configuration | Off | Mounts nothing new: off, every path answers as one nothing is published at, and the pass does not start |
| A product publishes | The product, set by an administrator, recorded in the trail | Off | On, the next pass writes its documents and they are served from then. Off, they are withdrawn in the same act and stop being served at once. On again, nothing is served until the next pass, and a document stating what it stated before returns as the revision it was |
| The statuses published | An administrator's setting | Every status somebody decided | Limited, only not affected and fixed are published, and a document left with none is withdrawn |
| The rate one client may ask at | Deployment configuration | 600 a minute | Past it, 429 with when to ask again |
| The signing key | A secret in deployment configuration | None | With one, every document carries a detached OpenPGP signature and the provider claims the trusted provider role |

| Rule | Reason |
|---|---|
| Publishing requires the deployment's own `https` address, a publisher's name and a namespace | Every address a document states is built from it, and every document names the publisher |
| A deployment also writing the static directory keeps writing it (`design-docs/remediation-directory.md`) | An advisory then states the address this deployment serves it at, and the directory is a copy |
| A key that does not read, is locked with no passphrase or the wrong one, or cannot sign now is refused at startup, naming the setting | |
| A publishing setting set while the deployment does not publish is refused at startup | Nothing would read it |

## The served surface

Two folders below the deployment's address. The CSAF folder is the standard's
provider in both its shapes at once: a directory with a list and a list of
changes, and a ROLIE feed naming the same documents.

| Path | Serves |
|---|---|
| `/.well-known/csaf/provider-metadata.json` | The provider description: the publisher, one distribution naming the directory and the feed, the role, and the public key where there is one |
| `/.well-known/csaf/white/index.txt` | Every CSAF document's path below the directory, in path order |
| `/.well-known/csaf/white/changes.csv` | Every CSAF document and when its revision was released, newest first |
| `/.well-known/csaf/white/csaf-feed-tlp-white.json` | The same documents as one ROLIE feed, each entry naming both digests and, where there is one, the signature |
| `/.well-known/csaf/white/<year>/<name>.json` | One advisory or one CSAF VEX document. The year is the document's first release, the name its tracking identifier under the standard's filename rule |
| `/.well-known/csaf/openpgp/<fingerprint>.asc` | The public key, where there is one |
| `/openvex/index.txt` | Every OpenVEX document's path below the folder |
| `/openvex/<product>/<branch or tag>.json` | One OpenVEX document; each name is one escaped path segment |
| Any document's path with `.sha256`, `.sha512` or `.asc` | Its digests and its signature |

| Rule | Reason |
|---|---|
| No credential is looked at | A request carrying a session, a key or a proxy's header is answered as one carrying nothing, and no subject is resolved for it |
| GET and HEAD only | Any other method answers 405, naming the two, before anything is read |
| One answer for nothing | Publishing off, no product publishing, a product that stopped, a document withdrawn or never written, and one written under wider statuses than are published now all answer the same 404, so nothing tells a reader what exists |
| A path below `/.well-known/csaf/white/` naming no document, and an `index.txt` with nothing to list, answer that 404 | |
| The description and the feed are not served where there is no CSAF document | Each states when the newest was released |
| Nothing names a row | Paths, product identifiers and tracking identifiers are built from names, never from an identifier this deployment holds |
| Every answer carries an entity tag; a document and the files beside it also carry the moment it last moved; a request repeating either answers 304 | A list carries no date, because one that shrank by a withdrawal or a product turned off is newer than its newest document |
| `Cache-Control: public, no-cache` | A reader asks every time and fetches only what changed |
| A signature is tagged by the document it signs | Its own bytes carry a random salt and differ every time, so a reader holding the signature of an unchanged document is told so without the key being used again |
| A list is read from every document's name and dates; a VEX document is read alone | Advisories' issued bytes are read only for the CSAF lists and for a path in their folder holding no VEX document, so a VEX document, the files beside one, an OpenVEX path and a key read none. A reader taking the provider whole asks for each document and its files, and none of those lists the rest |
| A VEX document is looked for before an advisory | Where an advisory's tracking identifier folds to a VEX document's path, the VEX document is served |
| The lists state dates from the documents | The feed and the description state the newest document's release, never the clock, so an unchanged provider answers the same bytes |
| A client is the address its connection came from, or the one a trusted proxy forwarded for | The proxies are the trusted sources sign-in reads, so one list. From one of them, the client is the first address from the right of `X-Forwarded-For` that is not itself trusted, since each proxy appends what it received from and everything left of that hop is the client's own writing. From anywhere else the header is not read |
| The allowance is per replica, held in each process | The request it limits writes nothing. Each process holds a bucket per client, refilling at the configured rate and holding a minute of it |
| Past ten thousand buckets, the clients whose bucket is full again are forgotten, then the half holding the most of theirs | A flood of addresses never hands a held-back client its allowance |
| An IPv6 client is its /64 | One host is handed a /64 and may rotate through it |

## Advisories served

An advisory is served from the bytes that went out, by the rule the static
directory reads them by: the newest revision of each advisory whose label lets
it travel (`design-docs/remediation-directory.md` § The provider directory).

| Rule | Reason |
|---|---|
| Read as anybody at all | The read of what went out is narrowed as every reader's is: every issue the advisory covers, now and when it went out, at a disclosed occurrence in a product the reader reads. Anybody at all reads only publishing products, so an advisory covering one product that does not publish is not served |
| A revision labeled RED is never served, whatever came after it | It is about a flaw nobody outside has been told about |
| An advisory generated where the deployment publishes, and every product it covers publishes and is in use, states this surface's address; otherwise the static directory's where one is written, or none | This surface would answer that address with nothing. Issued bytes never change, so an advisory issued before its products published keeps the address it went out with |

## Statements and statuses

What is stated about one build is what somebody decided: the document of one
build (`design-docs/remediation-vex.md` § The VEX document), with a decision
that an issue applies stated outright. A component nobody judged gets no
statement, so a scanner reports it as it would without these documents.

| Status | Stated where | Carries |
|---|---|---|
| Not affected | Every open occurrence of the component stands under an approved, live decision that it does not apply or the match was wrong | The decision's reason, and what stops it where the decision named it |
| Fixed | The same, for a decision that the fix is already here, and where a patch the build declares closed it | Nothing more |
| Affected | Every open occurrence stands under a decision in force that the issue applies, will be fixed, or will not be | What a holder can do where the decision named it; otherwise that no fix is planned, where every decision says it will not be fixed, or that none is available yet |

| Rule | Reason |
|---|---|
| An issue open and undecided, a deferral, and a decision waiting on a second person state nothing | A document about an issue with no statement left is not served |
| Under investigation is never stated | No decision records that somebody is looking: a deferral says when somebody looks again, and a waiting decision is one person's opinion |
| Disclosed findings only, read at the public visibility in a product anybody at all reads | A flaw of ours nobody disclosed is in no statement, document, list or count (REQ-37) |
| Where a flaw of ours recorded about an issue is out of anybody's reach, undisclosed or in a product that does not publish, the issue's other names and its description are left out | The flaw wrote its minted name and its summary onto the issue row every product shares |
| A decision in force states affected, with no second person needed | Saying an issue applies hides nothing; the statuses that hide risk come from approved decisions only |
| A supplier's statement about its own product is not passed on | Passing on a supplier's word under this deployment's name is the document carrying suppliers' statements, which somebody chooses |
| Each build is read at what it last scanned: every branch, tag and variant in use, once scanned | A build out of support is still published, because a reader still runs it (REQ-15) |
| A build stating more than one document of a build carries is refused | That product's documents are not worked out on the pass, stay as they were, and the pass logs it |
| The statuses published apply to both documents | Limited, a statement of another status is left out before a document is assembled, and a document left with none is withdrawn |

## Statement scope

A statement holds for anybody shipping the component at that version, or for
this product's own build of it. A fork shares most of the product, and the
scope decides whether a fork may take a statement as it stands (REQ-31).

| Reason | Holds for |
|---|---|
| The match was wrong | Anybody shipping the component |
| The component or the vulnerable code is not present | Anybody shipping the component |
| The code ships and is never called | This build: another build calls what it calls |
| Nothing an attacker controls reaches it, or something stops it | This build |
| Already fixed here, a patch the build declares, will not be fixed, affected | This build |

| Rule | Reason |
|---|---|
| A decision may state its scope when proposed, as part of what the second person agrees to | Changing it is proposing again, as for any part of a decision (`design-docs/triage.md`) |
| A stated scope wins either way | Narrowed, a statement whose reason holds for anybody is stated about the build; widened, one whose reason is the build's is stated about the component |
| A component is stated alone only where every build agrees: within one document, every statement about it holds for anybody and says the same, or each is stated about its own build | One build calling it not affected while another has the issue open is a contradiction, and a reader is told the cautious half |
| A statement about one occurrence is always stated beneath the component pulling it in, whatever the decision's scope | The other occurrences of the component disagree with it, so its scope is not published |

## The CSAF VEX document

One document per issue per product, across every branch, tag and variant.

| Element | Filled by |
|---|---|
| Category and version | `csaf_vex`, CSAF 2.0 |
| Tracking identifier | `VEX-<product>-<issue>`, fixed while the issue keeps its name |
| Title | The issue and the product's display name |
| Product tree | The publisher, the product, and one leaf per build a statement names, with the package identifier the build's inventory gave itself; every component and every component pulling one in, by package identifier; a relationship naming each component as part of a build or beneath the component pulling it in |
| Status | A component holding for anybody by its own product identifier; anything else by the relationship. A product under two statuses keeps the more cautious |
| Flags | The reason for every product not affected, one flag per reason |
| Threats | What stops the flaw, for a product not affected, where somebody named it |
| Remediations | For an affected product, that no fix is planned or none is available, and what to do where the decision named it |
| Identifiers | The CVE where the issue has one among its names, and every other name by its prefix |
| Notes | What the issue is, in the reporter's words, or its name where nobody said |
| References | The address the document is served at |
| Distribution | TLP WHITE, the standard's word for what TLP 2.0 calls CLEAR |
| Tracking status | Final: every statement stands on a decision agreed or a fact a scan recorded |

| Rule | Reason |
|---|---|
| A value that is not a package identifier is not stated as one | The schema refuses it, and one refused helper fails the whole document |
| A product identifier is built from names: `<product>:<branch>:<variant>` for a build, the package identifier for a component, the two joined by `\|` for a component as part of either | |
| Every list is ordered here, never by the engine | Two documents from the same state are the same bytes |

## The OpenVEX document

One document per branch or tag, across its variants, at what each last
scanned: what a scanner holding one build asks of it.

| Rule | Reason |
|---|---|
| A statement holding for anybody names the component alone as the product | A reader applies it wherever the component ships |
| A statement holding for this build names the build as the product, with the component beneath | The build is named by the package identifier its inventory gave itself, or by its names where it gave none |
| A statement about one occurrence names the component pulling it in, with this one beneath | As the document of one build does |
| One statement however many variants say it, stated from when it was first true | |
| Its identifier is the address it is served at | A reader keeps documents by it |
| `version`, `timestamp` and `last_updated` are the revision held, the first revision's release, and this one's | |
| A branch or tag with nothing stated has no document | |

## Revisions

A revision is a fact about a moment, so it is recorded and a request reads the
record.

| Rule | Reason |
|---|---|
| A new revision only where what it states moved | A digest over the address it states, its publisher, the title, the product tree and the statements is kept with the revision; one worked out again and equal writes nothing. Moving the deployment's address or publisher revises every document |
| Turning publishing on for a product, or renaming one that publishes, is refused where another product that publishes or has published folds alike, naming it | The standard's filename rule folds `edge.os` and `edge os` alike, so their documents about one issue would share a path. A withdrawn document keeps its path, so a product that has published counts after it stops |
| The pass refuses a path another product holds, naming the first product and saying to turn publishing off for the second, and carries on with the rest of that product's documents and withdrawals | Reached only by two products folded alike turned on at once |
| A rename is refused once a document that may name the part was served, withdrawn ones included | A reader holds each document by an address and identifier built from the names |
| What counts as naming a part | A product: any document about it. A release: its OpenVEX document, and once it has a scanned build every CSAF VEX document of its product, since which builds a revision named is in the bytes alone. A variant: every document of its product once it has a scanned build. A release or variant with no scanned build may be renamed |
| The next revision is one past the last, with every earlier revision in its history, and its first release never moves | Neither does its year folder |
| A revision is written in a transaction that reads what it replaces | Of two replicas writing one document, the second matches nothing on the version it read and goes again |
| A document the product has nothing to say about is withdrawn: kept, not served, and continued by its next revision if the issue returns | Stating again what it stated when withdrawn, it is served as that revision |
| A document written under every status stops being served once the statuses narrow, before anything is written again | The next pass writes it under the narrower setting, or withdraws it |
| Only the held revision's bytes are kept | The history inside them names every revision before it |

## Digests and signatures

| File | Holds |
|---|---|
| `.sha256`, `.sha512` | The digest of the bytes served, then the document's filename after two spaces: the standard's form, which ordinary command-line checkers read |
| `.asc` | An armored detached OpenPGP signature over the bytes served, made with the configured key and dated when the document was released, never before the key became valid |

| Rule | Reason |
|---|---|
| A signature is made per request | Signing at the pass and keeping it would store a copy of something worked out from the bytes and the key |
| Each signature carries a random salt, so two over one revision differ in their bytes and each verifies | |
| A signature is dated no earlier than the newest self-signature vouching for the key | Extending a key's expiry or adding a name to it leaves every older document signable |
| Digests are worked out on request from the bytes held | |

## The publishing pass

Every five minutes, on the replica holding its lease, the pass works out every
publishing product's documents as anybody at all would read them, and writes
what moved.

| Rule | Reason |
|---|---|
| Read as anybody at all, through the subject the surface reads through | A document cannot hold anything a reader may not be handed |
| One replica writes, under a lease as the deployment's other passes are | The conditional write keeps two from writing one revision twice where a lease is lost mid-pass |
| A product that cannot be worked out does not stop the next | Its documents stay as they were, and the pass logs it |
| What has not moved is stepped over on a read of the digests; what has is decided again inside its own transaction | |
| The number of documents grows with decisions, never with what a scanner reports | A document is an issue somebody decided about |
| A pass reads every build's decisions whatever is published | That is most of its cost (`design-docs/publishing-measurements.md`) |

## Not built

| Not built | What exists |
|---|---|
| A ROLIE service document and a category document | Both optional. The provider description lists the one feed, and a checker reports each absence as a warning |
| Directory listings | A path naming a folder answers 404. The index and the list of changes name every document |
| A score in a VEX document | The CSAF VEX document carries none, and the validator's optional test asking for one on an affected product warns |

## Limits

| Rule | Reason |
|---|---|
| A document is as current as the last pass, up to five minutes behind a decision agreed or a scan landing | Turning a product off and narrowing the statuses take effect at once, because what may be served is asked on every request |
| Every document of a product is worked out on every pass | 3.3 s on a full-size image, nearly all of it reading what stands (`design-docs/publishing-measurements.md`); a record of what moved would be a second copy of what the findings say (REQ-74) |
