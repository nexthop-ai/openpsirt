# Published documents

The security documents this deployment serves to anybody, without signing in,
for the products an administrator chose: its advisories, a CSAF VEX document
per issue, and an OpenVEX document per branch or tag.

Satisfies REQ-31, REQ-37, REQ-39, REQ-42, REQ-43, REQ-63, REQ-69, REQ-74.

Neighboring pieces: what an advisory and the VEX document of one build say is
in `DESIGN-remediation.md`; the subject anybody at all reads as is in
`DESIGN-access.md`; the routes beside the API are in `DESIGN-api.md`; how
another deployment reads these documents is in `DESIGN-ingest.md`.

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
- [Measurements](#measurements)
- [Not built](#not-built)
- [Limits](#limits)

## Switches

Nothing is served until three things are true: the deployment publishes, a
product publishes, and the document is about disclosed work in that product
(REQ-63, REQ-37).

| Switch | Held | Default | What it does |
|---|---|---|---|
| The deployment publishes | Deployment configuration | Off | Mounts nothing new: the paths answer either way. Off, every one of them answers as a path nothing is published at, and the pass that writes documents does not start |
| A product publishes | The product, set by an administrator and recorded in the trail | Off | Its documents are written by the next pass and served from then on. Turned off, they are withdrawn in the same act and stop being served at once; turned on again, nothing is served until the next pass, and a document stating what it stated before comes back as the revision it was |
| The statuses published | A setting an administrator changes | Every status somebody decided | Limited, only statements that something is not affected or is fixed are published, and a document left with none is withdrawn |
| The rate one client may ask at | Deployment configuration | 600 a minute | Requests past it are answered 429 with when to ask again |
| The signing key | A secret in deployment configuration | None | With one, every document carries a detached OpenPGP signature and the provider claims the trusted provider role |

The deployment's own address is required to publish, over https, with a
publisher's name and namespace: every address a document states is built from
it, and every document names the publisher. A deployment that also writes the
static directory of `DESIGN-remediation.md` keeps writing it; an advisory then
states the address this deployment serves it at, and the directory is a copy.

A key that does not read, is locked with no passphrase or the wrong one, or
cannot sign now is refused at startup, naming the setting. A publishing setting
set while the deployment does not publish is refused the same way, because
nothing would read it.

## The served surface

Two folders below the deployment's address. The CSAF folder is the standard's
provider, in both of its shapes at once: a directory with a list and a list of
changes, and a ROLIE feed naming the same documents.

| Path | Serves |
|---|---|
| `/.well-known/csaf/provider-metadata.json` | The provider description: the publisher, one distribution naming the directory and the feed, the role, and the public key where there is one |
| `/.well-known/csaf/white/index.txt` | Every CSAF document's path below the directory, in order of path |
| `/.well-known/csaf/white/changes.csv` | Every CSAF document and when its revision was released, newest first |
| `/.well-known/csaf/white/csaf-feed-tlp-white.json` | The same documents as one ROLIE feed, each entry naming both digests and, where there is one, the signature |
| `/.well-known/csaf/white/<year>/<name>.json` | One advisory or one CSAF VEX document. The year is the document's first release, and the name its tracking identifier under the standard's filename rule |
| `/.well-known/csaf/openpgp/<fingerprint>.asc` | The public key, where there is one |
| `/openvex/index.txt` | Every OpenVEX document's path below the folder |
| `/openvex/<product>/<branch or tag>.json` | One OpenVEX document. Each name is one escaped path segment |
| Any document's path with `.sha256`, `.sha512` or `.asc` | That document's digests, and its signature |

| Rule | |
|---|---|
| No credential is looked at | A request carrying a session, a key or a proxy's header is answered as one carrying nothing, and no subject is resolved for it |
| GET and HEAD only | Every other method is answered 405, naming the two, before anything is read |
| One answer for nothing | Publishing off, no product publishing, a product that stopped, a document withdrawn or never written, and a document written under wider statuses than are published now all answer the same 404, so nothing tells a reader what exists |
| Nothing names a row | Paths, product identifiers and tracking identifiers are built from names, never from an identifier this deployment holds |
| A tag on every answer, and a date on a document | Each answer carries an entity tag, and a document and the files beside it the moment it last moved; a request repeating either is answered 304. A list carries no date: one that shrank, by a document withdrawn or a product turned off, is newer than its newest document. `Cache-Control: public, no-cache`: a reader asks every time and fetches only what changed |
| A signature is tagged by the document it signs | Its own bytes carry a random salt and differ every time, so a reader holding the signature of an unchanged document is told so, and the key is not used again |
| A list is read from every document's name and dates | A VEX document is read alone. Advisories' issued bytes are read only for the CSAF lists and for a path in their folder that holds no VEX document, so a VEX document, the files beside one, an OpenVEX path and a key read none. A reader taking the provider whole asks for every document and the files beside it, and none of those lists the rest |
| A VEX document is looked for before an advisory | Where an advisory's tracking identifier folds to a VEX document's path, the VEX document is served |
| The lists state dates from the documents | The feed and the description state the newest document's release, never the clock, so an unchanged provider answers the same bytes every time |
| A client is the address its connection came from, or the one a trusted proxy forwarded for | The proxies are the trusted sources sign-in reads, so a deployment has one list of them. From one of those, the client is the first address from the right of `X-Forwarded-For` that is not itself a trusted source: each proxy appends what it received from, and everything left of that hop is whatever the client wrote. From anywhere else the header is not read |
| The allowance is per replica | Each process holds a bucket per client, refilling at the configured rate and holding a minute of it. Once ten thousand are held it forgets the clients whose bucket is full again, and then the half holding the most of theirs, so a flood of addresses never gives a client being held back its allowance back |
| An IPv6 client is its /64 | One host is handed a /64 and may rotate through it |

A path below `/.well-known/csaf/white/` that names no document and a request
for `index.txt` with nothing to list answer the same 404. The description and
the feed are not served where there is no CSAF document to describe, since
each states when the newest was released.

## Advisories served

An advisory is served from the bytes that went out, read through the same rule
the static directory reads them by: the newest revision of each advisory whose
label lets it travel (`DESIGN-remediation.md` § The provider directory).

| Rule | |
|---|---|
| Read as anybody at all | The read of what went out is narrowed by the clauses every reader's is: every issue the advisory covers, now and when it went out, at a disclosed place in a product the reader reads. Anybody at all reads only the products that publish, so an advisory covering one product that does not is not served |
| Only what may travel | A revision labeled RED, about a flaw nobody outside has been told about, is never served, whatever came after it |
| An advisory states the address it is served at, where it is | Generated where the deployment publishes and every product it covers publishes and is in use, the address it states for itself is this surface's; otherwise the static directory's, where one is written, or none, since this surface would answer it with nothing. Issued bytes never change, so an advisory issued before its products published keeps the address it went out with |

## Statements and statuses

What is stated about one build is what somebody decided: the document of one
build (`DESIGN-remediation.md` § The VEX document), with a claim that an issue
applies and stays stated outright. A component nobody has judged gets no
statement, so a scanner reports it as it would without these documents.

| Status | Stated where | What it carries |
|---|---|---|
| Not affected | Every open place of the component stands under an approved, live claim that it does not apply or that the match was wrong | The claim's reason, and what stops it where the claim named it |
| Fixed | The same, for a claim that the fix is already here, and where a patch the build declares closed it | Nothing more |
| Affected | Every open place stands under a claim in force that the issue applies, will be fixed, or will not be | What a holder can do where the claim named it; otherwise that no fix is planned, where every claim says it will not be fixed, or that none is available yet |

| Rule | |
|---|---|
| Nothing is stated about a component nobody judged | An issue open and undecided, a deferral, and a claim still waiting on a second person state nothing. A document about an issue with no statement left is not served |
| Under investigation is never stated | No claim records that somebody is looking at an issue: a deferral says when somebody will look again rather than that anybody is looking, and a claim waiting on a second person is one person's opinion |

| Rule | |
|---|---|
| Disclosed findings only | Read at the public visibility, in a product anybody at all reads. A flaw of ours nobody has disclosed is in no statement, no document, no list and no count (REQ-37) |
| No other name and no description of an issue a flaw held back wrote onto | Where a flaw of ours recorded about an issue sits out of anybody's reach — undisclosed, or in a product that does not publish — the issue's other names and its description are left out: the flaw wrote its minted name and its summary onto the issue row every product shares |
| A claim in force states affected | Saying an issue applies hides nothing, so a claim of it needs nobody; the statuses that hide risk come from approved claims only, as in the document of one build |
| A supplier's statement about its own product is not passed on | Passing on a supplier's word under this deployment's name is the document carrying suppliers' statements, which somebody chooses |
| Each build is read at what it last scanned | Every branch and tag in use, as every variant in use, once it has been scanned. A build out of support is still published, because a reader still runs it (REQ-15) |
| A build stating more than one document of a build carries is refused | The product's documents are not worked out on that pass, and stay as they last were. The pass logs it |
| The statuses published apply to both documents | Limited, a statement of either other status is left out before a document is assembled, and a document left with none is withdrawn |

## Statement scope

A statement either holds for anybody shipping the component at that version,
or holds for this product's own build of it. A fork of the product shares most
of it, and which of the two a statement is decides whether a fork may take it
as it stands (REQ-31).

| Reason | Holds for |
|---|---|
| The match was wrong | Anybody shipping the component |
| The component or the vulnerable code is not present | Anybody shipping the component |
| The code ships and is never called | This build: another build calls what it calls |
| Nothing an attacker controls reaches it, or something stops it | This build |
| Already fixed here, a patch the build declares, will not be fixed, affected | This build |

| Rule | |
|---|---|
| A claim may state its scope | Stated when the claim is proposed, and part of what the second person agrees to. Changing it is proposing again, as changing any part of a claim is (`DESIGN-triage.md`) |
| A stated scope wins either way | Narrowed to this build, a statement whose reason holds for anybody is stated about the build; widened, one whose reason is the build's is stated about the component |
| A component is stated alone only where every build agrees | Within one document, every statement about the component as a whole holds for anybody and says the same thing, or each is stated about its own build. One build calling it not affected while another has the issue open there is a contradiction, and a reader is told the cautious half |
| A statement about one place is always stated beneath the component that pulls it in | Other places of the same component disagree with it, which is why it is about one place |

## The CSAF VEX document

One document per issue per product, across every branch, tag and variant: this
issue, in everything the product ships.

| Element | What fills it |
|---|---|
| Category and version | `csaf_vex`, CSAF 2.0 |
| Tracking identifier | `VEX-<product>-<issue>`, which never moves while the issue keeps its name |
| Title | The issue and the product's display name |
| Product tree | The publisher, the product and one leaf per build a statement names, with the package identifier the build's inventory gave itself; every component and every component pulling one in, by its package identifier; and a relationship naming each component as part of a build or beneath the component pulling it in. A value that is not a package identifier is not stated as one: the schema refuses it, and one refused helper fails the whole document |
| Status | A component holding for anybody is listed by its own product identifier; anything else by the relationship. A product listed under two statuses keeps the more cautious |
| Flags | The reason for every product not affected, one flag per reason |
| Threats | What stops the flaw, for a product not affected where somebody named it |
| Remediations | For an affected product, that no fix is planned or none is available, and what to do where the claim named it |
| Identifiers | The CVE where the issue has one among its names, and every other name, by the prefix it carries |
| Notes | What the issue is, in the words of whoever reported it, or its name where nobody said |
| References | The address the document is served at |
| Distribution | TLP WHITE, which is the standard's word for what TLP 2.0 calls CLEAR |
| Tracking status | Final: every statement in it stands on a claim already agreed or on a fact a scan recorded |

A product identifier is built from names: `<product>:<branch>:<variant>` for a
build, the package identifier for a component, and the two joined by `|` for a
component as part of either. Two documents generated from the same state are
the same bytes, because every list is ordered here rather than by the engine.

## The OpenVEX document

One document per branch or tag, across its variants, at what each last
scanned: what a scanner holding one build asks of it.

| Rule | |
|---|---|
| A statement holding for anybody names the component as the product, alone | A reader applies it to the component wherever it ships |
| A statement holding for this build names the build as the product, with the component beneath it | The build is named by the package identifier its inventory gave itself, or by its names where it gave none |
| A statement about one place names the component pulling it in, with this one beneath it | As the document of one build does |
| One statement however many variants say it | Stated from when it was first true |
| Its identifier is the address it is served at | A reader keeps documents by it |
| `version`, `timestamp` and `last_updated` | The revision held, when the first revision was released, and when this one was |
| A branch or tag with nothing stated has no document | A document of no statements answers nothing |

## Revisions

A revision of a published document is a fact about a moment: what was said,
and when. So it is recorded rather than worked out again on a request, and a
request is a read of what was recorded.

| Rule | |
|---|---|
| A new revision only where what it states moved | A digest over the address it states, its publisher, the title, the product tree and the statements is kept with the revision, and one worked out again and equal writes nothing. Moving the deployment's address or its publisher revises every document |
| Two products folded alike cannot share a path | The standard's filename rule folds `edge.os` and `edge os` alike, so their CSAF VEX documents about one issue would share a path. Turning publishing on for a product, and renaming one that publishes, is refused where another product that publishes or has published folds alike, naming it. A withdrawn document keeps its path, so a product that has published counts after it stops |
| The pass refuses a path another product holds | Reached only by two products folded alike turned on at once. The second product's document there is refused in words naming the first and saying to turn publishing off for the second, and the pass carries on with the rest of that product's documents and its withdrawals |
| A served document keeps the names it was built from | A rename is refused once a document that may name the part was served, withdrawn ones included, because a reader holds each by an address and an identifier built from the names. A product counts any document about it. A release counts its OpenVEX document, and once it has a scanned build every CSAF VEX document of its product, since which builds a revision named is in the bytes alone. A variant counts every document of its product once it has a scanned build. A release or variant with no scanned build is in no document and may be renamed |
| The next revision is one past the last | Its history is every revision before it with this one appended, and its first release never moves, so neither does its year folder |
| A revision is written in a transaction that reads what it replaces | Two replicas writing one document, the second matches nothing on the version it read and goes again |
| A document the product has nothing to say about any more is withdrawn | Kept, not served, and continued by its next revision if the issue comes back. Stating again what it stated when it was withdrawn, it is served again as that revision |
| A document written under every status is not served once the statuses narrow | Before anything is written again. The next pass writes it again under the narrower setting, or withdraws it |
| The bytes are kept for the revision held | The history inside them says every revision before it. Earlier revisions' bytes are not kept |

## Digests and signatures

| File | What it holds |
|---|---|
| `.sha256`, `.sha512` | The digest of the bytes served and the document's filename after two spaces, which is the standard's form and what the ordinary command-line checkers read |
| `.asc` | An armored detached OpenPGP signature over the bytes served, made on request with the key configured, and dated when the document was released, never before the key became valid |

The library adds a random salt to every signature, so two signatures over one
revision differ in their bytes; each verifies. A signature is dated no earlier
than the newest self-signature vouching for the key, so extending a key's
expiry or adding a name to it leaves every older document signable. Digests
are worked out on request from the bytes held.

## The publishing pass

Every five minutes, on the replica holding its lease, the pass works out every
publishing product's documents as anybody at all would read them, and writes
what moved.

| Rule | |
|---|---|
| Read as anybody at all | The pass reads the findings through the subject the surface reads the documents through, so a document cannot hold anything a reader may not be handed |
| One replica writes | A lease names it, as for the other passes that answer for the deployment; the conditional write keeps two from writing one revision twice where a lease is lost mid-pass |
| A product that cannot be worked out does not stop the next | Its documents stay as they last were, and the pass logs it |
| Read before written, and read again inside the write | What has not moved is stepped over on a read of the digests; what has is decided inside its own transaction |

## Measurements

The full-size switch image as both variants of a branch on PostgreSQL, every
component with a package identifier carrying one issue and the kernel the
4,943 a real one did: 11,785 issues at components per build. A tenth of the
distribution packages' own issues, 76, are agreed not to apply because the code
is not there; nothing else is decided.

| Measured | |
|---|---|
| CSAF VEX documents | 76, one per issue decided, median 1,657 bytes, largest 1,842 |
| OpenVEX documents | 1, 20,832 bytes |
| Held in all | 145,778 bytes |
| The feed | 88,601 bytes, answered in 7 to 8 ms |
| The index | 2,660 bytes |
| The provider description, one document, or its digest | Answered in 6 to 7 ms |
| The first pass | 3.8 s, writing every document |
| A pass over nothing that moved | 3.3 s, writing nothing |

A document is an issue somebody decided about, so the number of documents
grows with the decisions rather than with what a scanner reports. A pass reads
every build's claims whatever is published, which is most of what it costs.

## Not built

| Not built | What exists |
|---|---|
| A ROLIE service document and a category document | Both optional. The provider description lists the one feed, and a checker reports each absence as a warning |
| Directory listings | A path naming a folder answers 404. The index and the list of changes name every document |
| A score in a VEX document | The CSAF VEX document carries none, and the validator's optional test asking for one on an affected product warns |
| Upstream statements read back | A fork's deployment reading these documents as statements about what it ships, applying the ones that hold for anybody |

## Limits

| | |
|---|---|
| The rate is per replica | Held in each process rather than in the database, so the request it limits writes nothing |
| A document is as current as the last pass | Up to five minutes behind a claim agreed or a scan landing. Turning a product off and narrowing the statuses take effect at once, because what may be served is asked on every request |
| Every document of a product is worked out on every pass | 3.3 s on the image above, nearly all of it reading what stands; a record of what moved would be a second copy of what the findings already say (REQ-74) |
| The scope of a statement about one place is not published | A place is stated beneath the component pulling it in whatever the claim's scope, because the other places of the component disagree |
| A signature is made per request | Signing at the pass and keeping the signature would make it a stored copy of something worked out from the bytes and the key |
