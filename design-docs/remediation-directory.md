# The provider directory

Every advisory that has gone out, written as the static directory the CSAF
standard defines for a provider, into a store an operator configured for their
own web server.

Satisfies REQ-39, REQ-70.

Nothing here answers a request for a file, and nothing in the application can
reach the package that writes them. The documents this deployment serves itself
are in `design-docs/publishing.md`; a deployment may have both, and an advisory
then states the address this deployment serves it at, with the directory a
copy.

## Contents

- [Directory rules](#directory-rules)
- [The files](#the-files)
- [Operator responsibilities](#operator-responsibilities)
- [Not built](#not-built)
- [Limits](#limits)

## Directory rules

| Rule | Reason |
|---|---|
| What is written is the bytes that went out, kept as the issuance was recorded | The file a reader fetches is the one published, never what the record would produce today |
| Issuing is what publishes | An edit afterwards withdrew the agreement that let the last revision go, so nothing changes until the next revision is recorded as gone out |
| Only a document that may travel is written | The directory is the freely accessible half of the standard's distribution |
| Whether it may travel is asked of the bytes, never of the record | The record moves and the file does not. A document saying it may be passed on says so for ever, and one saying nothing is not read as permission |
| The newest revision that may travel, per advisory | An advisory whose newest revision went to a coordinating body under embargo has an earlier one already public; dropping the advisory takes it out of every list a reader holds |
| A pass writing what this process last wrote writes nothing; a process just started writes once | A rewrite is the same file but costs a reader: a versioned store keeps a version per pass, and a rewritten file's modified time is what a web server answers "has this moved" from |
| The documents first, the lists naming them last | A list naming a missing file sends a reader to nothing; a file nothing names yet is fixed by the next line |
| Nothing is dated from the clock: the feed and the provider description date themselves from their newest document | Dated by the pass, every file moves every hour and every reader fetches the whole directory |
| Nothing is deleted | A document that went out is out. What may be published and where it goes are properties of bytes that do not change, so the set only grows |
| A document's first release is frozen when it first goes out; until then it is the earliest moment any covered flaw was recorded here | It is the year folder. Naming an older flaw afterwards would move a published document and orphan the path a reader found |
| Held back is counted per advisory | Counted per revision, an advisory with two held revisions over a travelling one reports two missing from a directory missing none |
| A pass with nothing that may travel logs how many it held back, once each time the count moves | An all-embargoed deployment otherwise has an empty directory and nothing saying why |
| A document that no longer reads back is skipped, counted and logged every pass; its advisory leaves the directory, and no older revision is carried in its place | Issued bytes are kept for ever and their shape may change below 1.0, so stopping on one keeps every later advisory out. Every revision shares a path, so an older one would overwrite a revision that may already be out |
| A pass fails only where nothing it was given could be read | |
| The files are readable by whoever serves them | Another process, as another user, serves them; written as an authorized download is, every one is refused and the directory reads as empty |
| A directory with nothing in it is not written | It would have to state when it was last updated |
| A store of its own | Every file here is served to anybody, and every attachment is authorized first (REQ-70) |
| The store is a type of the package writing the directory, and a test checks nothing in the application reaches that package | Handed the storage underneath, a handler could serve the files without reaching the package, and the check would pass it |
| The address is required configuration, an `https` address, refused at startup otherwise | Every address the directory states about itself is built from it, an aggregator follows them, and the standard requires `https` for the documents |

## The files

| File | Holds |
|---|---|
| `provider-metadata.json` | Who the publisher is, where the documents are, and whether aggregators may list and mirror them. The publisher is the object every listed document carries, built by the same rule |
| `<year>/<name>.json` | One document per advisory. The year is the one the document states the flaw was recorded in, so a document revised in January stays put; the name is the tracking identifier lower-cased, then every run outside letters, digits, a plus and a hyphen replaced by one underscore |
| `<year>/<name>.json.sha256` | The hash of the delivered bytes, value first and filename after: the standard's form and the ordinary command-line checker's |
| `index.txt` | Every document's path, one per line |
| `changes.csv` | Every document and when its revision was released, newest first, so a reader who fetched yesterday stops early |
| `feed-tlp-white.json` | The same documents as a ROLIE feed, each entry naming the document, its hash file, and when it was first recorded and last released |

| Rule | Reason |
|---|---|
| The supplier reader follows this directory, which a test checks, reading only the fields it uses under the names written here | A publisher's misshaped field it does not use leaves the listing readable |
| A document's stated address and the path it is written under come from one rule: the tracking identifier gives the name, the initial release date the folder | Spelled apart, a document cites a file the directory does not serve |
| A hash file sits beside each document and nothing else | The standard asks for one per CSAF document and the feed names it in that document's entry; a hash beside a list has no entry and no reader |
| The feed names itself by a token, never by its own address | The shape a reader validates a feed against allows letters, digits, a plus, a hyphen, an underscore and a dot |
| The list of changes and the feed are how somebody outside follows what is published: no subscriber list, no per-CVE notification, nothing to sync | Destinations an administrator configures are for this deployment's own notifications (`design-docs/notifications.md`) |

## Operator responsibilities

The operator's web server owns the transport, directory listings, and one of
the three ways a reader finds the provider description: the well-known path, a
`CSAF` field in `security.txt`, or the DNS record.

## Not built

| Not built | What exists |
|---|---|
| Signatures in the static directory | The documents this deployment serves itself are signed where a key is configured (`design-docs/publishing.md`); the directory writer writes none, and its provider description claims the provider role alone |
| A ROLIE service document and a category document | Both optional; the provider description already lists the feed, nobody has asked for a categorization, and a checker reports each absence as a warning |

## Limits

| Rule | Reason |
|---|---|
| The directory is read whole on every pass, and the documents that may be published are written again | Advisories are single or low double digits a year, so the pass is a read finding nothing new, and a record of what the store holds would be a second copy of the store |
