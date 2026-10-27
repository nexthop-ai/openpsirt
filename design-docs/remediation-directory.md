# The provider directory

Every advisory that has gone out, written as the CSAF provider directory into a
store an operator configured for their own web server.

Satisfies REQ-39, REQ-70.

Nothing here answers a request, and nothing in the application reaches the
package that writes it. Where the deployment also serves its documents
(`design-docs/publishing.md`), an advisory states that address and the directory
is a copy.

## Contents

- [Directory rules](#directory-rules)
- [The files](#the-files)
- [Operator responsibilities](#operator-responsibilities)
- [Not built](#not-built)
- [Limits](#limits)

## Directory rules

| Rule | Reason |
|---|---|
| What is written is the bytes that went out | Never what the record would produce today |
| Issuing publishes; an edit changes nothing until the next revision is recorded as gone out | The edit withdrew the agreement |
| Only a document that may travel is written, asked of its bytes | The record moves and the file does not; a document saying nothing is not permission |
| The newest revision that may travel, per advisory | A newest revision under embargo leaves an older public one listed |
| A pass writing what this process last wrote writes nothing; a new process writes once | A versioned store keeps a version per write, and a new modified time tells a web server the file moved |
| Documents first, the lists naming them last | A list never names a missing file |
| Nothing is dated from the clock; the feed and the description date from their newest document | Otherwise every reader fetches everything every hour |
| Nothing is deleted | What may be published and where are properties of unchanging bytes |
| A first release is frozen when it goes out, until then the earliest moment a covered flaw was recorded here | It is the year folder, and moving it orphans the path a reader holds |
| Held back is counted per advisory | Per revision overcounts |
| A pass with nothing that may travel logs how many it held back, once per change of the count | An all-embargoed directory is otherwise silently empty |
| A document that no longer reads back is skipped, counted and logged each pass; its advisory leaves the directory, with no older revision in its place | Issued bytes outlive their shape below 1.0; revisions share a path, so an older one would overwrite one already out |
| A pass fails only where nothing it was given could be read | |
| The files are readable by whoever serves them | Another user serves them |
| An empty directory is not written | It would have to state when it was last updated |
| A store of its own | Every file is public, and every attachment is authorized first (REQ-70) |
| The store is a type of the writing package, and a test checks nothing in the application reaches that package | Handed the storage beneath, a handler could serve the files |
| The address is required, `https`, refused at startup otherwise | Every self address is built from it, and the standard requires `https` |

## The files

| File | Holds |
|---|---|
| `provider-metadata.json` | The publisher, built by the rule every listed document uses, where the documents are, and whether aggregators may list and mirror them |
| `<year>/<name>.json` | One document per advisory. The year is when the document states the flaw was recorded; the name is the tracking identifier lower-cased, every run outside letters, digits, a plus and a hyphen one underscore |
| `<year>/<name>.json.sha256` | The delivered bytes' hash, then the filename, as the standard and the command-line checker read it |
| `index.txt` | Every document's path, one per line |
| `changes.csv` | Every document and its revision's release, newest first |
| `feed-tlp-white.json` | The ROLIE feed: each entry names the document, its hash file, and when it was first recorded and last released |

| Rule | Reason |
|---|---|
| The supplier reader follows this directory, which a test checks, reading only the fields it uses | A misshaped unused field leaves the listing readable |
| A document's stated address and its path come from one rule: the tracking identifier names it, the initial release date folders it | |
| A hash file sits beside each document and nothing else | The feed names it in the document's entry |
| The feed names itself by a token, never its address | The feed shape allows letters, digits, a plus, a hyphen, an underscore and a dot |
| The list of changes and the feed are how outsiders follow publication: no subscriber list, no per-CVE notice | Configured destinations are this deployment's notifications (`design-docs/notifications-delivery.md`) |

## Operator responsibilities

The operator's web server owns the transport, directory listings, and one of
the three ways a reader finds the provider description: the well-known path, a
`CSAF` field in `security.txt`, or the DNS record.

## Not built

| Not built | What exists |
|---|---|
| Signatures in the directory | The served documents are signed where a key is configured (`design-docs/publishing.md`); the directory's description claims the provider role alone |
| A ROLIE service document and a category document | Both optional; a checker warns on each absence |

## Limits

| Rule | Reason |
|---|---|
| The directory is read whole every pass, and what may be published is written again | Advisories are few, and a record of the store's contents would copy the store |
