# Catalog, upload and release screens

The catalog, uploading an inventory, the Uploads screen and its receipts, an
upload's changes, the repositories screen, the product page, a scan run's page,
release comparison, and a tag's release page.

Satisfies REQ-05, REQ-13, REQ-15, REQ-42, REQ-54, REQ-60.

## Contents

- [Catalog and uploads](#catalog-and-uploads)
- [The Uploads screen](#the-uploads-screen)
- [Inventory changes](#inventory-changes)
- [The repositories screen](#the-repositories-screen)
- [Product and scan pages](#product-and-scan-pages)
- [A release, gathered](#a-release-gathered)
- [Limits](#limits)

## Catalog and uploads

Adding to the catalog is an action (REQ-60): products, branches and tags,
variants and users each carry an "add" control in the header and a floating
action, both opening a drawer; the table is the screen.

| Rule | Reason |
|---|---|
| The catalog says what each entry holds: a product its branch, tag and variant counts, what is open and when last scanned; a branch or tag what it came from; a variant whether it ships to customers. Every count is issues at components | |
| What is open is counted only where asked: the three screens drawing the column ask; the pickers do not. Absent, never zero, where not asked | It is the whole cost of a catalog read (`design-docs/interface-measurements.md` § Catalog reads) |
| A product row says what it triages from, "deployment's" where it follows the deployment, never the deployment's current word; an administrator changes it there | It explains a number; following and stating differ |
| A product row says whether its documents are published: a box for an administrator, a word for others (`design-docs/publishing.md`) | |
| An administrator's row action opens the trusted upstream drawer: the upstream as trusted, how reading it goes, a key it offers in place of the trusted one, stop trusting, and a field to name one. Naming is check, then trust, showing the key before anything is read (`design-docs/upstream.md`) | |
| An administrator's row action opens the repository settings (§ The repositories screen) | |
| A product, a release and a variant are corrected and retired from the list declaring them; a release's list of variants carries no control | It is what the release was built as |
| A product's edit offers both names, the one scans and documents use and the one screens show, which move independently; only the first is refused once a document is published, and the drawer says so where the name is typed | A published document is held under its name |
| A retired product says so on its own page | Only a kept link reaches it |
| A retired tag opens its release page, which reads retired lines to resolve it, and says it is retired; nothing offers it as the release before another | |
| A retired variant is marked on releases built as it | Their findings stay open |
| An inventory is uploaded from the bar and from Uploads (REQ-05): the drawer takes the build (prefilled from the scope, refused if undeclared), one CycloneDX or SPDX inventory, as the file itself says, and any number of OpenVEX suppression documents; it posts the pipeline's multipart request and opens Uploads | |

## The Uploads screen

One build's uploads, a tab per kind, each reading its own list
(`design-docs/ingest-receipts.md` § Upload listing).

| Tab | Holds |
|---|---|
| SBOMs | The build's receipts, builds gone quiet, the scanner, and what a new line inherits |
| Static analysis | The build's runs, newest first, with status and counts, and each series' last upload turned away |
| VEX documents | Every one uploaded to the product, newest first, taken or refused |
| Supplier advisories | Every one that arrived for the product, uploaded or fetched by a feed, newest first, taken or refused |

| Rule | Reason |
|---|---|
| The tabs are the kinds the every-kind list names; an unreadable kind has no tab, so a reader of disclosed findings has no static analysis tab | |
| A tab whose newest upload failed or was turned away is marked | A pipeline owner checks the newest |
| Each tab carries its list's count from the every-kind list | |
| The tab is in the address, SBOMs the bare address; a kind with no tab opens SBOMs | |
| The body waits for the every-kind list | Otherwise an unreadable kind's list is asked and refused |
| The VEX and supplier tabs are product-wide and say "All builds of this product" above the list and on hover | |
| A document row says who sent it: the uploader's display name, or the supplier and "feed" | |
| A refused document shows the reason the sender was told, under its state | |
| The newest taken copy of a document is marked Current; an earlier copy is kept and replaced | |
| An address a feed fetched from is not a link, shown on hover | A third party's URL |
| VEX documents and supplier advisories are uploaded from the suppliers settings, which an empty tab links | |
| An empty document tab says uploads before v0.11.0 are not listed, and their statements still apply | |
| An upload from anywhere asks the every-kind list again | A refusal moves the counts too |
| Each document tab opens on its first page | |

### Receipts

The SBOM tab is the receipts. A receipt shows "queued" until its run says what it
changed.

| Rule | Reason |
|---|---|
| It says what each run changed and what it measured against: scanner, version, vulnerability database (REQ-13) | A clean build and a stale database read alike |
| Where one run answers several uploads, the numbers sit on the newest and the rest are blank | A run covers a build |
| A run that changed nothing says 0; a row with nothing to report is blank, and the wire tells them apart | A superseded upload must not read as a clean scan |
| Each receipt says what its upload did to the build's contents and opens the names: removals marked and first; an upload that moved nothing says so; a build's first upload says nothing | A removal looks like a stopped dependency |
| What a new line inherits: the line it carries from, how many reach this one, how many are past their date, how many cover nothing here, the rest a list to tick. A promised upgrade that moved is a line of its own saying to plan again from the component. Two of the six groups are questions, and it says which | Asked when a line has its first scan |

## Inventory changes

An upload's own screen lists the names it added, removed and moved to another
version against the upload before, with every version each name stood at on both
sides. It is where an alert about a sharply changed build leads.

| Rule | Reason |
|---|---|
| Removals, then arrivals, then names at new versions, ordered by the server, never by a sorted column | The order is the answer |
| One kind at a time is a filter asked of the server | A page's count is of the page |
| A name that went is not a link; every other name opens the component | |

The component comparison is the same listing between any two builds of a
product as each stands now, reached from release comparison with its two builds
and picking its own pair the same way.

| Rule | Reason |
|---|---|
| Table, order and filter are the upload listing's | |
| A removed name is a link | The earlier build still ships it |
| The chosen kind is in the address | |
| The file is the narrowing on screen: CSV and JSON take the two builds and the kind | |
| A build with no inventory is said in words | The server refuses rather than listing all as added |

## The repositories screen

One product's repository settings, reached from its row in the products table
(`design-docs/analysis-source.md` § Repository settings).

| Rule | Reason |
|---|---|
| An administrator's screen; for anybody else it reads nothing and says so | The endpoint refuses others |
| Hosts and paths are two tables edited in place and saved together; nothing is sent until Save | The endpoint replaces both |
| A host offers its two templates only where custom; a template left on a host changed from custom is not sent | |
| A path states each source setting as kept, not kept, or inherited; inherited is sent as left out, taking the nearest prefix stating it | |
| An empty field is left out and every field trimmed | Repository and branch come together or not at all |
| A refusal is shown, naming the entry, and the draft stays as typed | |
| A save moves the code finding screens | Their links are built from these settings when read |

## Product and scan pages

The product page names every declared build with what is open, overdue,
exploited, undecided and agreed in each, and when each was last scanned. The
products table is administration; this page is reading how something goes.

| Rule | Reason |
|---|---|
| Every number opens the list it counts; waiting decisions open the queue narrowed to the product | |
| On home, lapsed decisions open the findings list narrowed to lapsed, and expired deferrals that queue list, each counted from the list it opens | |
| Counted as issues at components | The findings list's unit |
| The product's totals are counted again over the product, never summed from builds | A sum put 15,231 over a list of 7,629 |
| "Undecided" and "agreed" are the findings list's words, from the same expression | |
| A build never scanned is a row; one out of support says so | |
| The figures and each build's counts are dependency findings, drawn under `design-docs/interface.md` § Families a reader holds: absent for a reader not reading them here, with one line where they are read in another product; the builds and their last scans stay | Zeros for a reader holding security testing alone read as a clean product |

A scan run's page, Known vulnerability scan, is reached from the upload's state,
its breadcrumb under Uploads, and release comparison's "the known vulnerability
scan that stopped" beside a closure it does not explain. It says what the run
opened and closed by the rating in force, and how much it opened is known
exploited.

| Rule | Reason |
|---|---|
| A band with none is left out | A row of zeros reads as a failed chart |
| What it opened is a list reached from the count: the findings list narrowed to the run by identifier, as a self-removing chip | Two runs can land one day |
| What it closed is not a list | The list is of what is open |
| How long it took is said; a run still going says when it started | |

Release comparison carries a chart across every build (REQ-54), in bars, because
the builds are separate points and a line draws a trend through a gap.

## A release, gathered

`/products/:product/branches-and-tags/:branch_or_tag` names a tag's release page
when the catalog says the name is a tag: a tag is what was handed over when cut,
a branch what it is built as nightly.

| Section | Answers |
|---|---|
| The variants | The variants it was built as, each with what is open |
| Open now | Open across every variant, by severity |
| Changes | The release before this one, and the comparison against it |
| Customer documents | The release note, the advisories, a published VEX per variant |
| The record | The disposition register per variant |

| Rule | Reason |
|---|---|
| No overdue section | A tag never changes |
| The release before is the newest earlier tag with a recorded day | A declaration date sorts a late-recorded release wrongly |
| It is cut from the same branch, where both say so | Two branches are two pieces of software |
| Advisories are not narrowed to the release | An advisory goes out once |
| The per-variant count comes from the answer the severity split is added from | The variant list fills no count |

## Limits

| Limit | Detail |
|---|---|
| When a product was retired is not recorded | Its out-of-support date is when support ended |
