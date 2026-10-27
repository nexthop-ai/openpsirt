# Build and publisher claims

What a build claims about itself, and the VEX documents and supplier advisories
an administrator uploads: how each is read, stored and matched to components.

Satisfies REQ-08, REQ-11, REQ-18, REQ-31, REQ-66.

## Contents

- [Build-declared suppressions](#build-declared-suppressions)
- [Claim matching](#claim-matching)
- [Stored claims](#stored-claims)
- [Administrator-supplied VEX](#administrator-supplied-vex)
- [Supplier advisories](#supplier-advisories)
- [Name folding](#name-folding)
- [Limits](#limits)

## Build-declared suppressions

A build's claims (REQ-11) arrive two ways.

| Source | Precision |
|---|---|
| On the component | A patch in a component's pedigree recording which vulnerability it fixes, attached to the thing it is about |
| In a document of its own | Statements naming what they apply to by package identifier: one version, every version of a package, or a source tree |

| Rule | Reason |
|---|---|
| Only CycloneDX carries the first | SPDX can say a file is a patch for a package and never which vulnerability it resolves, so an SPDX build states its carried patches in a document. Deriving the link from a patch's filename would report a suppression nobody made |
| The format a scan arrived in is carried out of the reader | A claim the build no longer argues is withdrawn, which holds only where the build had somewhere to argue it |
| A claim of an origin the scan could not have stated is left open and counted, and the receipt says how many were carried forward | Closed on silence, a product's first scan in the other format would close every claim and reopen every finding they suppressed |
| A claim the scan could have stated and did not is closed | Otherwise the difference means nothing |
| Both sources are read into one shape with the origin recorded | They differ in precision, not meaning, and only the document can point at something that cannot be resolved |
| The vocabulary is kept, never translated | "We carry the fix" and "the vulnerable code is never reached" are different claims. Two of the four statuses take a finding out of somebody's work; the other two say the build looked |
| A carried patch reports as fixed | The vulnerable code was there and a patch resolved it, which differs from never applying |
| Only what a patch claims is read: a vulnerability in its own name or in a header saying what it fixes, and only a security claim | A patch resolves defects and improvements as readily as vulnerabilities |
| A claim naming an unreadable status refuses the document | A claim that cannot be acted on is one the build believes it made |
| A claim with no justification is kept | The format requires one for a single status, and an unjustified claim is a triage question |
| A claim that matched nothing is reported, never dropped | A judgment that went nowhere brings back as noise a finding the build answered. The producer's extracted claims name source trees, so this is the ordinary case |

What each claim does to a finding is `design-docs/findings-closure.md` §
Build-declared claims.

## Claim matching

| Rule | Reason |
|---|---|
| A package identifier is compared as identity reduces it: qualifiers and subpath dropped, escapes decoded, scheme and type lowercased | A claim names package and version, and the inventory's package carries its architecture. One real image carries one version as `2.3.2-2%2Bb1` and `2.3.2-2+b1` |
| A claim naming no version covers every version | The format says so |
| A claim naming a version reaches a component stating that version beside an identifier naming none | An inventory may state the version outside the identifier |
| An OpenVEX product with subcomponents is a claim about the subcomponents; one with none is a claim about itself | The product is what shipped. This deployment's own export states every claim that way |
| A subcomponent is read only as a package identifier, and a product whose subcomponents are all of another kind claims nothing | Anything else names a component and no version, which covers every version and every fork |
| A claim against a source tree matches a component of that name, or a fork of one | The build knows which packages came from a tree |
| A source tree is named as a bare name where the document carried no package identifier, or as a generic package identifier; the two match alike | They are the same claim |
| A generic identifier names its package by its last segment, and its namespace is compared only where the component is itself a generic identifier carrying one | A distribution's namespace names the distribution, never the tree |
| A source tree named with a version is matched on it, against the component's own version and what it was built from | Read as every version, a claim about one release suppresses a live finding on another |
| A claim is matched at every occurrence of its component, within the product it names | The fan-out is ours |
| A name somebody types to narrow what a build carries is folded as the claim's name is and compared exactly | It matches in any capitals on every engine (§ Name folding) |

A claim is placed by the product it names its subject as shipping inside.

| The product is | The claim applies |
|---|---|
| Named by nothing, the build's root, or nothing the build ships | Across the whole build. A root is stored by name alone, so a claim is never placed beneath it |
| A component of the build, at the version the claim names | At an occurrence where every route up the tree runs through that component, at any depth, never on the component itself. An occurrence reached both through the product and outside it is not answered |
| A component of the build at another version, or at no version | Nowhere, and the claim is counted as reaching nothing |

## Stored claims

| Rule | Reason |
|---|---|
| A claim stores its product with the subject: package identifier, name and version | A claim about zlib inside curl and one about every zlib are two claims |
| A claim naming no product keys as it did before a product was stored | A claim recorded earlier keeps its row until the build restates it with its product |
| A claim attached to a scan stores the package identifier, the name, and the version stated outside the identifier | |
| A claim naming no package and stating its version only as a branch covers that version and no other | A statement that acme-fw 4.2 is not affected leaves a finding on acme-fw 5.0 open |
| A version stated outside the package identifier is part of the claim's identity; one inside it is not stored again; a claim stating none keys as before | A claim about 4.2 and one about 5.0 are two claims. A claim stating its version only as a branch has a new identity, so each closes and reopens once, on the first scan after the upgrade |
| The carried patches read names the version beside the subject: "acme-fw 4.2" | A status without its version reads as a claim about whatever ships |
| The reasoning is part of the identity where the claim gives one; a claim giving none keys as before | A changed explanation closes the old claim and opens the new, so both are kept. The v0.9.0 upgrade keys every stored claim this way, so none reopens on the first scan after it |
| A claim keeps the name of its subject as the producer spelled it, for display, and beside it the name folded | |

## Administrator-supplied VEX

VEX statements arrive by administrator upload (REQ-31), as a conforming VEX or
CSAF-VEX document, read into the same claim whichever was written.

| Rule | Reason |
|---|---|
| A CSAF product identifier is resolved through the tree defining it, once the document closes | It is somebody else's key, and the tree may follow the claims. An identifier the tree never defines is dropped, and a claim left pointing at nothing is refused |
| A composite identifier is resolved through its relationship down to the package, with the product it relates to kept beside it, for all five relationship categories | A distribution names a package inside a platform. The package is what a component can be, and the product places a supplier's statement in a build |
| An OpenVEX product with subcomponents is kept beside each subcomponent | A statement about zlib inside a product is not one about every zlib |
| A CSAF advisory is refused here and read by § Supplier advisories | What each kind means and what a later upload replaces differ |
| The reader is the one the build's own suppressions go through | One parser keeps the hostile-input surface to a size somebody can reason about (REQ-66) |
| A document is digested as it streams, and one past the size bound is refused for its size before any parse error | A document cut at the bound otherwise fails as malformed |
| A publisher's name and an advisory's own name are held without control or format characters, from the request, the file name or the document | Both are shown beside the evidence, and a right-to-left override reads reversed there |
| Uploading again from one publisher sets aside what they no longer say, never deletes it, and every statement keeps its document's digest | What an approval relied on stays readable, and a revision can be noticed |
| The same document again writes nothing where it reads as what stands, and replaces what stands where it reads differently | The digest is of the bytes. A reader deriving a different name or target from the same bytes has changed what the statements say, and re-uploading brings stored rows up to date |
| A statement is stored against the package's decoded name, without namespace, version, qualifiers or subpath | `pkg:deb/debian/frr?arch=amd64` is a statement about `frr` |
| The product a component ships inside is stored as its package identifier, its folded name, and the version stated | The name finds a product in a build, and the version is what a statement applies at |
| What a statement names its supplier's product as is stored: a component inside a named product, a product named alone by no package identifier, or nothing | Only a statement read this way places anything, so one recorded before the product was read, and a package named alone, close nothing |
| A claim a later document repeats word for word, with the supplier's product where it stood, keeps its row and takes the later digest and the moment it was said again | A superseded claim tells every approved decision citing it that the publisher changed their word; a repeat did not |
| A row recorded before its product was read keeps its row for the same claim placed anywhere, and takes the new placement | |
| A claim moved to another release of the product is a change | What an approval was granted on stays readable as it was |
| A fetched advisory's digest covers which of its claims were kept as well as its bytes | The same advisory differs in digest whenever the product ships something it did not |

What the statements do is triage's: a statement whose product is a build's root
is that build's own claim (REQ-11), a supplier's statement about its own
product closes the finding at every occurrence inside it (REQ-31), and every
other statement is evidence and a prefill (`design-docs/triage.md` § Evidence
from publishers).

## Supplier advisories

A supplier's CSAF security advisory arrives by administrator upload on a path
of its own, or from its feed (`design-docs/ingest-suppliers.md`), and lands
where a VEX document lands (REQ-31): evidence and a prefill, and where it says
the publisher's own product is not affected, a closure at every occurrence
inside it.

| Rule | Reason |
|---|---|
| The profile is checked both ways, each refusal naming the path that takes the document | A VEX document read here would be superseded under a name it lacks, and an advisory read as VEX would turn announcements about the publisher's flaws into claims about what a build ships |
| An advisory is replaced by its publisher's name for it | A statement set is a publisher's whole answer; an advisory is one of hundreds, and keyed on the publisher each would set aside the rest |
| Neither kind touches the other | One publisher issues both |
| An advisory naming no publisher or no tracking identifier is refused | They decide what it supersedes and whose name stands beside it, and both are mandatory in the format |
| Every product-status list the format defines is read, at the versions it names | Two of the eight carry the only status a real advisory states |
| Words are attached to the products they name, by identifier or by group | Read by identifier only, a remediation scoped by a group lands on the status's general words, so an upgrade instruction reaches a claim the document never made |
| A group is expanded once the document closes, and a group holding nothing scopes words to no product | The tree may follow the words naming it |
| A CVE is the issue's name wherever it is stated, and every other identifier an alias; with no CVE, the first other identifier is the name (REQ-18) | Key order is the producer's |
| Claims come back in the order the document stated them | A map has no first, and the same bytes twice would store different reasoning under a digest saying nothing moved |
| A version stated as a branch is the version the claim is about | A publisher with no package identifier states its version as a branch; dropped, a claim about one release answers for all |
| A claim naming a version offers a prefill only at that version | An advisory names the fixed version, which is not the shipped one; offered elsewhere, the control is prefilled with a claim the publisher never made |
| A claim is shown at every version, with the version it was about | A triager wants which versions the publisher spoke of, and a status without one reads as its opposite |
| Words naming products reach the claim those products are under | A remediation names the packages to upgrade and lists them as fixed; read by category alone, it lands on an affected claim |

A publisher names products as a package with a package identifier, a package
composed into a platform by a relationship, or a product named and nothing
more, each with its version. The third is the ordinary equipment vendor's, and
resolves as a claim against a source tree does.

### CSAF bounds

| Bound | Charges |
|---|---|
| The component bound | Each distinct identifier stated, once however often named |
| Ten times the component bound | Each entry kept: a product defined, a group, a group member, a product listed under a status by each claim, a product or group a sentence names, an alias, and every member a group reference expands to |

| Rule | Reason |
|---|---|
| A justification naming no product is not an entry, and a claim keeps the last one it gives | A document repeating it holds one |
| A group reference is charged what it expands into | One group of 50,000 products referenced 4,000 times is 200 million entries from under a megabyte |
| The second bound is about 170 MB at its default | An entry costs about 170 bytes. A real kernel advisory, 794 identifiers named 220,088 times, spends a fifth of it in 27 MB against a 256 MB size default |
| A composite identifier resolves through its relationship | One distribution VEX document composes all 1,669 of its product identifiers that way |
| One document's claims are written in batches | One advisory is 95,139 claims and the caller is waiting (`design-docs/ingest-measurements.md` § Claim writes) |

## Name folding

| Rule | Reason |
|---|---|
| A component's name is folded on the way in, into a column of its own, and a statement's component is folded the same way and cut to the same width (REQ-08) | The engines fold differently outside ASCII, so a statement naming a component with such a letter matches on three engines and not the fourth. Folding on write keeps the index usable, and a name past the width matches instead of being refused by three engines |
| An issue's identifier and every name it goes by are folded the same way | Comparing through `LOWER` puts a function on the indexed side and scans both vulnerability and alias tables per statement: thirty seconds for an answer of a fraction of one |

## Limits

| Limit | Detail |
|---|---|
| The range a product-status list implies is not read | That everything after a first fixed version is fixed is not taken; the document enumerates the versions it is about, and a version it does not name has no claim |
