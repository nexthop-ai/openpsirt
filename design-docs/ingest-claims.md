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

A build's claims about itself (REQ-11) arrive as a pedigree patch on a
component naming the vulnerability it fixes, or as statements in a document of
their own naming one version, every version of a package, or a source tree.
What each claim does to a finding is `design-docs/findings-closure.md`
§ Build-declared claims.

| Rule | Reason |
|---|---|
| Only CycloneDX carries a patch claim | SPDX cannot say which vulnerability a patch resolves, and a filename is no claim |
| The scan's format is carried out of the reader | A claim no longer argued is withdrawn only where the format could argue it |
| A claim of an origin the scan could not state is left open, and the receipt counts those carried forward | Otherwise switching format reopens everything |
| A claim the scan could have stated and did not is closed | |
| Both origins read into one shape with the origin recorded | Only a document can point at something unresolvable |
| The status vocabulary is kept, never translated | "We carry the fix" and "never reached" differ; two statuses remove work, two say the build looked |
| A carried patch reports as fixed | |
| Only a security claim a patch makes is read, from its name or a header saying what it fixes | Patches fix defects too |
| An unreadable status refuses the document | |
| A claim with no justification is kept | It is a triage question |
| A claim matching nothing is reported, never dropped | The producer's extracted claims name source trees, so this is ordinary |

## Claim matching

| Rule | Reason |
|---|---|
| A package identifier is compared reduced: qualifiers and subpath dropped, escapes decoded, scheme and type lowercased | One image carries `2.3.2-2%2Bb1` and `2.3.2-2+b1` |
| No version covers every version | The format says so |
| A version reaches a component stating it beside an identifier naming none | |
| An OpenVEX product with subcomponents claims the subcomponents, read only as package identifiers; one with none claims itself; one whose subcomponents are all of another kind claims nothing | A bare name covers every version and fork. This deployment's export states claims that way |
| A source-tree claim matches a component of that name, or a fork | The build knows what came from its tree |
| A tree is a bare name or a generic package identifier, matched alike; the generic one names its package by its last segment, comparing namespace only against a generic component carrying one | A distribution's namespace names the distribution |
| A tree named with a version is matched on it, against the component's version and what it was built from | |
| A claim is matched at every occurrence of its component in the product it names | |
| A name typed to narrow a build's carried patches is folded and compared exactly | § Name folding |

| The claim's product is | It applies |
|---|---|
| Nothing, the build's root, or nothing the build ships | Across the build |
| A component of the build at the version named | Where every route up runs through that component, never on it; an occurrence reached both inside and outside is not answered |
| A component at another version, or at none | Nowhere, counted as reaching nothing |

## Stored claims

| Rule | Reason |
|---|---|
| A claim stores its product's package identifier, name and version beside the subject; a claim naming no product keys as before products were stored | zlib inside curl and every zlib are two claims |
| A scan's claim stores the package identifier, the name, and a version stated outside the identifier, which joins its identity | 4.2 and 5.0 are two claims |
| A claim naming no package and its version only as a branch covers that version alone, and closes and reopens once on the first scan after the upgrade | acme-fw 4.2 leaves acme-fw 5.0 open |
| The carried patches read shows the version: "acme-fw 4.2" | |
| Reasoning given joins the identity, so a new explanation closes one claim and opens another; v0.9.0's upgrade rekeys every stored claim so none reopens | |
| The subject's name is kept as spelled and folded beside it | |

## Administrator-supplied VEX

Statements arrive by administrator upload (REQ-31), as VEX or CSAF-VEX, into
one claim shape.

| Rule | Reason |
|---|---|
| A CSAF product identifier resolves through its tree once the document closes; an undefined one is dropped, and a claim left with none is refused | |
| A composite identifier resolves through its relationship to the package, keeping the related product, for all five categories | The product places a statement in a build; one distribution VEX document composes all 1,669 of its identifiers |
| An OpenVEX product with subcomponents is kept beside each | |
| A CSAF advisory is refused here and read in § Supplier advisories | |
| The build's suppression reader reads these | One parser bounds the hostile-input surface (REQ-66) |
| A document is digested as it streams, and past the size bound refused for size before any parse error | |
| Publisher and advisory names are held without control or format characters, from request, filename or document | A right-to-left override reads reversed beside evidence |
| Re-uploading from one publisher sets aside what they no longer say, never deleting; each statement keeps its digest | Approvals stay readable |
| The same bytes again write nothing where they read as what stands, and replace it where the reader now derives differently | |
| A statement is stored against the package's decoded name, without namespace, version, qualifiers or subpath | `pkg:deb/debian/frr?arch=amd64` is `frr` |
| A shipping-inside product is stored as package identifier, folded name and version | |
| What a statement names its supplier's product as is stored: inside a named product, a product named alone, or nothing; only the first two place anything | |
| A claim repeated word for word, placed where it stood, keeps its row and takes the new digest and moment; a row stored before products were read takes its new placement | A superseded claim tells citing approvals the publisher changed their word |
| A claim moved to another release is a change | |
| A fetched advisory's digest also covers which claims were kept | |

A root-product statement is the build's own claim (REQ-11); a supplier's
statement about its own product closes the finding inside it (REQ-31);
anything else is evidence and a prefill (`design-docs/triage.md` § Evidence
from publishers).

## Supplier advisories

A supplier's CSAF advisory arrives by upload or feed
(`design-docs/ingest-suppliers.md`) and lands as a VEX document does (REQ-31).

| Rule | Reason |
|---|---|
| The profile is checked both ways, each refusal naming the path that takes it | |
| An advisory is replaced by its publisher's name for it | A publisher issues hundreds |
| Neither kind touches the other | One publisher issues both |
| No publisher or tracking identifier is refused | Both are mandatory and key supersession |
| Every product-status list is read at the versions it names | Two of eight hold every real status |
| Words attach to products named by identifier or group, groups expanded at close; an empty group scopes to nothing | Otherwise a grouped remediation lands on a claim never made |
| A CVE is the name wherever stated, others aliases; with none, the first other identifier (REQ-18) | |
| Claims return in document order | The same bytes would otherwise store different reasoning |
| A branch version is the version claimed | Dropped, one release answers for all |
| A versioned claim prefills only at its version, and shows at every version with that version beside it | The advisory names the fixed version, not the shipped one |
| Words naming products reach those products' claim | A remediation lists the upgraded packages as fixed |

A product is named as a package identifier, a package composed into a platform,
or a bare name, each with its version; a bare name matches as a source-tree
claim.

### CSAF bounds

| Bound | Charges |
|---|---|
| The component bound | Each distinct identifier, once |
| Ten times the component bound | Each entry kept: product, group, member, status listing, named product or group, alias, and every member a group reference expands to |

| Rule | Reason |
|---|---|
| A justification naming no product is no entry; a claim keeps its last | |
| A group reference is charged its expansion | 50,000 products referenced 4,000 times is 200 million entries from under a megabyte |
| The second bound defaults to about 170 MB | About 170 bytes an entry; a real kernel advisory, 794 identifiers named 220,088 times in 27 MB, spends a fifth |
| One document's claims are written in batches | `design-docs/ingest-measurements.md` § Claim writes |

## Name folding

| Rule | Reason |
|---|---|
| A component's name is folded on write into its own column, and a statement's component folded and cut alike (REQ-08) | Engines fold differently outside ASCII, and the index stays usable |
| An issue's identifier and aliases are folded alike | `LOWER` on the indexed side scanned both tables per statement: thirty seconds |

## Limits

| Limit | Detail |
|---|---|
| The range a status list implies is not read | Only enumerated versions carry a claim |
