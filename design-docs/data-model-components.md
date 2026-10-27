# Components

What a component is, how its identity is derived, how a request names one, and
what is kept when a build describes it twice.

Satisfies REQ-08, REQ-17, REQ-18, REQ-25.

## Contents

- [Component identity](#component-identity)
- [Upstream name and version](#upstream-name-and-version)
- [The fold](#the-fold)
- [Duplicate descriptions](#duplicate-descriptions)
- [Limits](#limits)

## Component identity

A component is a package at a version, or a container image by its name. One
row, however many products ship it. Identity is derived from what it is (REQ-08):
the package identifier where the producer emits one, name and version where it
does not, hashed to a fixed width.

| Rule | Reason |
|---|---|
| Identifiers the file supplies are not used | Nothing keeps them stable between builds or consistent between producers, and an identity that moves takes its decisions with it |
| The two bases are hashed apart, each marked with which it is | A component named `pkg:npm/lodash` at `4.17.22` with no identifier is otherwise the real package's row, and whichever arrives first decides for every product whether that row carries a matchable identifier |
| A name is prefixed with its length | Joined by `@`, the name `a@b` at `c` is `a` at `b@c`; a producer's JSON can spell any byte, a null included |
| A package identifier is read for what it says: escapes decoded, the ecosystem lowercased, the qualifiers excluded | On a public switch image 8,374 described components named 7,858 packages, and all 516 collisions were one name at one version described twice, with and without qualifiers. Verbatim, each package counts twice and its findings split |
| Architecture is among the qualifiers excluded | What a product is built as is already the variant |
| One reduction, the identifier specification's, for every ecosystem | Nothing here knows which producer wrote a document |

### Container images

A container image is identified by its name (REQ-08). The version a build states
for one is a tag, a build stamp or a digest, new on every CI rebuild whether or
not anything inside moved. SONiC stamps each image `master.<build>-<commit>`.

| Producer shape | Read as an image |
|---|---|
| A package identifier of type `oci` or `docker` | Yes. SONiC, Trivy, apko |
| A package identifier of any other type | No, whatever the format calls the component |
| No identifier, and a CycloneDX component of type `container` | Yes |
| No identifier, and an SPDX 2 primary purpose `CONTAINER` or SPDX 3 `container` | Yes |
| The document's own root | Already stored by its name (`design-docs/data-model-graph.md` § The dependency graph) |

| Rule | Reason |
|---|---|
| An image is stored without its version | The version is cut from the identifier and the version field alike; identity is the identifier with no version, qualifiers dropped as for every component |
| The node's identifier is the build's, with the version cut | It holds the qualifiers the build stated, rewritten in place when restated (§ Duplicate descriptions) |
| A build stating one image name at two versions has no image by name | One component is one node. Each keeps its version in its identity, as a package does. apko describes every layer as an image named `image`, and a base image ships beside an image built on it |
| A build stating the name once again moves it to the name, once | The version-identified node closes and the image's node opens, as a version moving would |
| Every other component keeps its version in its identity | An upgrade inside an image still closes the old node and supersedes its findings |
| The scanner is given an image as stored, name and versionless identifier | Reports match back by identity, and no vulnerability data is published against a build stamp: the scanner matched nothing for the `oci` type (`design-docs/analytics-catalog.md` § Unmatched components) |
| A VEX statement names an image as the build stamped it | The image is read with the build's open image version, since a product named with no version is one a reader cannot match |
| A claim or statement naming an image at a version is placed against the version the build states now | The component row carries no version, so the build's image versions answer |

On a ten-build SONiC bench with every image identified by its version and
restamped nightly, about 176,000 finding rows closed, 95,000 edges opened and
120 to 140 MB were written a night, with open findings flat.

#### Image versions

Kept beside the image's node: the format's version as stated, empty where none,
and the package identifier whole. One row per version stated, open across the
scans that stated it (`design-docs/data-model-graph.md` § History as intervals).

| Rule | Reason |
|---|---|
| A rebuilt image writes one version row and nothing else | Its node, edges and findings stay |
| Restating the same version writes nothing | An unchanged build writes nothing |
| A version row closes when the build states something else, the image leaves, or the build states its name twice | Its interval is the scans that stated it |
| Recorded as given | Nothing is derived from it and nothing else holds a copy |

### Component references

A request names a component as a reader does: by name, narrowed where the name
is not enough.

| Part | Needed where |
|---|---|
| Name | Always |
| Version | The build ships the name at more than one version |
| Ecosystem | A source repository and the package built from it share a name and a version |
| Namespace | One package is described under two namespaces: 170 names in one real switch image, as the distribution's and the producer's own |

| Rule | Reason |
|---|---|
| The four parts are identity without the qualifiers | Every choice a refusal offers resolves exactly one component |
| A part left empty matches anything | A caller that never meets the ambiguity sends nothing more |
| Except where the part before it was named and exactly one match has nothing in it, which that empty part then names | A choice with an empty part can be named only by leaving it out. apko describes each package again as a directory with no identifier at the same name and version. A name alone still matches every component of that name |
| A name matching several is refused with the choices, each carrying all four parts | A choice missing one leads back to the refusal |
| A name matching none is not found, looked up only once the request is authorized | Otherwise the refusal says what an unreadable build holds |
| Where an issue is open at only one match, that one is taken | One choice is not a choice |
| Findings rows, tree nodes, rows of the tree of one's own work, steps of a way down, component packages, and the unassigned, late, disposed, blocking and decision lists carry ecosystem and namespace | A screen sends back only what it was given |
| The finding and its reach, decision, assignment and labels, a component's neighbors, trend, open issues and decision about them, and a list narrowed beneath one, take all four and narrow alike | A route taking fewer resolves a name the others refuse |

## Upstream name and version

Carried beside identity (REQ-18). A shipped fork has a version of its own while
the vulnerability lives on the upstream one, and a build's suppressions use the
upstream name, because a patch is written against a source tree.

| Rule | Reason |
|---|---|
| Both producer spellings are read: the format's own field and the package identifier's | In the measured image 30 components state it the first way and 537 the second, 16 both |
| A bare upstream name with no version is kept as an answer | For a binary cut from a differently named source it is all that is knowable, and the half claim matching needs |

## The fold

The binaries one source package was built at one version are one thing to a
person: curl, libcurl4t64 and libcurl3t64 are one bump. Every component carries
a fold key, written when it is first stored.

| Part of the key | Separates |
|---|---|
| Package type | The Debian `python3-protobuf` and the PyPI `protobuf` |
| Distribution release | Debian's busybox at `1:1.37.0-6+b8` and Alpine's at `1.37.0-r31` |
| Source package | The binaries cut from it, which is the grouping |
| Version it was built at | One source shipped twice in one build |

| Rule | Reason |
|---|---|
| All four parts | On the demo, all four fold 41 groups with no binaries disagreeing about issues or fixes; the name alone folds 72 and 14 disagree. A kernel image at 6.12.41-1 carries 5,088 issues beside perf and headers at 6.12.107-1 carrying 607 and none |
| It groups and never identifies | Identity stays content-derived (REQ-08), a finding keyed on its occurrence (REQ-17), and a decision keyed on its occurrence and expiring on its own version (REQ-25). A producer starting to state a source package moves the grouping and no record |
| Written on the way in and read as a column | One key, grouped on an index |
| Hashed | A readable key bounded for an index merges two source packages agreeing to the bound, and one decision over the fold writes rows across both |
| A component stating no source package is its own fold | Coverage is thin: 564 of 786 Debian packages, 10 of 18 Alpine, 2 of 188 PyPI, none of 1,684 Go or 3,880 generic |
| Folded for capitals here | The four engines fold differently outside ASCII |
| Each part cut to a number of characters | Indexed name columns are declared in characters; a byte cut shortens a three-byte script to a third, folds names differing past it, and can split a character into invalid UTF-8 |
| The disposition register and VEX and CSAF statements are not folded | They name the binary a customer received |
| The graph is not folded at ingest | 82 of 117 groups hold binaries with different parents (`libcurl3t64-gnutls` has 30, `libcurl4t64` and `curl` one each), and 54 live edges run within one source, so a folded graph answers "what pulls this in" wrongly and acquires cycles |

## Duplicate descriptions

A document describing one package twice describes one component, not always the
same way: keeping whichever arrives first discards the vulnerability-database
identifier for 204 components in the measured image. The first statement of
anything stands, and what it left out is taken from the next description that
states it. Nothing is overwritten, because a reader cannot settle two producers
disagreeing.

The component row is shared by every product, and a pipeline key is scoped to
one, so across reports the rule is scoped to one product.

| Rule | Reason |
|---|---|
| The row holds what the first report stated; no later report writes its identifiers | One product's `distro=debian-13` on the shared row matched another product's Debian 12 package against the wrong release's advisories |
| What a build states for matching is held on its node: the package identifier with qualifiers, the platform enumeration, the source package and its version | Two products ship one package version built for two distribution releases |
| The scanner is given the node's statement, with what the build left out taken from other builds of the same product, earliest first | One product describes one package one way |
| A build's claim is matched against what its scanner was given | Matched against the row, the build's claim about a source tree stops covering a binary another product described first |
| A VEX statement names the component by the node's identifier | |
| Nothing stated is overwritten; qualifiers compare key by key ignoring capitals | The build's own statement stands |
| The supplier and the license fill in on the row where it has none | Neither reaches a scanner. `design-docs/findings-components.md` § Component suppliers |
| The repository a build states a component is built from is held on its node, without credential or query, never filled from another build | It places an analyzer's result (`design-docs/analysis.md` § Placement); another build's repository is a guess |
| A build restating an identifier writes its node in place and opens and closes nothing | The component has not changed; every other node of an unchanged build is left alone |
| The fold key never moves after the component is first stored | An upgrade commitment keyed on the fold keeps covering what it covered |
| Captured at ingest | A scan file is not kept once read |

| Filled in from a build of the same product | Reason |
|---|---|
| A package-identifier qualifier, key by key | `distro` selects a distribution's advisories and `upstream` its source package's: a kernel stored as `pkg:deb/sonic/linux-image…?arch=amd64` matched nothing, and with `distro=debian-13&upstream=linux` matches the Debian kernel's |
| The platform enumeration | The second identifier a scanner matches on, for firmware, operating systems and appliances. Kept out of identity, which would otherwise move for every component carrying one |
| The source package and its version | What selects a source package's advisories |

## Limits

| Limit | Detail |
|---|---|
| A component's row, and its fold, are what the first report of it stated | A later report's source package or distribution reaches that product's scanner, claims and closure explanations from the node, and never the fold, a decision's expiry, an assignment rule or a search by name, which read the row. A package first described without its source folds on its own name in every product |
| Two artifacts distinguished only by a package qualifier are one component | A qualifier does not change which vulnerabilities apply |
| An image with no package identifier in a database v0.8.0 built is not recognized by the upgrade | Nothing recorded that the format called it a container. Its next upload stores it by name, once, as a version moving would (`design-docs/database.md` § The v0.9.0 upgrade) |
| An image's version is shown on the component screen alone | The tree, findings list, chains and comparisons show it as stored, with no version |
| Where an issue sits, and the disclosure queue, link to a finding by name and version alone | The first groups occurrences by component name; where a build holds that name and version as two components, the link lands on the choice |
