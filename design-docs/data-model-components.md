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

A component is a package at a version, or a container image by its name: one
row however many products ship it. Identity is derived from content (REQ-08):
the package identifier where the producer emits one, name and version otherwise,
hashed to a fixed width.

| Rule | Reason |
|---|---|
| Identifiers the file supplies are not used | They are not stable between builds or producers, and a moving identity takes its decisions with it |
| The two bases are hashed apart, each marked with which it is | A component named `pkg:npm/lodash` at `4.17.22` with no identifier is otherwise the real package's row |
| No byte inside a name or a version moves anything across: a name is prefixed with its length | Joined by `@`, the name `a@b` at `c` is `a` at `b@c`, and JSON can spell any byte, a null included |
| A package identifier is read for what it says: escapes decoded, the ecosystem lowercased, the qualifiers excluded | On a public switch image 8,374 described components named 7,858 packages, every collision one package described with and without qualifiers |
| Architecture is among the qualifiers excluded | It is already the variant |
| One reduction, the identifier specification's, for every ecosystem | Nothing here knows which producer wrote a document |

### Container images

Identified by name (REQ-08). The version a build states for an image is a tag, a
build stamp or a digest, new on every CI rebuild; SONiC stamps
`master.<build>-<commit>`.

| Producer shape | Read as an image |
|---|---|
| A package identifier of type `oci` or `docker` | Yes. SONiC, Trivy, apko |
| A package identifier of any other type | No, whatever the format calls it |
| No identifier, and a CycloneDX `container`, an SPDX 2 `CONTAINER` or an SPDX 3 `container` purpose | Yes |
| The document's own root | Already stored by name (`design-docs/data-model-graph.md` § The dependency graph) |

| Rule | Reason |
|---|---|
| An image is stored without its version, cut from the identifier and the version field alike | Its identity is the identifier with no version, the qualifiers dropped as for every component |
| The node's identifier is the build's with the version cut, qualifiers kept, rewritten in place when restated (§ Duplicate descriptions) | |
| A build stating one image name at more than one version holds no image by name and records no image version | One component is one node; each keeps its version in its identity. apko describes every layer as `image`, and a base image ships beside one built on it |
| A build stating the name once again moves it to the name, once | The version-identified node closes and the image's opens |
| Every other component keeps its version in its identity | An upgrade inside an image still supersedes its findings |
| The scanner is given an image as stored | Reports match back by identity, and the scanner matched nothing for `oci` (`design-docs/analytics-catalog.md` § Unmatched components) |
| The product a VEX statement names inside the build, and a component it is about, are named with the build's open image version | A product named with no version cannot be matched |
| A claim or statement naming an image at a version is placed against the version the build states now | The row carries none |

Identified by version and restamped nightly, a ten-build SONiC bench closed about
176,000 finding rows, opened 95,000 edges and wrote 120 to 140 MB of database a
night, with open findings flat.

#### Image versions

Beside the image's node: the format's version as stated, empty where none, and
the package identifier whole. One row per version, open across the scans that
stated it (`design-docs/data-model-graph.md` § History as intervals).

| Rule | Reason |
|---|---|
| A rebuilt image writes one version row and nothing else | |
| Restating the same version writes nothing | |
| A row closes when the build states something else, the image leaves, or the name is stated twice | |
| Recorded as given; nothing is derived from it or copies it | |

### Component references

A request names a component by name, narrowed where the name is not enough.

| Part | Needed where |
|---|---|
| Name | Always |
| Version | The build ships the name at more than one version |
| Ecosystem | A source repository and its package share a name and version |
| Namespace | One package under two namespaces: 170 names in one real switch image |

| Rule | Reason |
|---|---|
| The four parts are identity without the qualifiers | Every choice offered resolves one component |
| An empty part matches anything, except where the part before was named and exactly one match has nothing there, which the empty part then names | Such a choice is named only by leaving the part out. apko describes each package again as a directory with no identifier |
| A name matching several is refused with the choices, each carrying all four parts | |
| A name matching none is not found, looked up only once the request is authorized | |
| Where an issue is open at only one match, that one is taken | |
| Findings rows, tree nodes, rows of the tree of one's own work, steps of a way down, component packages, and the unassigned, late, disposed, blocking and decision lists carry ecosystem and namespace | A screen sends back what it was given |
| The finding and its reach, decision, assignment and labels, a component's neighbors, trend, open issues and decision about them, and a list narrowed beneath one, take all four and narrow alike | |

## Upstream name and version

Carried beside identity (REQ-18): a fork's vulnerability lives on the upstream
version, and a build's suppressions use the upstream name.

| Rule | Reason |
|---|---|
| Both producer spellings are read: the format's field and the package identifier's | In the measured image 30 components use the first, 537 the second, 16 both |
| A bare upstream name with no version is kept | For a binary from a differently named source it is all that is knowable |

## The fold

The binaries one source package was built into at one version are one thing to
a person: curl, libcurl4t64 and libcurl3t64 are one bump. Every component
carries a fold key, written when first stored.

| Part of the key | Separates |
|---|---|
| Package type | The Debian `python3-protobuf` and the PyPI `protobuf` |
| Distribution release | Debian's busybox at `1:1.37.0-6+b8` and Alpine's at `1.37.0-r31` |
| Source package | The binaries cut from it |
| Version it was built at | One source shipped twice in one build |

| Rule | Reason |
|---|---|
| All four parts | On the demo all four fold 41 groups and none disagree; the name alone folds 72 and 14 disagree. A kernel image at 6.12.41-1 carries 5,088 issues beside perf and headers at 6.12.107-1 carrying 607 and none |
| It groups and never identifies | Identity, a finding's occurrence key (REQ-17) and a decision's expiry on its version (REQ-25) never move with it |
| Written on the way in, read as an indexed column | |
| Hashed | A bounded readable key merges two sources, and one decision then writes across both |
| A component stating no source package is its own fold | 564 of 786 Debian packages, 10 of 18 Alpine, 2 of 188 PyPI, none of 1,684 Go or 3,880 generic state one |
| Folded for capitals here | The engines fold differently outside ASCII |
| Each part cut to a number of characters | Columns are declared in characters; a byte cut folds names differing past it and can split a character |
| The disposition register and VEX and CSAF statements are not folded | They name the binary a customer received |
| The graph is not folded at ingest | 82 of 117 groups hold binaries with different parents and 54 live edges run within one source, so a folded graph answers "what pulls this in" wrongly and grows cycles |

## Duplicate descriptions

A document describing one package twice describes one component: keeping the
first discards the vulnerability-database identifier for 204 components in the
measured image. The first statement of anything stands, and what it left out is
taken from the next description stating it. The row is shared across products,
and a pipeline key is scoped to one, so across reports the rule is scoped to one
product.

| Rule | Reason |
|---|---|
| The row holds what the first report stated; no later report writes its identifiers | One product's `distro=debian-13` matched another's Debian 12 package against the wrong advisories |
| What a build states for matching is held on its node: the package identifier with qualifiers, the platform enumeration, the source package and its version | Two products ship one version built for two releases |
| The scanner is given the node's statement, gaps filled from other builds of the same product, earliest first; a build's claim is matched against the same | Matched against the row, a claim misses a binary another product described first |
| A VEX statement names the component by the node's identifier | |
| Nothing stated is overwritten; qualifiers compare key by key ignoring capitals | |
| The supplier and the license fill in on the row where it has none | `design-docs/findings-components.md` § Component suppliers |
| The repository a build states is held on its node without credential or query, never filled from another build | `design-docs/analysis.md` § Placement |
| Restating an identifier writes the node in place and opens and closes nothing | |
| The fold key never moves after first storage | An upgrade commitment keyed on it keeps its coverage |
| Captured at ingest | A scan file is not kept |

| Filled in from a build of the same product | Reason |
|---|---|
| A package-identifier qualifier, key by key | `distro` selects a distribution's advisories and `upstream` its source package's: `pkg:deb/sonic/linux-image…?arch=amd64` matched nothing, and with `distro=debian-13&upstream=linux` matches the Debian kernel's |
| The platform enumeration | A second matching identifier for firmware and appliances, kept out of identity |
| The source package and its version | |

## Limits

| Limit | Detail |
|---|---|
| A component's row and fold are what its first report stated | A later source package or distribution reaches that product's scanner, claims and closure explanations from the node, never the fold, a decision's expiry, an assignment rule or a search by name. A package first described without its source folds on its own name everywhere |
| Two artifacts distinguished only by a qualifier are one component | |
| An image with no package identifier in a database v0.8.0 built is not recognized by the upgrade | Its next upload stores it by name once, as a version moving would (`design-docs/database.md` § The v0.9.0 upgrade) |
| An image's version is shown on the component screen alone | |
| Where an issue sits, and the disclosure queue, link to a finding by name and version alone | Two components of that name and version land on the choice |
