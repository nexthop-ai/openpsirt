# Reader fixtures

What each file is, and where it came from. A fixture nobody can trace is one
nobody can tell a producer quirk from a typo in.

| File | Origin |
|---|---|
| `gomod-app.cdx.json` | Real output. This project's own inventory, emitted by the Go module producer. Its identifiers are not its package identifiers, and it states most of its structure by nesting rather than by naming edges — both of which a reader written against one producer gets wrong |
| `build-fragment.cdx.json` | Real output. One artifact a build step produced, on its way into an inventory. It names no component of its own, which is why it is refused |
| `suppression-from-patch.openvex.json` | Real output. One claim a build extracted from a patch of its own. It names a source tree rather than a package, which is what makes matching a claim to a component something that can fail |
| `image.cdx.json` | Written by hand, in the shape of the aggregate inventory a switch operating-system build emits: an image at the root, containers under it, packages under those, a shared library reached from several of them, and a forked component whose pedigree carries the version it was forked from. Not a producer's output, and not a substitute for one |
| `openpsirt-image.cdx.json` | Real output, and the only fixture at **CycloneDX 1.7**. The inventory this deployment's own image carries of itself: the scanner's description of the container, composed from its parts by the tool that builds it. It is what the image ships and what the demo ingests, so the revision every shipped inventory now states is read here by evidence rather than by construction |
| `switch-image.cdx.json.xz` | Real output, and the full-size one. The public SONiC network operating-system image, 6,866 components and 18,948 edges over 18 MB, from a build of sonic-buildimage at `5acba0313`. Compressed because the shape is the point and 18 MB of it is not. See below |
| `alpine-image.spdx.json` | Real output, and the rich **SPDX** one. syft 1.51.1 — the same producer the 1.7 CycloneDX fixture came from — scanning `alpine:3.20`. It states the root as a relationship from the document, eight spellings of one database key per package, and 77 files against 15 packages, which is what makes "a file is not a component" a rule rather than an opinion |
| `rust-app.spdx.json` | The specification's own example 11, a Rust application and its cargo dependencies. It states the root the other way — a list beside the packages, naming a package and a file built from it — and its dependency edges as `DEPENDS_ON` |
| `maven-app.spdx.json` | The specification's own example 14, a Maven application enriched by a second tool. Eleven relationships of which four are structure: the rest are a test dependency, a test case, what generated what and what the document amends. It also carries packages with no identifier at all and no version, which is what identity falling back to a name is for |

## The SPDX fixtures

Three, because no one of them is enough. The scanner's output is real and rich
and states only what that scanner states; the specification's own examples state
the shapes a single producer never emits — the other way of naming a root, a
package with no identifier, and a document whose relationships are mostly not
structure. A reader written against one of the three looks correct against one
of the three.

`rust-app.spdx.json` and `maven-app.spdx.json` come from the
[spdx-examples](https://github.com/spdx/spdx-examples) repository, under
`software/example11/spdx2.3` and `software/example14/spdx2.3`. **The SPDX
documents there are CC0-1.0**, which the repository states and each document
repeats in its own `dataLicense`. The sample source code beside them is
GPL-3.0-or-later and is not taken.

What is deliberately not here is a document converted from the other format.
One was made to see what conversion costs, and the answer is why it is not kept:
the full-size switch image's 18,948 edges become 6,830 `CONTAINS` relationships
all hanging off a single root, plus 2,767 `DEPENDENCY_OF`. The hierarchy is the
thing the fixture exists to hold, so a fixture that has lost it proves the
reader against a shape no producer emits.

The 1.7 document is deliberately uncompressed, unlike the full-size one. That
fixture skips where `xz` is missing, which is the right trade for something
kept for its scale; a fixture kept to prove a format revision is read has to
run wherever the suite does.

It brought eight paths with it, all recorded as skipped and all for the same
reason: a component's licenses, description, publisher and SWID tag are things
the scanner fills in and nothing here acts on. Identity comes from the package
identifier, the national database keys on the CPE, and neither of those is any
of these. They are named so that reading one later is a decision rather than a
discovery.

`producer-paths.txt` records every key path these documents contain and what
the reader does with it. Regenerate with `go test ./internal/sbom -update`,
which adds paths it has not seen before as deliberately skipped and leaves
every decision already made alone.


## The full-size fixture

`switch-image.cdx.json.xz` is what a real aggregate inventory looks like, and
it is here because a hand-written one cannot stand in for it. What it holds
that nothing written on purpose would:

**A graph rather than a tree.** 1,168 of its components have more than one
direct consumer, which is what makes "why is this here" a question with more
than one answer, and what a reader assuming a tree gets wrong.

**A hierarchy rather than a root with everything under it.** The image root has
30 direct children — 29 containers and the host filesystem — and the packages
installed on the host hang off the host rather than off the image. An earlier
build gave the root 5,198 direct children and left 237 components with no
consumer at all, which is a shape no reader can answer "why is this here" from.
27 are still unreached: 22 lockfile and recipe fragments the build emits
without saying what consumed them, and 5 container layer records the document
names but hangs off nothing.

**Build tooling kept apart from what ships.** 849 components sit under
`formulation` — Go and Rust dependencies harvested from inside the build
containers — rather than in `components` beside the image's contents. The
question a scanner answers is what shipped; the question a build-chain
compromise asks is what built it, and the document now answers both without
either being mistaken for the other.

**What it no longer holds is worth writing down**, because this file used to be
the evidence for a rule and is not any more. It carried the same package twice,
516 times over, spelled two ways — once with a platform identifier and an
upstream qualifier, once with only an architecture, and sometimes escaping the
`+` in a version and sometimes not. That was one producer's merge step, fixed
upstream in sonic-buildimage #29237, and this fixture now arrives as one
component per package. **So it no longer exercises the merging rule it was
originally kept for** — deleting that code entirely leaves the full-size test
passing. The rule is proved by a test that constructs the duplicates instead,
which is where a rule of this kind belongs: a fixture is somebody else's output
and can stop exercising a rule without anybody deciding it should.

**It describes the programs in the image**: twenty-one `application`
components — `/usr/bin/dockerd`, `/usr/bin/containerd`, `/usr/sbin/rest_server`,
the containerd shims, the gNMI and gNOI binaries and the rest — with the Go
modules linked into each hanging off the program rather than off the filesystem
that holds it. Four different Go runtimes appear here, and before that change
all four were children of a container or of the host with nothing saying which
program each belonged to.

**All twenty-one survive as components**, which was not true of the build
before this one. That one described thirteen programs under nine names:
`/usr/bin/dockerd`, `/usr/bin/containerd`, `/usr/bin/runc` and
`/usr/sbin/dialout_client_cli` each appeared in two images and merged into one
component apiece, because a program arrives with no version and no package
identifier and identity is a name and a version. They appeared twice because
the otel container shipped its own copies of the docker binaries, and it no
longer does.

**So this fixture no longer shows that merge**, and the property it showed is
still real: two programs of one name anywhere in a document are one component,
and what is linked into one reads as being in the other. It collapses only what
is genuinely alike — a place is a component and its direct consumer, so two
modules under two same-named programs are one place only where both ship the
same module at the same version, and a different version is a different package
identifier that cannot merge. Still not worth changing the producer for: the
only field free to distinguish them is `version`, and a scope name there is a
lie every consumer has to know to ignore. If it ever matters, the honest fix is
a hash on the program component.

It is stored compressed. The uncompressed document is 18 MB, which is a size
worth reading once in a test and not a size worth keeping in every checkout.

## A second variant of the same image

`switch-image-mellanox.cdx.json.xz` is the mellanox build of the same switch
image, compressed the same way: 6,748 components and 17,141 edges, from
sonic-buildimage at `5acba0313`. It is the
fixture that exercises a decision carrying across variants: where the chain and
the upstream versions match it reaches the other variant by lookup, and where a
version differs it is the build the guided review walks. The demo and the dev loop seed both, as two variants of one branch,
from `DEMO_BUILDS` in the Makefile.

**Both fixtures are from the same producer revision**, which is what makes them
comparable as variants. They drifted apart twice — mellanox was a build ahead
for a day, then broadcom was a build ahead for an afternoon — and each time the
difference was the same thing: whether the build describes the programs in the
image and hangs the modules compiled into them off the program. Both do now, and
both describe the same twenty-one programs under twenty-one names.

**The platform difference is what a comparison of the variants is about**, and
it is measured rather than assumed: 6,671 package identifiers in common, 54 only
in mellanox, 172 only in broadcom.

Those three numbers are byte for byte what they were at the previous shared
revision, which is worth more than either fixture on its own: it says the
producer change moved the graph above the packages and left the packages alone,
on both platforms independently. A decision carrying across variants matches on
package identity, so nothing about that behavior moved when these were retaken.

It is not yet read by any test. The full-size test reads the broadcom build,
and a second full-size read would add its cost to every run; what this one
proves — matching across variants — wants a test that constructs the two
builds small rather than one that reads sixteen megabytes twice.
