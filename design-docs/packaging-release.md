# Releases

The release assets, this project's own inventories, where a version comes from
and lands, signing, the release procedure and its notes.

Satisfies REQ-01, REQ-02, REQ-04, REQ-76.

## Contents

- [Self-inventories](#self-inventories)
- [Inventory composition](#inventory-composition)
- [Release assets](#release-assets)
- [Version sources](#version-sources)
- [Image tags and labels](#image-tags-and-labels)
- [Chart version stamping](#chart-version-stamping)
- [Signing and provenance](#signing-and-provenance)
- [The release procedure](#the-release-procedure)
- [Release notes](#release-notes)
- [Not built](#not-built)
- [Limits](#limits)

## Self-inventories

The image ships two CycloneDX inventories, because they are not the same list
(REQ-04). CycloneDX is the format this project treats as authoritative on the
way in.

| File | Describes | Produced by |
|---|---|---|
| `openpsirt.cdx.json` | What the binary ships: the modules it was linked from and the interface it embeds | The built binary's module graph, never the source, and the interface's lock file, composed under the application. The binary's build information names every module, so no checkout is needed |
| `image.cdx.json` | What the image ships | Cataloging the assembled filesystem in a later stage, since the published image does not exist until the build finishes |

| Rule | Reason |
|---|---|
| The interface's packages are read from its lock file, development dependencies left out | Neither cataloger sees into a bundle: the module reader reads Go build information, and a directory scan finds npm packages by manifests bundling leaves behind. Build tools and the test runner do not ship |
| In the image inventory the interface's packages sit inside the server's main module | The server is the binary embedding them |
| The file catalogers are off | They add a version-less, identifier-less component per path, eight hundred here, which no scanner matches, and carry the build-time scan path into a shipped document. Left are the Alpine packages, the operating system, both binaries' modules, and the interface's packages inside the server |
| musl, busybox, the certificate bundle and the bundled scanner appear only in the image inventory | They are shipped by the image and in no module graph |
| License fields are not relied on | The generator fills them unreliably; the allowlist check gates compliance (`design-docs/build-dependencies.md` § Licenses) |
| The binary's inventory is this project's first test fixture | |

## Inventory composition

| Method | Produces | Loses |
|---|---|---|
| Catalog a directory | Every package in the image | Structure inside a compiled binary: modules arrive flat, not even under the module that *is* the binary |
| Catalog one binary | A dependency graph | The image around it |

So the filesystem is cataloged with the binaries excluded, each binary is
cataloged alone, and a composer joins them, adding one edge from the image to
each component nothing else placed. Before composition the root had no children
and 345 components floated; after, the root has ten and every module sits under
its binary.

| Composer rule | Reason |
|---|---|
| A component is identified by its package identifier without the per-scan package identity, its other qualifiers in a fixed order | A module two binaries link gets a different reference and per-scan qualifier in each catalog; one component with two parents is the truth, where two would be a decision made twice. The other qualifiers, an architecture or a classifier, name which package it is |
| An input is named once, and every placement names an input | A file read twice is every component twice. A placement naming an unread file is refused |
| Everything else a producer recorded is carried through untouched | Licenses, hashes, and properties stating where something was found |
| A part can be placed inside a component another part describes | The interface's packages are inside the server binary. Placed inside a component no input describes, composing is refused |
| The root can be one part's own root | The binary's inventory stays rooted at the application its module reader named |
| The generator is pinned by version and checksum, as the scanner is | |
| The demo declares this deployment as a product and uploads both files as the `binary` and `container` variants | An evaluator sees what was written beside what ships |

## Release assets

`make dist` builds every asset into `bin/dist`. `<version>` is the tag without
its leading `v` (REQ-01 and REQ-02).

| Asset | Name | Detail |
|---|---|---|
| Container image | `ghcr.io/nexthop-ai/openpsirt:<version>` | The deployment; everything else supports it. `linux/amd64` alone (§ Not built) |
| Helm chart | `openpsirt-<version>.tgz`, pushed to `oci://ghcr.io/nexthop-ai/charts` | The registry already holding the image, so nobody hosts an index |
| Binary archive | `openpsirt_<version>_linux_<arch>.tar.gz` | The binary with `LICENSE`, `NOTICE` and `README.md`, serving the image's pages. amd64 and arm64, cross-compiled with cgo off |
| Upload client archive | `openpsirt-upload_<version>_<system>_<arch>.tar.gz`, `.zip` for Windows | The upload client with `LICENSE` and `NOTICE`, for Linux, macOS and Windows on amd64 and arm64, cgo off. A zip is what Windows opens without a tool; the release check opens each archive to find the program. See `design-docs/analysis.md` § Upload client |
| Binary inventory | `openpsirt_<version>.cdx.json` | What the binary ships |
| Image inventory | `openpsirt-image_<version>_linux_<arch>.cdx.json` | What the image ships, one per architecture, read off an assembled filesystem |
| Upload client inventory | `openpsirt-upload_<version>_<system>_<arch>.cdx.json` | One client binary's modules, the standard library among them, one per archive. The release check refuses one naming another system or architecture, or no standard library |
| Checksums | `SHA256SUMS` | Every file above, checkable without a signature |
| Signature | `SHA256SUMS.cosign.bundle` | One signature over the checksum file, which covers every asset |

Every inventory is published, never left as an expiring workflow artifact:
REQ-04 is the promise this project asks of others, kept about its own software.

## Version sources

| Rule | Reason |
|---|---|
| The tag is the only place a version is typed; `git describe` derives it and every asset takes it from there | A version written in a file is moved in one file |
| A tag is `vX.Y.Z`, and everything downstream drops the `v` | A chart version, archive name and image tag are not tags, and the chart accepts SemVer |
| `make dist` refuses an untagged or dirty tree, unless a version is named outright | Both describe as something nobody can get back to; building assets to inspect them is reasonable |
| `make dist` checks every place a version lands against the tag | An archive named `0.2.0` whose binary reports `0.1.9` makes "which version were you running" unanswerable |
| A binary for another architecture is asked its version where an emulator runs it, and named as not checked where none can | A stripped `-trimpath` binary records no linker flags to read without running it |
| The binary's inventory is told its version | A binary built here is from no module the proxy has seen, so its build information records `(devel)`, and the inventory would describe a component with no version, the field a scanner needs |

| Version reaches | By |
|---|---|
| `openpsirt -version`, the startup log, `/v1/version`, the interface footer | Stamped at link time |
| The CSAF advisory's engine, the VEX document's tooling, the parser a scan records | The same value, read at run time |
| The image tag and OCI labels | Build arguments |
| The chart's `version` and `appVersion` | Stamped at packaging |
| The image inventory | The build argument the cataloger is given |
| Every asset's file name | The variable that built it |

## Image tags and labels

| Tag | Moves |
|---|---|
| `<version>` | Never |
| `<major>.<minor>` | To the newest patch on that line |
| `latest` | To the newest release that is not a prerelease |

The labels trace an image pulled by digest to what produced it, since the
inventories carrying the version sit in a filesystem nobody has mounted. They
take the binary's build arguments, so the labels, the inventories and
`openpsirt -version` agree about one build.

| Label | Holds |
|---|---|
| `org.opencontainers.image.version` | The release |
| `org.opencontainers.image.revision` | The commit |
| `org.opencontainers.image.created` | When it was built |
| `org.opencontainers.image.source` | The repository |
| `org.opencontainers.image.vendor` | Nexthop Systems Inc. |
| `org.opencontainers.image.licenses` | `Apache-2.0` |
| `org.opencontainers.image.title`, `.description` | What it is |

## Chart version stamping

| Rule | Reason |
|---|---|
| `version` and `appVersion` are set from the tag when the chart is packaged | A committed number is the one somebody forgets to move |
| `Chart.yaml` carries `0.0.0-dev` | A chart packaged from a checkout is not a release, and names none |
| `image.tag` stays empty and falls back to `appVersion` | A chart installs the application it was packaged for; an operator wanting another passes it |

## Signing and provenance

| Rule | Reason |
|---|---|
| Signatures are keyless, cosign against the workflow's own identity | No key to hold, rotate or lose |
| The image, the chart in the registry, and the checksum file are signed | The chart is signed where it is installed from |
| Every registry reference is computed once, in lower case, and every push, signature, verification, attestation and release note reads it | A registry reference is lower case and a repository's owner and name need not be. The signing identity keeps the repository's case, which the certificate carries |
| Build provenance is an attestation naming the repository, the workflow file and the tag | It proves an asset came from this repository at that tag, never that its contents are correct, which is the inventories' and the scan's work |
| Every signature is verified in the workflow that makes it, with a third party's command and identity | Otherwise the first to test it is somebody who downloaded it |
| The release notes publish the identity to pin and the two commands checking a download | Issuer `https://token.actions.githubusercontent.com`; identity the release workflow in this repository, at a tag |

## The release procedure

A release is a tag, on a commit that froze the release's migrations. Everything
after the tag is the `Release` workflow.

1. Rehearse the upgrade from every earlier release the baseline upgrades, on
   each engine. `design-docs/database.md` § Upgrade rehearsal says what it checks.

   ```
   make engines-up
   for from in v0.7.0 v0.8.0; do for engine in sqlite postgres mysql mariadb; do
     make upgrade-rehearsal FROM=$from ENGINE=$engine || break 2
   done; done
   ```

2. Freeze the migrations on a branch from the head of `main`, and land the
   record through a pull request. `design-docs/database.md` § Release records
   says what it holds.

   ```
   git switch main && git pull && git switch -c freeze-v0.6.0
   make engines-up
   make release-freeze VERSION=v0.6.0
   ```

3. Tag the commit the merge queue put on `main`.

   ```
   git switch main && git pull
   make gate full
   make release-check VERSION=v0.6.0
   git tag -a v0.6.0 -m "0.6.0"
   git push origin v0.6.0
   ```

| The workflow | Reason |
|---|---|
| Refuses a tag not on `main` | Everything on `main` passed the merge queue; a side branch did not, and the assets are indistinguishable afterwards |
| Refuses a release whose migrations were not frozen | A database the release builds applies what it shipped. A release candidate, `-rc.N`, is held to the record of the release it precedes, and any other suffix is refused |
| Runs `make dist` | The developer's command, so a failure reproduces locally. It builds the interface, and gates the image and chart before checksumming. It is handed the version and image name the workflow pushes, so what is pushed is what was built |
| Pushes the image and the chart to `ghcr.io` | |
| Signs the image, the chart and the checksum file, then verifies each | |
| Creates the release and uploads every asset, marked Latest only where this is the newest release | GitHub marks a new release Latest unless told. The notes follow § Release notes |
| Publishes the documentation under the version, and moves `latest` and the site default where this is the newest release | |

| Rule | Reason |
|---|---|
| A version with a hyphen is a prerelease, read from the tag | `0.2.0-rc.1` is, `0.2.0` is not. The migration check accepts only a release candidate, `-rc.N` |
| A prerelease moves nothing: no `latest` or `<major>.<minor>` image tag, no documentation alias | It exists to be tried, never landed on by somebody asking for the current version |
| A fix to an older line moves nothing past a newer release | `latest`, for the image, the documentation and the repository's Latest release, moves only for the newest release, and `<major>.<minor>` only for the newest on its line; a 0.2 patch after 0.3 would otherwise hand out the older schema |
| A release is never rebuilt under its tag | The tag names one set of bytes; a fix is the next tag |
| When a step fails before anything is published, the tag is deleted on the remote and locally and tagged again | The only case a tag moves. Once assets exist under a tag, it is spent |

## Release notes

A release's notes open with what changed since the previous release, then the
image, the chart, the downloads and how to verify them. The list is GitHub's
release-notes generator, run with this tag and the previous one: one line per
pull request merged in the range, the line its title, which is why titles follow
`AGENTS.md` § Pull request descriptions.

| Release | Previous tag |
|---|---|
| Stable | The newest stable tag sorting below it by version; prereleases skipped |
| Prerelease | The newest tag of any kind sorting below it |
| The first of its kind | None; the list covers the history up to the tag |

| Rule | Reason |
|---|---|
| The workflow chooses the previous tag and names it in the request | GitHub would start at the most recent release, which for an older line's fix is newer |
| A prerelease sorts below its release | `0.1.0-rc.1` sorts below `0.1.0`, as semantic versioning orders them |
| Pull requests fall into `Changes`, then `Dependencies`, set by `.github/release.yml` | A dependency update is skimmed past |
| `Dependencies` holds every pull request Dependabot opened and every one labeled `dependencies` | A pull request matching neither group would be dropped |
| The generator needs no permission beyond `contents: write` | The job holds it to create the release |
| Notes are written once, at creation | A release is never rebuilt, and its notes are not rewritten. Releases created before the list existed carry none |

## Not built

| Not built | Detail |
|---|---|
| Multi-architecture images | The image is published for `linux/amd64` and the chart runs on `amd64` nodes. The stage cataloging what the image ships runs the cataloger at the target architecture, so an `arm64` image builds `node`, `go` and `syft` under emulation, tens of minutes. The fix is building the binary stage at the build platform and cross-compiling (`FROM --platform=$BUILDPLATFORM`, `GOARCH` from `TARGETARCH`), leaving only the cataloger emulated |
| Compatibility, which begins at 1.0 (REQ-76) | Below it the API and schema are alpha: a release exercises the whole publication path and promises no compatibility, and the schema is not collapsed into one baseline migration until then. The collapse keeps an upgrade from the last 0.x release (`design-docs/database.md` § Migrations) |

The major version says alpha, never a tag suffix, so `0.1.0` is published as a
release and moves the aliases: `latest` names the newest alpha, which is what
somebody asking for the current version should get.

## Limits

| Limit | Detail |
|---|---|
| The binary archives are a convenience | REQ-02 ships an image and a chart, and a bare binary has none of the chart's render-time refusals. Linux amd64 and arm64 alone, since nothing targets another platform and an untested archive is a support surface. The upload client is the one program built for macOS and Windows, because it runs on a build host, and CI tests it on both |
| `make dist` reads one image inventory, for its own architecture | Cataloging a foreign filesystem runs foreign binaries under emulation. The workflow publishes one per architecture it pushes; a developer wanting another names it and waits |
