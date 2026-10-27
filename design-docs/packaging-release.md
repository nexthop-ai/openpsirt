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

The image ships two CycloneDX inventories, which list different things (REQ-04).
CycloneDX is the format this project treats as authoritative on the way in.

| File | Describes | Produced by |
|---|---|---|
| `openpsirt.cdx.json` | What the binary ships: its linked modules and embedded interface | The built binary's module graph, never the source, plus the interface's lock file, composed under the application |
| `image.cdx.json` | What the image ships | Cataloging the assembled filesystem in a later stage, since the image does not exist until the build ends |

| Rule | Reason |
|---|---|
| The interface's packages come from its lock file, development dependencies left out | Neither cataloger sees into a bundle |
| In the image inventory they sit inside the server's main module | The server embeds them |
| The file catalogers are off | They add a version-less component per path, eight hundred here, matchable by nothing, and leak the build path |
| musl, busybox, the certificate bundle and the scanner appear only in the image inventory | No module graph holds them |
| License fields are not relied on | The generator fills them unreliably; the allowlist gates compliance (`design-docs/build-dependencies.md` § Licenses) |
| The binary's inventory is this project's first test fixture | |

## Inventory composition

| Method | Produces | Loses |
|---|---|---|
| Catalog a directory | Every package in the image | A binary's structure: modules arrive flat, not even under the binary's own module |
| Catalog one binary | A dependency graph | The image around it |

The filesystem is cataloged with the binaries excluded, each binary alone, and a
composer joins them. Nothing is inferred: each input states what it found, and
the composer adds one edge from the image to each component nothing else
placed. Before composition the root had no children and 345 components floated;
after, the root has ten and every module sits under its binary.

| Composer rule | Reason |
|---|---|
| A component is identified by its package identifier minus the per-scan package identity, other qualifiers in a fixed order | A module two binaries link is one component with two parents. Other qualifiers, such as an architecture, name which package it is |
| Each input is named once, and every placement names an input | A file read twice doubles everything; a placement naming an unread file is refused |
| Everything else a producer recorded passes untouched: licenses, hashes, location properties | Composing rewrites references and adds one edge |
| A part can be placed inside a component another part describes | The interface sits inside the server; a component no input describes is refused |
| The root can be one part's own root | The binary's inventory stays rooted at its application |
| The generator is pinned by version and checksum | |
| The demo uploads both files as the `binary` and `container` variants of this deployment | An evaluator sees written against shipped |

## Release assets

`make dist` builds every asset into `bin/dist`. `<version>` is the tag without
its `v` (REQ-01 and REQ-02).

| Asset | Name | Detail |
|---|---|---|
| Container image | `ghcr.io/nexthop-ai/openpsirt:<version>` | The deployment. `linux/amd64` alone (§ Not built) |
| Helm chart | `openpsirt-<version>.tgz`, at `oci://ghcr.io/nexthop-ai/charts` | The image's registry, so no index to host |
| Binary archive | `openpsirt_<version>_linux_<arch>.tar.gz` | The binary, serving the image's pages, with `LICENSE`, `NOTICE` and `README.md`. amd64 and arm64, cross-compiled, cgo off |
| Upload client archive | `openpsirt-upload_<version>_<system>_<arch>.tar.gz`, `.zip` for Windows | With `LICENSE` and `NOTICE`, for Linux, macOS and Windows on amd64 and arm64. The release check opens each to find the program. See `design-docs/analysis-client.md` § Upload client |
| Binary inventory | `openpsirt_<version>.cdx.json` | |
| Image inventory | `openpsirt-image_<version>_linux_<arch>.cdx.json` | One per architecture |
| Upload client inventory | `openpsirt-upload_<version>_<system>_<arch>.cdx.json` | One per archive, refused if it names another system or architecture or lacks the standard library |
| Checksums | `SHA256SUMS` | Every file above |
| Signature | `SHA256SUMS.cosign.bundle` | One signature over the checksums |

Every inventory is published, never an expiring workflow artifact, keeping
REQ-04 for this project's own software.

## Version sources

| Rule | Reason |
|---|---|
| The tag is the only typed version; `git describe` derives it for every asset | |
| A tag is `vX.Y.Z`; everything downstream drops the `v` | The chart takes SemVer |
| `make dist` refuses an untagged or dirty tree unless a version is named | |
| `make dist` checks every place a version lands against the tag | An archive `0.2.0` reporting `0.1.9` is untraceable |
| A foreign-architecture binary is asked its version under an emulator, or named unchecked where none runs | A stripped `-trimpath` binary must run to report its stamp |
| The binary's inventory is told its version | Its build information says `(devel)`, leaving the component versionless |

| Version reaches | By |
|---|---|
| `openpsirt -version`, the startup log, `/v1/version`, the interface footer | Link-time stamp |
| The CSAF engine, the VEX tooling, the parser a scan records | The same value at run time |
| The image tag and OCI labels | Build arguments |
| The chart's `version` and `appVersion` | Stamped at packaging |
| The image inventory | The cataloger's build argument |
| Every asset's file name | The variable that built it |

## Image tags and labels

| Tag | Moves |
|---|---|
| `<version>` | Never |
| `<major>.<minor>` | To the newest patch on that line |
| `latest` | To the newest non-prerelease |

The labels trace an image pulled by digest to its source, and share the binary's
build arguments, so labels, inventories and `openpsirt -version` agree.

| Label | Holds |
|---|---|
| `org.opencontainers.image.version` | The release |
| `org.opencontainers.image.revision` | The commit |
| `org.opencontainers.image.created` | Build time |
| `org.opencontainers.image.source` | The repository |
| `org.opencontainers.image.vendor` | Nexthop Systems Inc. |
| `org.opencontainers.image.licenses` | `Apache-2.0` |
| `org.opencontainers.image.title`, `.description` | What it is |

## Chart version stamping

| Rule | Reason |
|---|---|
| `version` and `appVersion` are stamped from the tag at packaging | A committed number gets forgotten |
| `Chart.yaml` carries `0.0.0-dev` | A checkout's chart is no release |
| `image.tag` is empty, falling back to `appVersion` | |

## Signing and provenance

| Rule | Reason |
|---|---|
| Signatures are keyless cosign, against the workflow's identity | No key to lose |
| The image, the registry chart and the checksum file are signed | The chart is signed where it installs from |
| Registry references are computed once, lower-cased, and read by every push, signature, verification, attestation and note | Owners and names may have capitals; the signing identity keeps the repository's case, as the certificate does |
| Provenance attests the repository, workflow file and tag | It proves origin, never correctness |
| Each signature is verified in its workflow with a third party's command and identity | |
| The release notes publish the identity and the two verification commands | Issuer `https://token.actions.githubusercontent.com`; identity the release workflow here, at a tag |

## The release procedure

A release is a tag on a commit that froze its migrations; the `Release`
workflow does the rest.

1. Rehearse the upgrade from every earlier release the baseline upgrades, on
   each engine. `design-docs/database-migrations.md` § Upgrade rehearsal says what it checks.

   ```
   make engines-up
   for from in v0.7.0 v0.8.0; do for engine in sqlite postgres mysql mariadb; do
     make upgrade-rehearsal FROM=$from ENGINE=$engine || break 2
   done; done
   ```

2. Freeze the migrations on a branch from the head of `main`, and land the
   record through a pull request. `design-docs/database-migrations.md` § Release records
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
| Refuses a tag not on `main` | Only `main` passed the merge queue |
| Refuses unfrozen migrations; a candidate, `-rc.N`, is held to its release's record, and other suffixes are refused | A release's databases apply what it shipped |
| Runs `make dist`, handed the version and image name it pushes | A failure reproduces locally, and what is pushed is what was built |
| Pushes the image and chart to `ghcr.io` | |
| Signs and verifies the image, chart and checksum file | |
| Creates the release with every asset, marked Latest only when newest | GitHub would mark every release Latest |
| Publishes the documentation under the version, moving `latest` and the default when newest | |

| Rule | Reason |
|---|---|
| A hyphenated version is a prerelease; the migration check accepts only `-rc.N` | |
| A prerelease moves no `latest` or `<major>.<minor>` tag and no documentation alias | It is for trying |
| `latest`, for image, documentation and repository, moves only for the newest release, and `<major>.<minor>` for the newest on its line | A 0.2 patch after 0.3 would hand out the older schema |
| A release is never rebuilt under its tag | A fix is the next tag |
| A failed release with nothing published is retagged after deleting the tag on the remote and locally; once assets exist the tag is spent | |

## Release notes

Notes open with the changes since the previous release, then the image, chart,
downloads and verification. The change list is GitHub's generator over this tag
and the previous one, one line per merged pull request, its title, so titles
follow `AGENTS.md` § Pull request descriptions.

| Release | Previous tag |
|---|---|
| Stable | The newest stable tag below it by version |
| Prerelease | The newest tag of any kind below it |
| The first of its kind | None; the whole history |

| Rule | Reason |
|---|---|
| The workflow chooses and names the previous tag | GitHub would pick the latest release, newer for an old line's fix |
| A prerelease sorts below its release | Semantic versioning order |
| Groups are `Changes`, then `Dependencies`, set by `.github/release.yml` | |
| `Dependencies` takes every Dependabot pull request and every one labeled `dependencies` | A pull request matching no group is dropped |
| The generator needs only `contents: write` | |
| Notes are written once; releases before the list carry none | |

## Not built

| Not built | Detail |
|---|---|
| Multi-architecture images | The image is `linux/amd64` and the chart runs on `amd64` nodes. The inventory stage runs the cataloger at the target architecture, so `arm64` builds `node`, `go` and `syft` under emulation, for tens of minutes. The fix: build the binary stage at the build platform and cross-compile (`FROM --platform=$BUILDPLATFORM`, `GOARCH` from `TARGETARCH`), emulating only the cataloger |
| Compatibility, which begins at 1.0 (REQ-76) | Below it the API and schema are alpha: releases exercise the publication path and promise no compatibility, and the schema is collapsed into one baseline only then, keeping an upgrade from the last 0.x release (`design-docs/database-migrations.md` § Migrations) |

The major version marks alpha, never a tag suffix, so `0.1.0` is a release and
moves the aliases: `latest` names the newest alpha.

## Limits

| Limit | Detail |
|---|---|
| The binary archives are a convenience | REQ-02 ships an image and chart, and a bare binary lacks the chart's refusals. Linux amd64 and arm64 only; the upload client alone is built for macOS and Windows, since it runs on build hosts, and CI tests both |
| `make dist` reads one image inventory, for its own architecture | A foreign filesystem needs emulation. The workflow publishes one per pushed architecture |
