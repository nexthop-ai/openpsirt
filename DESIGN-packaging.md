# Packaging and deployment

The container image, the Helm chart, and what a deployment looks like.

Satisfies REQ-01, REQ-02, REQ-04, REQ-76, and the probe behavior REQ-72
requires.

## Contents

- [Image structure](#image-structure)
- [Base version](#base-version)
- [Bundled scanner](#bundled-scanner)
- [Image and archive checks](#image-and-archive-checks)
- [Chart probes](#chart-probes)
- [Starting and stopping](#starting-and-stopping)
- [Chart security context](#chart-security-context)
- [Render-time refusals](#render-time-refusals)
- [Where a secret comes from](#where-a-secret-comes-from)
- [Self-inventories](#self-inventories)
- [Inventory composition](#inventory-composition)
- [Release assets](#release-assets)
- [Where a version comes from](#where-a-version-comes-from)
- [Image tags and labels](#image-tags-and-labels)
- [Chart version stamping](#chart-version-stamping)
- [Signing and provenance](#signing-and-provenance)
- [Cutting a release](#cutting-a-release)
- [Not built](#not-built)
- [Limits](#limits)

## Image structure

Multi-stage: the interface built with node, the binary built with the Go
toolchain the module declares, the result run on Alpine.

| | |
|---|---|
| Size | ~40 MB |
| User | Non-root, no login shell, no home directory |
| Extras | The vulnerability scanner; root certificates for outbound TLS to the ranking feeds and the scanner's data; timezone data |
| Healthcheck | Liveness only. Readiness needs the database and belongs to the orchestrator |

The interface is built inside the image rather than taken from the build
context. The Go build embeds a git-ignored directory, so an image built from a
clean checkout — which is what CI builds — carried no interface and nothing
reported it: an API-only binary is a supported build, and the embed tolerates an
empty directory. Building it here also limits the image's requirements to docker.

The binary is fully static, with CGO off, which is part of why the pure-Go
SQLite driver was chosen. `scratch` or distroless would work and carry no shell.
Alpine is used because a self-hosted operator debugging their own deployment
wants a shell.

## Base version

Every stage that is not a third-party toolchain image starts from the same build
argument, so the stages cannot drift apart. The version is pinned rather than
tracking latest: what a finding means depends on what was measured, and a base
that moves under a rebuild changes the answer.

The packages inside that release are upgraded at build time (REQ-04). This is
distinct from moving the pin. A base tag's package set is frozen when that image
was published while the distribution continues publishing fixes for it, so
pinning alone ships what was known-vulnerable on that date and keeps shipping
it.

Measured on this image the day the base moved from 3.21 to 3.24: **22 findings
against the distribution's own packages, 20 of them OpenSSL at `3.5.7-r0` with
the fix published as `3.5.8-r0`**, two of them critical, every one matched
through Alpine's own advisories rather than by comparing an identifier against an
upstream range. Upgrading cleared them. The older base had the same shape and was
less legible about it.

## Bundled scanner

The deployment runs the scan rather than trusting whatever a producer's pipeline
installed, so an image without a scanner accepts inventories it can never answer
a question about. The scanner is pinned to a version and its download is
checksummed: which build of a scanner answered is part of what a finding means.

Its vulnerability data is fetched at runtime rather than built in. A database
baked into an image is stale the day after that image is published.

That data requires a writable path and the root filesystem is read-only, so the
chart mounts a volume. The default is scratch space living as long as the pod,
which re-downloads on every start; a deployment that restarts often points it at
a claim. The image and the chart read the directory from one value in the chart.

## Image and archive checks

These are the only places these claims are tested rather than asserted.

| Check | Detects |
|---|---|
| The image runs | A build that produces an unstartable image |
| It is not running as root | A security context regression |
| The bundled scanner runs | A scanner binary that does not execute in this base |
| It serves the interface | An image built with no interface, which answers the page's path with a credential refusal rather than a page |
| The archive's binary serves the interface | The same build with no interface in it, in the form somebody runs by hand |

They run against a release as well as against a change. The image a
release publishes is built from a fresh checkout with its base upgraded as it
builds, so it is a different set of bytes from the one a merge was gated on,
and the scanner it bundles can stop working in between. A deployment that
cannot scan ingests inventories it never reads.

The archive is asked the same question as the image and in the same words, so
the two cannot drift: it is started on a port nothing else holds, with a
throwaway database, and asked for the page.

## Chart probes

| Probe | Question | Path |
|---|---|---|
| Startup | Has it finished starting? | `/readyz` |
| Liveness | Is the process running? | `/healthz` |
| Readiness | Can it serve? | `/readyz` |

Liveness does not depend on the database. Restarting a process cannot fix an
unreachable database, and a liveness probe that fails on one turns a database
outage into a restart loop on top of a database outage.

The startup probe allows ten minutes by default. Migrations run before the
service answers, and a probe that gives up part way kills the pod and restarts
the migration from the beginning.

## Starting and stopping

| Rule | Reason |
|---|---|
| Everything contacted before the server listens is under one deadline, and each step says what it is about to do | An endpoint that accepts the connection and never answers held the process for ever with no log line written and no port listening — from outside, the same thing as a slow image pull. A crash loop naming what it could not reach is the failure a supervisor can act on |
| Migrating is outside that deadline | A schema change on a large table legitimately takes longer than a deployment starts in, which is what the ten-minute startup probe above is for |
| A subcommand this does not know is refused | Ignored, a typo in a job meant to apply migrations started a server instead, against whatever schema was there |
| Ten background loops run beside the server; two of them may be absent | The mail sender where no channel is configured, and the attachment sweeper where no store is. Every other pass runs whatever a deployment has — a list rather than ten guarded starts, so what runs can be read without opening the package behind each one |
| Every exit waits for the background work, including a failure to listen | Each pass begins with a timer that fires at once, so returning early left them mid-query while the deferred close took the database away — an orderly failure to listen became failed scans and jobs retried for no reason |
| Both halves of the shutdown grace answer the same way | An overrun request made the process exit 1 and an overrun worker exit 0, while the setting that bounds them is one. A supervisor reading the exit code was told that half of an unfinished shutdown had finished |

## Chart security context

Non-root, read-only root filesystem, every capability dropped, the default
seccomp profile, and no service-account token mounted — this application never
talks to the Kubernetes API. `/tmp` is an `emptyDir` with a size limit.

The pod's termination grace is twice the process's own shutdown grace: the
process drains requests for that long and then waits the same again for a worker
mid-scan.

A SQLite URL with more than one replica is refused at render. Every replica
serves, reads and scans, coordinated through the database (REQ-03), and SQLite is
a file inside one pod. The chart sees only a URL given in values; one in an
operator's own Secret is not checked here, and the process warns at startup that
SQLite is not a production engine.

## Render-time refusals

Each fails at render with a sentence naming the problem. Rendering manifests that
cannot work moves the failure to a crash-looping pod and a message nobody reads.

| Refused | Reason |
|---|---|
| Both a managed Secret and a chart-created one for the database URL, or neither | There must be exactly one |
| No bootstrap admin | Nobody can administer the deployment |
| No sign-in provider | Naming a bootstrap admin grants a role; it does not admit anybody |
| A provider with no base URL | A provider returns somebody to an address and compares it against its registration |
| A trusted header with no sources | A header named with nothing to trust it from is a header anybody can set |
| A mail server with no address to send as | Mail configured halfway comes up healthy and sends nothing (REQ-02) |
| An address with no server | |
| A password with no username | |
| A sign-in provider with no client secret | The process refuses to start without one, so the install would render cleanly and never come up |
| An OIDC provider with no username claim | The same, and there is no default: what an authorization is redeemed against is a question only the deployment's operator can answer |
| A secret given both ways at once | The chart writes no Secret when one is named, so the value in the values file would be ignored without a word — the rule the database URL already follows |

Mail is opt-in, so refusing half of it costs a deployment that wants none of it
nothing (REQ-49).

Each refusal is tested by asserting that it fires, and the count of refusals
examined is printed, because a loop that checked nothing reads exactly like one
that found nothing wrong.

A legal install is tested the other way round, and read out of the render
rather than compared against a list: every `secretKeyRef` a legal install
produces is resolved against the Secrets that same install creates. A list
written beside the check would give a fifth secret source no row, and stay
green on the defect it exists for.

## Where a secret comes from

| Value | Where it is read from |
|---|---|
| Set in the values | A Secret the chart creates, under a key of the chart's own |
| A Secret the operator names | That Secret, under the key they name beside it |
| Both | Refused at render. One of them would be ignored, and which one is not something to leave a reader to work out |
| Neither, for the mail password | Nothing is asked for. Mail is opt-in and a server may want no credentials |
| Neither, for a sign-in provider | Refused at render, because the process refuses to start without one |

The key an operator names is read only where they also name the Secret. A
Secret the chart created holds the value under the chart's key, and asking for
the operator's key name there asks for a key that is not there — which renders
perfectly and produces a pod that never starts.

A Secret is written only while the thing that reads it is configured.
Turning a provider off by clearing its issuer used to leave the Secret behind,
holding a live credential nothing reads.

The same pair answers for the database URL, both client secrets and the mail
password, because what differs between them is the name of the Secret and the
key inside it rather than anything about how the question is answered.

Bootstrap admins are applied at every startup rather than once, which makes them
the recovery path: lose administrative access, add yourself, upgrade. The notes
printed after an install state this.

The database URL always comes from a Secret. An operator either names one they
manage or lets the chart create one from a value, with the caveat stated in the
values file that a password put there enters the release history. Mail
credentials are in the chart for the same reason.

## Self-inventories

The image ships two inventories, because they are not the same list (REQ-04).

| File | Describes | Produced by |
|---|---|---|
| `openpsirt.cdx.json` | What the binary was linked from | Reading the built binary in the build stage. Its build information names every module, so no checkout is needed; the version is passed in, because a binary built here is from no module the proxy has seen |
| `image.cdx.json` | What the image ships | Cataloging the assembled filesystem in a later stage |

musl, busybox, the certificate bundle and the bundled scanner are shipped by this
image and appear in neither the first list nor any module graph.

The image inventory is read off the assembled filesystem rather than by scanning
a published image, because the image being described does not exist until the
build finishes.

Packages, not files. The file catalogers add a component per path with no
version and no package identifier — eight hundred of them here — which no
scanner can match and no finding can hang off, and they carry the build-time
scan path into a shipped document. With them off the count is 357 components:
seventeen Alpine packages, the operating system, and the modules of both
binaries.

## Inventory composition

Neither way of cataloging answers the whole question:

| Method | Produces | Loses |
|---|---|---|
| Catalog a directory | Every package in the image | The structure inside a compiled binary. Modules arrive flat, with nothing above them, not even the module that *is* the binary |
| Catalog one binary | A dependency graph | Any knowledge of the image around it |

So the filesystem is cataloged with the binaries excluded, each binary is
cataloged separately, and a composer joins them. Nothing is inferred: each input
states what it found, and the composer adds one edge from the image to each
component nothing else placed.

Measured: before composition the root had no children and 345 components floated.
After, the root has ten and every module sits under the binary it came from.

| Composer rule | Reason |
|---|---|
| A component is identified by its package identifier with the producer's qualifiers cut | A module two binaries both link gets a different reference in each catalog. One component with two parents is the truth; two components is a count saying the image ships it twice, and a decision to be made twice |
| Everything else a producer recorded is carried through untouched | Licenses, hashes, and the properties stating where something was found. Composing rewrites references and adds one edge |

The generator is pinned by version and checksum, as the scanner is.

The demo declares this deployment as a product and uploads both files as the
`binary` and `container` variants, so an evaluator sees the difference between
what was written and what ships.

## Release assets

`make dist` builds every one of these into `bin/dist`. `<version>` is the tag
with its leading `v` removed (REQ-01 and REQ-02).

| Asset | Name | |
|---|---|---|
| Container image | `ghcr.io/nexthop-ai/openpsirt:<version>` | The deployment. Everything else here supports it. `linux/amd64` today — see below |
| Helm chart | `openpsirt-<version>.tgz`, pushed to `oci://ghcr.io/nexthop-ai/charts` | The registry that already holds the image, rather than an index somebody has to host and keep |
| Binary archive | `openpsirt_<version>_linux_<arch>.tar.gz` | The binary with `LICENSE`, `NOTICE` and `README.md`. The interface is inside the binary, so the archive serves the same pages the image does. amd64 and arm64, cross-compiled — cgo is off, so neither architecture needs a machine or an emulator of its own |
| Binary inventory | `openpsirt_<version>.cdx.json` | What the binary was linked from |
| Image inventory | `openpsirt-image_<version>_linux_<arch>.cdx.json` | What the image ships. One per architecture, because it is read off an assembled filesystem |
| Checksums | `SHA256SUMS` | Every file above, so a download is checkable without holding a signature |
| Signature | `SHA256SUMS.cosign.bundle` | One signature over the checksum file rather than one per asset: the file already covers every asset, so a verifier checks one signature and then the hashes |

Both inventories are published rather than left as a workflow artifact that
expires. We ingest these for other people's software; REQ-04 is the same
promise kept about our own, and a promise kept where somebody can see it.

## Where a version comes from

| Rule | Why |
|---|---|
| The tag is the only place a version is typed | A version written in a file is a version somebody moves in one file. `git describe` derives it, and every asset takes it from there |
| A tag is `vX.Y.Z`; everything downstream drops the `v` | A chart version, an archive name and an image tag are not tags, and SemVer is what the chart will accept |
| `make dist` refuses an untagged or dirty tree | Both describe as something nobody else can get back to. Overridable by naming a version outright, because building the assets to look at them is a reasonable thing to want |

Where it lands:

| Reaches | By |
|---|---|
| `openpsirt -version`, the startup log, `/v1/version`, the interface footer | Stamped at link time |
| The CSAF advisory's engine, the VEX document's tooling, the parser a scan records | The same value, read at run time |
| The image tag and the image's OCI labels | Build arguments |
| The chart's `version` and `appVersion` | Stamped when the chart is packaged |
| The inventory of what the image ships | The build argument the cataloger is given |
| Every asset's file name | The variable that built it |

`make dist` checks every one of those against the tag rather than assuming
them: an archive named `0.2.0` whose binary reports `0.1.9` is what makes
"which version were you running" unanswerable, and nothing else in the build
compares the two.

The binary's inventory is told its version rather than asked for it. A binary
built here comes from no module the proxy has seen, so its build information
records the main module as `(devel)` — and the document went out describing a
component with no version at all, which is the one field a scanner needs to
decide whether a release is affected.

## Image tags and labels

| Tag | Moves |
|---|---|
| `<version>` | Never |
| `<major>.<minor>` | To the newest patch on that line |
| `latest` | To the newest release that is not a prerelease |

The image carried no labels at all until releases were designed, so an image
pulled by digest could not be traced back to what produced it — and the two
inventories that do carry the version are inside a filesystem nobody has
mounted at the moment the question is asked.

| Label | Holds |
|---|---|
| `org.opencontainers.image.version` | The release |
| `org.opencontainers.image.revision` | The commit |
| `org.opencontainers.image.created` | When it was built |
| `org.opencontainers.image.source` | The repository |
| `org.opencontainers.image.vendor` | Nexthop Systems Inc. |
| `org.opencontainers.image.licenses` | `Apache-2.0` |
| `org.opencontainers.image.title`, `.description` | What it is |

They take the same build arguments the binary is stamped with, so the labels,
the inventories and `openpsirt -version` cannot disagree about one build.

## Chart version stamping

| Rule | Why |
|---|---|
| `version` and `appVersion` are set when the chart is packaged, from the tag | The committed number is the one somebody forgets to move — the failure `pins-check` exists for. Stamping at package time leaves the tag as the only thing that has to be right |
| `Chart.yaml` carries `0.1.0` as a placeholder | A chart packaged from a checkout is not a release, and should not claim to be one |
| `image.tag` stays empty and falls back to `appVersion` | A chart installs the application it was packaged for. An operator who wants another passes it |

## Signing and provenance

| | |
|---|---|
| Keyless signatures | cosign, against the workflow's own identity. No key to hold, rotate, or lose to whoever holds it next |
| What is signed | The image, the chart in the registry, and the checksum file that covers every attached asset. The chart is signed where it is installed from, which is the registry copy rather than the archive |
| Build provenance | An attestation naming the repository, the workflow file and the tag that produced the asset |
| What it proves | That an asset came out of this repository at that tag. Not that what is inside it is correct — that is what the inventories and the scan are for |

Every signature is verified in the workflow that makes it, with the
command and the identity a third party would use. A signature nobody has
verified is a signature nobody has tested, and the first person to find out is
otherwise somebody who downloaded it.

The identity to pin is published in the release notes, with the two commands
that check a download:

| | |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Identity | The release workflow in this repository, at a tag |

## Cutting a release

A release is a tag. Everything after it is the `Release` workflow, and there
is no step anybody performs by hand:

```
git switch main && git pull
make gate full
git tag -a v0.2.0 -m "0.2.0"
git push origin v0.2.0
```

| The workflow then | |
|---|---|
| Refuses a tag that is not on `main` | Everything on `main` arrived through the merge queue with the gate green. A tag on a side branch did not, and the assets are indistinguishable afterwards |
| Runs `make dist` | The same command a developer runs, so a failure reproduces locally rather than only in a log. It builds the interface first, and gates the image and the chart before checksumming anything |
| Pushes the image and the chart to `ghcr.io` | |
| Signs the image, the chart and the checksum file, then verifies each | Keyless, against the workflow's own identity, with the command a downloader would run |
| Creates the release and uploads every asset | |
| Publishes the documentation under the version | And moves `latest`, unless this is a prerelease |

| Rule | Why |
|---|---|
| A version with a hyphen is a prerelease | `0.2.0-rc.1` is, `0.2.0` is not. The workflow reads the tag rather than being told twice |
| A prerelease moves nothing | No `latest` image tag, no `<major>.<minor>` tag, no documentation alias. It exists to be tried, not to be landed on by somebody who asked for the current version |
| A release is never rebuilt under the same tag | The tag names one set of bytes. Something wrong in a published release is fixed by the next tag, not by moving this one |

When a step fails, the tag stays and the release does not exist yet. Fix what
failed, delete the tag on the remote and locally, and tag again — the only case
where a tag is allowed to move, because nothing has been published under it.
Once assets exist under a tag, that tag is spent.

## Not built

Multi-architecture images. The image is published for `linux/amd64`. The
binaries are cross-compiled for both, because cgo is off and Go needs no machine
of its own to do it — the image cannot follow, because the stage that catalogs
what it ships runs the cataloger at the target architecture, so an `arm64` image
builds `node`, `go` and `syft` under emulation. What that costs is measured in
tens of minutes, not seconds.

The fix is named rather than guessed at: build the binary stage at the build
platform and cross-compile from there (`FROM --platform=$BUILDPLATFORM`, with
`GOARCH` from `TARGETARCH`), which leaves only the cataloger emulated. It is
not done, so the manifest holds one architecture and the chart runs on
`amd64` nodes.

Compatibility begins at 1.0 (REQ-76). Below it the API and the schema are both
alpha: a release exercises the whole publication path and undertakes nothing
about upgrading from one to the next, and the schema is not collapsed into one
initial migration until then (REQ-72). What says so is the major version rather
than a suffix on the tag, which is why `0.1.0` is published as a release and
moves the aliases — `latest` has to name something, and while every version is
alpha the newest one is still what somebody asking for the current version
should get.

## Limits

- **Pinning the base means nothing moves it either.** The image carried 3.21 —
  released December 2024, support ending 2026-11-01 — until somebody looked, by
  which point it was three releases behind. Past a base's end-of-life its packages
  receive no security backports, and all of the base, the scanner and the
  inventory tool were found two or more releases behind in one week. Dependabot
  now watches what a `FROM` line names, which is the base images and the Go
  toolchain. **The scanner and the inventory tool are still watched by nobody**:
  each is a version and a checksum in a build argument, which nothing reads as a
  dependency.
- **Two builds of one commit can differ**, because the packages inside the base
  are upgraded at build time. Accepted because the image carries an inventory of
  itself, so what shipped is recorded rather than assumed.
- **The packaging gate has one implementation.** The image and chart checks were
  seven checks written twice, once in the Makefile and once in the workflow,
  neither a superset of the other. CI runs the target.
- **Pinned pairs are compared rather than trusted.** The Go toolchain, the SBOM
  generator and Node are each written in two files. The same check catches a build
  argument given two different defaults, which made a binary report one version
  and its SBOM another.
- **The binary archives are a convenience, not the product.** REQ-02 says this
  ships as an image and a chart, and a binary run bare has none of the chart's
  render-time refusals in front of it. Linux amd64 and arm64 only: nothing in the
  design targets another platform, and an archive nobody tests is a support
  surface rather than a release.
- **`make dist` reads one image inventory, for the architecture it runs on.**
  Cataloging a foreign filesystem means running foreign binaries under emulation.
  The workflow publishes one per architecture it pushes; a developer who wants
  the other names it and waits.
- **Nothing is fetched at run time from a source only this project controls**,
  and nothing is gated on a key this project issues. An operator who mirrors the
  image into their own registry has the whole thing, which is what Apache 2.0
  (REQ-01) requires of delivery.
