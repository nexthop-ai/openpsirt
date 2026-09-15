# The base every stage that is not somebody else's toolchain image starts from.
# Declared here because an argument a `FROM` line reads has to be declared
# before the first one, and pinned in one place so three stages cannot drift
# apart.
#
# **It has an end-of-life date and somebody has to move it.** 3.21, which this
# carried until now, shipped in December 2024 and stops being supported on
# 2026-11-01 — after which its packages get no security backports, and this
# tool would report unfixable findings against its own image and be right about
# them. 3.24 shipped 2026-06-09 and is supported to 2028-06-01.
#
# Pinned rather than tracking latest for the reason the scanner is pinned: what
# a finding means depends on what was measured, and a base that moves under a
# rebuild changes the answer without anybody asking it to.
ARG ALPINE_VERSION=3.24

# The interface, built here rather than taken from the build context.
#
# The Go build embeds whatever `internal/webui/dist` holds, and that directory
# is git-ignored — so building this image from a clean checkout produced an
# image with no interface in it at all, which is what CI was testing. Nothing
# said so, because an API-only binary is a supported build and the embed
# tolerates an empty directory on purpose.
#
# Building it here also means the image needs nothing of the builder's machine
# but docker, which is what lets one command stand a working instance up.
FROM node:26-alpine AS web

WORKDIR /web

# The lockfile first, so a source-only change does not reinstall. `npm ci`
# installs exactly what is pinned rather than re-resolving ranges, for the same
# reason every other tool here is pinned.
COPY web/package.json web/package-lock.json ./
RUN npm ci

# The one copy of the logos, which the brand files under web/public are
# symlinks to. The link targets are relative to the repository root, and this
# stage's /web stands in for the repository's web/ — so the copy has to land at
# /assets for them to resolve. Without it the build fails on a stat of a
# dangling link rather than on anything it could explain, because vite copies
# the public directory by walking it.
COPY assets/ /assets/

# The shared XSS corpus, for the same reason and by the same arithmetic: the
# interface's tsconfig includes `../testdata/*.json`, which against this
# stage's /web is /testdata. The server's submission check reads the same file,
# which is the point of it — one corpus, not two that drift.
#
# **The gate cannot catch a missing copy here.** `make check` type-checks from
# a checkout where every path resolves, and `check-packaging` — which builds
# this image — is skipped by it because it needs docker. So a path added to the
# interface's tsconfig that reaches outside web/ breaks this build with the
# gate green, and the way it is noticed is the image failing to build.
COPY testdata/ /testdata/

COPY web/ ./
RUN npm run build

# Build. Pinned to the same Go the module asks for.
FROM golang:1.27.1-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The interface, which the build context no longer carries: both interface
# build directories are excluded there, because copying one in and writing over
# it does not replace it. A chunk's name carries a content hash, so a stale
# chunk does not collide with the new one beside it — it survives, embedded and
# reachable by address, referenced by nothing.
COPY --from=web /web/dist/ ./internal/webui/dist/

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# CGO off gives a static binary, which is what lets the runtime image be this
# small — and is why the pure-Go SQLite driver was chosen.
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags "-s -w \
        -X 'github.com/nexthop-ai/openpsirt/internal/version.version=${VERSION}' \
        -X 'github.com/nexthop-ai/openpsirt/internal/version.commit=${COMMIT}' \
        -X 'github.com/nexthop-ai/openpsirt/internal/version.date=${DATE}'" \
      -o /out/openpsirt ./cmd/openpsirt

# The inventory of what this image ships (SCP-08), read from the built binary
# rather than from the source tree (SCP-09): the build information the binary
# carries names every module it was linked from, so no checkout is needed —
# the build context carries no git history. It travels in the image so that a
# deployment can be its own first product: the demo uploads it, and an
# operator evaluating the tool has a second product to look at without owning
# a build pipeline.
#
# The version is passed rather than read. A binary built here is not built
# from a module the proxy has ever seen, so its build information records the
# main module as "(devel)" and the document went out describing a component
# with no version at all — the one field a scanner needs to answer whether a
# release is affected.
ARG CDXGOMOD_VERSION=v1.12.0
RUN CGO_ENABLED=0 go build -trimpath -o /out/compose ./internal/tools/compose
RUN go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@${CDXGOMOD_VERSION} \
      bin -json -version "${VERSION}" -output /out/openpsirt.cdx.json /out/openpsirt

# Run.
#
# The binary is static, so this could be scratch or distroless and carry no
# shell at all. Alpine is chosen deliberately: a self-hosted operator debugging
# their own deployment wants a shell, and that is worth the few megabytes and
# the surface it adds.
# The vulnerability scanner. This deployment runs the scan rather than trusting
# whatever a producer's pipeline happened to install, so an image without one
# takes in inventories it can never answer a question about.
#
# Pinned and checksummed. Which scanner build answered is part of what a
# finding means — counts are only comparable between products measured the same
# way — so "whatever was latest at build time" is not good enough.
FROM alpine:${ALPINE_VERSION} AS scanner
ARG GRYPE_VERSION=0.118.0
ARG TARGETARCH=amd64
RUN apk add --no-cache curl ca-certificates \
 && case "${TARGETARCH}" in \
      amd64) expected=1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2 ;; \
      arm64) expected=32aceeb8ee837244775fcb522372c8b3a47914986385f3148f4ee2c930482a84 ;; \
      *) echo "no pinned checksum for ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/grype.tar.gz \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && echo "${expected}  /tmp/grype.tar.gz" | sha256sum -c - \
 && mkdir -p /out \
 && tar -xzf /tmp/grype.tar.gz -C /out grype \
 && chmod 0755 /out/grype

# The generator for the second inventory: what the whole image ships, rather
# than what the binary was linked from.
#
# Pinned by version and checksum, the same way the scanner is, and from the
# same project — a build that fetches an unpinned tool over the network is a
# build whose output depends on a day.
FROM alpine:${ALPINE_VERSION} AS inventory-tool
ARG SYFT_VERSION=1.51.1
ARG TARGETARCH=amd64
RUN apk add --no-cache curl ca-certificates \
 && case "${TARGETARCH}" in \
      amd64) expected=8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3 ;; \
      arm64) expected=a7fd2b784e6664acd44719270574f6cd8c6864fc2b1700bf9099bd1cccda7d7f ;; \
      *) echo "no pinned checksum for ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/syft.tar.gz \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && echo "${expected}  /tmp/syft.tar.gz" | sha256sum -c - \
 && mkdir -p /out \
 && tar -xzf /tmp/syft.tar.gz -C /out syft \
 && chmod 0755 /out/syft

FROM alpine:${ALPINE_VERSION} AS runtime

# The packages this inherits from the base are upgraded before anything is
# added to them (SCP-17).
#
# A base tag's package set is frozen at the moment that image was published,
# and the distribution goes on publishing fixes for it — so pinning the base
# and stopping there ships whatever was known-vulnerable on that date, forever.
# Measured on ourselves the day the base moved to 3.24: twenty-two findings
# against the distribution's own packages, twenty of them OpenSSL at 3.5.7-r0
# with the fix published as 3.5.8-r0, two of those critical, every one matched
# through Alpine's own advisories rather than guessed at.
#
# What it costs is that two builds of one commit can differ. That is accepted
# rather than overlooked: the image carries an inventory of itself, so what
# actually shipped is recorded rather than assumed, and the drift is a thing
# somebody can read instead of a thing nobody can see.
#
# Outbound TLS needs root certificates: the ranking feeds are fetched over
# HTTPS, and without these every fetch fails with an unhelpful error.
RUN apk upgrade --no-cache \
 && apk add --no-cache ca-certificates tzdata

# Runs as a normal user. Nothing here needs root, and a container that does not
# need it should not have it.
# The identifiers are pinned. Letting adduser choose meant the chart's
# runAsUser matched only by luck, and any future package that creates a system
# user would shift it — after which the pod runs as a different user than the
# chart declares, silently.
RUN addgroup -g 65532 -S openpsirt \
 && adduser -u 65532 -S -G openpsirt -H -s /sbin/nologin openpsirt

COPY --from=build /out/openpsirt /usr/local/bin/openpsirt
COPY --from=build /out/openpsirt.cdx.json /usr/share/openpsirt/openpsirt.cdx.json
COPY --from=scanner /out/grype /usr/local/bin/grype

# Where the scanner keeps its vulnerability data, and where this process looks
# for the scanner. Both are set so that a deployment which configures nothing
# still scans.
#
# The data is fetched at runtime rather than built in. A database baked into an
# image is stale the day after it is published, and the reason scanning happens
# here at all is that the data moves under an inventory that does not. The
# directory has to be writable, which with a read-only root filesystem means a
# mounted volume — the chart provides one.
ENV GRYPE_DB_CACHE_DIR=/var/cache/openpsirt/grype \
    OPENPSIRT_SCANNER_PATH=/usr/local/bin/grype
RUN mkdir -p /var/cache/openpsirt/grype \
 && chown -R 65532:65532 /var/cache/openpsirt

# What the whole image ships, read off the assembled filesystem.
#
# The other inventory describes the binary — every module it was linked from —
# and that is not what this image is. musl, busybox, the certificate bundle and
# the bundled scanner are all shipped here and appear in none of it. For a tool
# whose subject is knowing what is inside what you ship, carrying one inventory
# that leaves out most of the image is the wrong half to carry alone.
#
# Read from a copy of the runtime rather than by scanning an image, because the
# image being described does not exist until this build finishes. What is
# copied is the same filesystem the last stage starts from, so the answer is
# about this build rather than about one like it.
FROM inventory-tool AS image-inventory
# The same default the binary takes, so an unpassed build does not say "dev" in
# the version it prints and "0.0.0" in the inventory it ships about itself.
ARG VERSION=dev
COPY --from=runtime / /rootfs
COPY --from=build /out/compose /out/compose
RUN mkdir -p /parts
# Packages, not files. The file catalogers add a component per path with no
# version and no package identifier — eight hundred of them here — and nothing
# downstream can do anything with those: a scanner matches packages, so they
# would be eight hundred rows in a dependency tree that no finding can ever
# hang off. They also carry the scan path, which is a build-time detail that
# has no business in a shipped inventory.
ENV SYFT_FILE_METADATA_SELECTION=none

# Cataloged as parts, because neither way of asking answers the whole question.
#
# Cataloging the directory finds every package and loses the structure inside a
# compiled binary: the modules arrive flat, with nothing above them, not even
# the module that *is* the binary. Cataloging one binary produces the opposite —
# a proper graph, and no knowledge of the image around it.
#
# So each is asked what it can answer, and the parts are composed. The
# directory scan is told to leave the binaries alone, since the file scans
# below cover them properly.
RUN /out/syft scan dir:/rootfs \
      --select-catalogers "-file,-go-module-binary-cataloger" \
      --source-name openpsirt-image --source-version "${VERSION}" \
      -o cyclonedx-json=/parts/filesystem.cdx.json \
 && for binary in openpsirt grype; do \
      /out/syft scan "file:/rootfs/usr/local/bin/$binary" \
        --select-catalogers "-file" \
        -o "cyclonedx-json=/parts/$binary.cdx.json"; \
    done \
 && /out/compose -name openpsirt-image -version "${VERSION}" \
      -out /image.cdx.json \
      parts/filesystem.cdx.json parts/openpsirt.cdx.json parts/grype.cdx.json \
 && test -s /image.cdx.json \
 && chmod 0644 /image.cdx.json

FROM runtime
# Readable, like the module inventory beside it. The composer writes 0600 —
# what the analysis gate allows a program to write — and the mode travels
# through this copy, so shipped as written it landed root-only in an image that
# runs as nobody: the one document saying what this image contains could not be
# read from inside it.
COPY --from=image-inventory /image.cdx.json /usr/share/openpsirt/image.cdx.json

# What this image is, in the one place a registry, a scanner and a puller can
# all read without running it.
#
# The image carried no labels at all: an image pulled by digest could not be
# traced back to the commit that produced it, and the two inventories it ships
# — which do carry the version — are inside a filesystem nobody has mounted
# yet when the question is asked. The values are the same build arguments the
# binary was stamped with, so "openpsirt -version", the inventories and the
# labels cannot disagree about one build.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.title="OpenPSIRT" \
      org.opencontainers.image.description="Track vulnerabilities in the products you ship" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/nexthop-ai/openpsirt" \
      org.opencontainers.image.vendor="Nexthop Systems Inc." \
      org.opencontainers.image.licenses="Apache-2.0"

USER openpsirt
EXPOSE 8080

# Liveness. Readiness depends on the database and belongs to the orchestrator,
# which can act on it.
#
# This asks the running server, not a new process. Running "openpsirt -version"
# proved only that the binary was on disk and executable — a deadlocked or
# non-listening server passed it forever.
# Never through a proxy. A deployment that sets HTTP_PROXY so the scanner can
# fetch its vulnerability database sets it for everything in the image, and
# busybox wget honors the proxy variables while ignoring no_proxy — so the
# container asks a proxy about itself, is told 403, and reports unhealthy while
# serving every request correctly. An orchestrator acting on that restarts a
# working container in a loop.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q --proxy=off -O- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/openpsirt"]
