# Everything CI runs is reachable from here, so a developer can reproduce any
# failure with one command using the same versions.

# bash with pipefail, because a recipe that pipes takes the *last* command's
# status by default. "go test | tee" therefore reported the status of tee,
# which is always 0 — so the engines gate announced "every engine ran" while
# the suite it had just run was failing. That is the exact shape of bug the
# gate exists to catch, in the gate itself.
SHELL       := /usr/bin/env bash
.SHELLFLAGS := -eo pipefail -c

# Machine-local settings, chiefly the database URLs below. Ignored by git, so
# a checkout with one is not different from a checkout without one. Absent is
# fine: the dash means "if it exists".
-include local.mk

GO           ?= go
# The engines the suite runs against. Set in local.mk or in the environment;
# exported so they reach the test process either way, since a make variable is
# not an environment variable and the suite reads the environment.
#
# Unset means SQLite alone, which passes every portability trap the design is
# written around by never reaching one. "check" says so rather than letting a
# one-engine pass read as a four-engine pass; "check-engines" refuses.
export OPENPSIRT_TEST_POSTGRES_URL
export OPENPSIRT_TEST_MYSQL_URL
export OPENPSIRT_TEST_MARIADB_URL
export OPENPSIRT_TEST_TOO_OLD_URL
ENGINES_SET := $(strip $(OPENPSIRT_TEST_POSTGRES_URL)$(OPENPSIRT_TEST_MYSQL_URL)$(OPENPSIRT_TEST_MARIADB_URL))
# Named one at a time, because "all three are missing" and "one is missing" are
# different states and only the first used to be reported. With postgres alone
# configured the warning stayed silent and the run tested two engines of four.
ENGINES_MISSING := $(strip \
  $(if $(OPENPSIRT_TEST_POSTGRES_URL),,postgres) \
  $(if $(OPENPSIRT_TEST_MYSQL_URL),,mysql) \
  $(if $(OPENPSIRT_TEST_MARIADB_URL),,mariadb))

# The servers those URLs point at, as containers. Pinned for the same reason
# every tool below is, and to the versions CI runs: an engine that has drifted
# from CI's turns "it passed locally" into a different claim from "it passes".
# Two pinned lists in two files drift silently, so "engines-check" asserts they
# still agree rather than trusting that whoever moved one moved the other.
DOCKER               ?= docker
PYTHON               ?= python3
ENGINE_PG_IMAGE      ?= postgres:16-alpine
ENGINE_MYSQL_IMAGE   ?= mysql:8.4
ENGINE_MARIADB_IMAGE ?= mariadb:11.4
# Deliberately below the supported floor, so the refusal to run against an old
# server is exercised rather than skipped.
ENGINE_FLOOR_IMAGE   ?= postgres:13-alpine
ENGINE_PG_PORT       ?= 5432
ENGINE_MYSQL_PORT    ?= 3306
ENGINE_MARIADB_PORT  ?= 3307
ENGINE_FLOOR_PORT    ?= 5433
ENGINE_PREFIX        ?= openpsirt
# Seconds to wait for a server to start accepting connections. A container
# reported "Up" is not one that answers yet, and MySQL takes the longest.
ENGINE_WAIT          ?= 120

# Every package of ours, which is not what "./..." means here.
#
# An npm dependency ships a Go package: web/node_modules/flatted/golang is
# matched by "./..." and was compiled, vetted and tested as part of this
# module. Nothing chose that, and a JavaScript dependency putting Go source
# into this build graph is a surface rather than a curiosity. Every tool
# written here already skips node_modules by name — readable, unreachable,
# reserved and the document link test all list it — and the package pattern
# was the one place that did not.
#
# Computed rather than written as "./cmd/... ./internal/...", so a new
# directory of ours is included without anybody remembering to add it.
PACKAGES = $(shell $(GO) list ./... | grep -v '/node_modules/')

BIN          := bin/openpsirt
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE         ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG          := github.com/nexthop-ai/openpsirt/internal/version
# What the binary reports when asked. Defaults to what git describes, and the
# release targets below override it per target — a tag is "v0.2.0" and a chart
# version is "0.2.0", and the assets a release publishes have to agree with
# each other rather than differing by one character. Recursive rather than
# immediate for exactly that: an immediate assignment would bake the default
# in before a target-specific value could reach it.
STAMP_VERSION ?= $(VERSION)
LDFLAGS       = -s -w \
	-X '$(PKG).version=$(STAMP_VERSION)' \
	-X '$(PKG).commit=$(COMMIT)' \
	-X '$(PKG).date=$(DATE)'

# What a release is made of, and where it is built.
#
# The tag is the only place a version is typed. VERSION above is derived from
# it, DIST_VERSION is that tag with the leading v removed, and every asset
# takes its version from there — nothing is read from a file somebody has to
# remember to move, because a version written in two files is one that ends up
# in one of them.
DIST_DIR        ?= bin/dist
DIST_VERSION    ?= $(patsubst v%,%,$(VERSION))
DIST_ARCHES     ?= amd64 arm64
DIST_IMAGE      ?= ghcr.io/nexthop-ai/openpsirt
CHART_DIR       := deploy/helm/openpsirt
# The inventory of what the image ships is read off the assembled filesystem,
# so it describes one architecture. Locally that is this machine's, because
# cataloging a foreign one runs foreign binaries under emulation; the workflow
# that publishes builds one per architecture it pushes.
DIST_IMAGE_ARCH ?= $(shell $(GO) env GOARCH)

# Every tool is pinned. "latest" resolves at run time, so CI would not be
# reproducible against last week's run and a compromised upstream release would
# execute here on the day it shipped.
GOLANGCI_VERSION    ?= v2.13.1
GOVULNCHECK_VERSION ?= v1.7.0
GOLICENSES_VERSION  ?= v1.6.0
# The module path is not the repository path: the project moved to the
# gitleaks organization and the module still declares zricethezav, so asking
# for the other one fails with a version-constraint conflict rather than a
# not-found.
GITLEAKS_VERSION    ?= v8.30.1
CDXGOMOD_VERSION    ?= v1.12.0

# Permissive only, for anything that ships. Build tooling is unrestricted.
ALLOWED_LICENSES := Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MIT,MPL-2.0

# Modules the classifier cannot read, whose license has been checked by hand.
# Each entry needs a reason. Lowering the confidence threshold instead would
# silently accept every other unreadable license too, which is the opposite of
# what this check is for.
#
#   modernc.org/mathutil  BSD-3-Clause. Verified by reading LICENSE: three
#                         clauses and the standard disclaimer. The classifier
#                         fails on its wording, which says "neither the names
#                         of the authors" where the canonical text says
#                         "neither the name of the copyright holder".
LICENSE_EXCEPTIONS := modernc.org/mathutil

# The same thing for the interface's dependencies, as package=license so that
# the license still has to match rather than the package being waved through.
# One exception list rather than two: a reviewer asking what exceptions this
# project grants reads one file, and the reason for each is written beside the
# entry that grants it.
#
#   @fontsource/  OFL-1.1, the SIL Open Font License. What fonts are published
#                 under, and permissive about embedding and redistribution —
#                 what it withholds is the right to sell the fonts on their
#                 own, which is not something a shipped application does.
#   argparse      PSF-2.0, the Python Software Foundation license, because the
#                 package is a port of Python's argparse and carries the
#                 original's license. Permissive, and compatible.
WEB_LICENSE_EXCEPTIONS := @fontsource/=OFL-1.1,argparse=PSF-2.0

NPM ?= npm

.PHONY: attached secrets web-audit dist dist-clean dist-version dist-binaries dist-chart dist-inventories dist-sums dist-verify gate full docs-check unreachable unclaimed reserved reserved-words reserved-current weakness-names readable negatives granted narrowed all build test test-all test-race test-engines vet lint fmt openapi openapi-current run clean check check-packaging check-engines measure engines-up engines-down engines-status engines-check govulncheck licenses sbom web web-deps web-api web-check clean-web dist-serves confined

all: check build

build:
	@mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/openpsirt

# The quick loop: SQLite only, packages in parallel, the build cache on, no
# race detector. Seconds, so it is run after every change. The four-engine,
# race-detected, uncached run is test-all, and the gate uses that.
test:
	OPENPSIRT_TEST_ENGINES=sqlite $(GO) test $(PACKAGES)

# Every configured engine, the race detector once, nothing cached. Packages run
# in parallel: each test binary gets a database of its own on every engine
# (internal/dbtest), so they share nothing.
#
# Two runs rather than one, because the race detector is a property of the
# binary and cannot be turned on for one subtest. A Go data race does not vary
# by database engine, so running the detector four times proves nothing the
# first run did not — the argument already accepted for the two-engine form of
# a test. It runs on SQLite, which needs no server and where each test holds a
# database of its own, so those tests also run beside each other.
# Half the cores, rounded down, and never below one. Each of the two passes
# takes that, so the number of test binaries alive at once is what a single
# pass has and the memory falls rather than rises: 1.5 GB against the 3.4 GB
# the two reach running one after another with the whole machine each.
TEST_HALF := $(shell n=$$(nproc 2>/dev/null || echo 2); h=$$((n / 2)); 	if [ $$h -lt 1 ]; then h=1; fi; echo $$h)

# Both passes at once. They share no engine — the detector runs on SQLite and
# the portability pass on the three servers — so neither can see the other's
# rows, and the guard against two runs of one package meeting on one server
# still holds.
#
# What it buys is that the two are bottlenecked on different things: the
# detector is in-process work and the server pass spends its time waiting on a
# socket, so each fills what the other leaves idle. 119 s to 100 s on twelve
# cores with everything warm, and more where the two passes are further apart
# in length than they are here.
#
# Each pass labels its own lines rather than being held and printed at the
# end. Held, a run says nothing for the whole of it — which on a slow machine
# is a quarter of an hour of a log that looks stopped — and interleaved without
# labels, two runs of fifty packages are two answers to "did it pass" with no
# way to tell which said what.
#
# The label is flushed per line. Left to its own buffering a filter holds four
# kilobytes before writing, which on a pipe is most of a pass — so the log went
# quiet exactly as it did when the output was held deliberately, and for a
# reason harder to see.
#
# The label goes through a pipe, and the shell here runs with pipefail, so a
# failing pass is still a failing pipeline. Watched going red one pass at a
# time.
test-all:
	@( OPENPSIRT_TEST_ENGINES=sqlite $(GO) test -race -count=1 -p $(TEST_HALF) \
	    $(PACKAGES) 2>&1 | awk '{ print "[sqlite -race] " $$$$0; fflush() }' ) & detector=$$!; \
	( OPENPSIRT_TEST_ENGINES=postgres,mysql,mariadb $(GO) test -count=1 -p $(TEST_HALF) \
	    $(PACKAGES) 2>&1 | awk '{ print "[servers]      " $$$$0; fflush() }' ) & portability=$$!; \
	failed=0; \
	wait $$detector || failed=1; \
	wait $$portability || failed=1; \
	exit $$failed

# The detector, on the engine every checkout has. Its own target, for running
# one pass by hand; the gate runs both at once through test-all.
test-race:
	OPENPSIRT_TEST_ENGINES=sqlite $(GO) test -race -count=1 $(PACKAGES)

# The three server engines, without it. Their time is spent waiting on a
# socket, which is not where a race is found: 16.9 s against 12.0 s for the API
# package on MariaDB, where the same package on SQLite is 73.6 s against 10.1 s.
test-engines:
	OPENPSIRT_TEST_ENGINES=postgres,mysql,mariadb $(GO) test -count=1 $(PACKAGES)

# The checks this change has to pass, chosen from what it touches.
#
# The full gate is minutes and most changes cannot fail most of it: a prose
# edit cannot break a database engine, and an interface change cannot make a Go
# query non-portable. Running everything anyway is what teaches people to skip
# the gate, which is the failure the gate exists to prevent — so the tier is
# read off the change by a program rather than off a table by a person.
#
# "make gate full" runs the whole thing, which is what a session ends with and
# what a push carrying accumulated work takes. A clean tree gets the same
# answer: there is no change here to choose from.
#
# What it chose is printed before it runs, because a gate nobody can see the
# reasoning of is one people stop believing.
gate:
	@targets=$$($(GO) run ./internal/tools/gate $(if $(filter full,$(MAKECMDGOALS)),full)); \
	  echo "gate: running $$targets"; \
	  $(MAKE) $$targets

# An argument to "gate", not a target. Named here so that "make gate full"
# works; on its own it says what it is for rather than doing nothing quietly.
full:
	@case " $(MAKECMDGOALS) " in \
	  *" gate "*) : ;; \
	  *) echo "'full' is an argument to 'gate': run 'make gate full'"; exit 1 ;; \
	esac

# What a change to documents alone can break: a link pointing at a heading that
# has been renamed, and the style the design documents are written in. Seconds.
# The other half of that tier is "unclaimed", which is a check of its own.
docs-check:
	$(GO) test ./internal/docs/

vet:
	$(GO) vet $(PACKAGES)
	$(MAKE) measure-builds

# The measurement file, type-checked without being run.
#
# It sits behind a build tag, and "make measure" is the only thing that passes
# that tag — a target which refuses outright unless three server engines are
# configured, so nobody discovers that the file has stopped compiling. A rename
# anywhere it reaches left it silently broken while the build, the vet, the
# linter and CI all passed.
#
# Vetting rather than running: go vet type-checks, it needs no database, and it
# costs a second.
.PHONY: measure-builds
measure-builds:
	$(GO) vet -tags measure $(MEASURED)

lint:
# Verified before it is run. The loader drops a key it does not recognize
# without a word, so a setting spelled at the wrong level reads as configured
# and does nothing — which is how the "measure"-tagged file went on being
# unlinted under a comment saying it was not.
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) config verify
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run

fmt:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) fmt

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(PACKAGES)

# Both halves of what ships, against one allowlist.
#
# The interface is built into the binary, so its dependencies are shipped
# exactly as the Go ones are — and they went unchecked until the platform
# product that would have caught them turned out to be a paid add-on on a
# private repository. The allowlist is this variable, passed to both, because
# a policy written in two files is a policy that differs in one of them.
licenses:
	$(GO) run github.com/google/go-licenses@$(GOLICENSES_VERSION) check $(PACKAGES) \
		--allowed_licenses=$(ALLOWED_LICENSES) \
		$(foreach m,$(LICENSE_EXCEPTIONS),--ignore=$(m))
	@command -v $(NPM) >/dev/null 2>&1 \
	  || { echo "npm not found, so the interface's licenses are unchecked here"; exit 1; }
	@ALLOWED_LICENSES=$(ALLOWED_LICENSES) LICENSE_EXCEPTIONS=$(WEB_LICENSE_EXCEPTIONS) \
	  $(NPM) --prefix web run --silent licenses

# The reader over a real inventory, which the fixtures cannot stand in for.
#
# It reports every path the reader takes that no document exercised, and the
# shapes that appear once are the ones a small document does not have. It had
# never run: the test asks for a document through an environment variable that
# nothing in the makefile, the workflows or the documentation ever set, while a
# full-size one sat in the same directory compressed.
#
# Decompressed into a scratch directory rather than committed uncompressed:
# the file is the size the measurement is about.
.PHONY: sbom-shape
sbom-shape:
	@command -v xz >/dev/null 2>&1 \
	  || { echo "xz not found, so the full-size inventory cannot be read here"; exit 1; }
	@work=$$(mktemp -d); trap 'rm -rf "$$work"' EXIT; \
	  xz -dc internal/sbom/testdata/switch-image.cdx.json.xz > "$$work/full.cdx.json"; \
	  OPENPSIRT_TEST_SBOM="$$work/full.cdx.json" $(GO) test ./internal/sbom/ -count=1 \
	    -run TestAFullSizeDocumentIntroducesNoUndecidedPath

# We ingest SBOMs, so we publish one for ourselves. CycloneDX because that is
# the format this project treats as authoritative on the way in.
#
# It describes the source tree and is not what a release publishes: that
# document is read out of the image by "dist-inventories". This generator is
# asked about a module directory rather than about a compiled binary, so the
# version comes from the checkout's own history and is a commit where there is
# no tag to name — never the empty version a binary's build information
# carries, which is why the image's invocation has to be told one.
sbom:
	@mkdir -p bin
	$(GO) run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CDXGOMOD_VERSION) \
		app -main cmd/openpsirt -json -packages -output bin/openpsirt.cdx.json .
	@echo "wrote bin/openpsirt.cdx.json"

# Every asset a release carries, built into $(DIST_DIR) and checked there.
#
# A make target rather than steps in a workflow, for the reason every other
# check is one: the workflow that publishes these runs this command, so what a
# developer can build and what is published come out of one recipe. What is
# deliberately *not* here is pushing, signing and the release itself — each
# needs a registry credential or a workload identity that a checkout does not
# have, and a target that cannot run locally is a target that drifts.
#
# The order matters: the directory is emptied first, so an asset left by an
# earlier version cannot be checksummed and published alongside this one.
#
# The interface is built before the binaries, because the binary embeds a
# git-ignored directory and a fresh checkout's is empty — archives built
# without this step carry every API route and no page at all.
#
# The image is gated after it is built rather than only in CI. A release
# builds it from a fresh checkout, and the base image is upgraded as it
# builds, so it is a different set of bytes from the one CI checked: the
# scanner it bundles can stop working between the merge queue and the tag,
# and a deployment that cannot scan ingests inventories it never reads.
dist:
	@$(MAKE) --no-print-directory dist-version
	@$(MAKE) --no-print-directory dist-clean
	@$(MAKE) --no-print-directory web
	@$(MAKE) --no-print-directory dist-binaries
	@$(MAKE) --no-print-directory dist-chart
	@$(MAKE) --no-print-directory dist-inventories
	@$(MAKE) --no-print-directory check-packaging CHECK_IMAGE=$(DIST_IMAGE):$(DIST_VERSION)
	@$(MAKE) --no-print-directory dist-sums
	@$(MAKE) --no-print-directory dist-verify
	@echo "$(DIST_DIR) holds $$(ls -1 $(DIST_DIR) | wc -l) files for $(DIST_VERSION)"

# A release is cut from a tag, and nothing else is a release.
#
# An untagged commit describes as a bare hash and a modified tree as
# "-dirty" — both name a version nobody can get back to, and neither is
# something a chart will accept. Overridable, because building the assets to
# look at them is a reasonable thing to want: DIST_VERSION=0.0.0-dev.
# The version arrives from "git describe", so it is a tag name, and a tag name
# may carry shell syntax: the ref format refuses a space and a handful of
# characters and permits "$", "(" and ")". A value substituted into a recipe
# becomes script text, so this one is read from the environment instead, where
# the shell treats it as data.
#
# Everything downstream interpolates it freely, and may: past this target the
# value has matched the pattern below, which admits digits, dots and a
# restricted suffix and nothing a shell acts on. Which is why every target that
# builds a name from it asks for this one first.
dist-version: export CHECKED_VERSION = $(DIST_VERSION)
dist-version:
	@case "$$CHECKED_VERSION" in \
	  *-dirty) echo "the tree is dirty, so $$CHECKED_VERSION names no commit anybody else can get"; exit 1 ;; \
	esac
	@printf '%s' "$$CHECKED_VERSION" \
	  | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)*$$' \
	  || { echo "that is not a version a chart can carry: tag the commit, or pass DIST_VERSION=0.0.0-dev"; exit 1; }

dist-clean:
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)

# The binaries, one archive per architecture, each carrying the license it is
# under. Cross-compiled rather than built in a container: the SQLite driver is
# pure Go and cgo is off, so every supported architecture builds here in
# seconds and none of them needs emulation.
dist-binaries: STAMP_VERSION := $(DIST_VERSION)
dist-binaries: dist-version
	@mkdir -p $(DIST_DIR)
	@set -e; for arch in $(DIST_ARCHES); do \
	  name=openpsirt_$(DIST_VERSION)_linux_$$arch; \
	  rm -rf $(DIST_DIR)/$$name; mkdir -p $(DIST_DIR)/$$name; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath \
	    -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$$name/openpsirt ./cmd/openpsirt; \
	  cp LICENSE NOTICE README.md $(DIST_DIR)/$$name/; \
	  tar -C $(DIST_DIR) -czf $(DIST_DIR)/$$name.tar.gz $$name; \
	  rm -rf $(DIST_DIR)/$$name; \
	  echo "  $$name.tar.gz"; \
	done

# The chart, with its version and the version of the application it installs
# both stamped from the tag.
#
# Chart.yaml holds a placeholder rather than the released number, because a
# version committed to a file is the one somebody forgets to move — the same
# reason pins-check exists. Stamping at package time means the tag is the only
# thing that has to be right.
dist-chart: dist-version
	@mkdir -p $(DIST_DIR)
	@command -v helm >/dev/null 2>&1 \
	  || { echo "helm is needed to package the chart"; exit 1; }
	@helm package $(CHART_DIR) --version $(DIST_VERSION) \
	  --app-version $(DIST_VERSION) --destination $(DIST_DIR) >/dev/null
	@echo "  openpsirt-$(DIST_VERSION).tgz"

# The two inventories, lifted out of an image built from this tree.
#
# Published rather than left as a CI artifact that expires: we ingest these
# for other people's software, and REQ-04 is the same promise kept about our
# own. They are read out of the image rather than rebuilt here, because the
# image is what the inventories are about.
dist-inventories: dist-version
	@mkdir -p $(DIST_DIR)
	@command -v $(DOCKER) >/dev/null 2>&1 \
	  || { echo "$(DOCKER) is needed to read the inventories out of the image"; exit 1; }
	@echo "  building $(DIST_IMAGE):$(DIST_VERSION) for $(DIST_IMAGE_ARCH)"
	@# Not quiet. This builds the binary's inventory inside the image, and a
	@# release that cannot say why it failed is one somebody re-runs to find
	@# out — which is what happened: the step exited 1 and the only thing
	@# recorded was that it had.
	$(DOCKER) build -t $(DIST_IMAGE):$(DIST_VERSION) \
	  --build-arg VERSION=$(DIST_VERSION) --build-arg COMMIT=$(COMMIT) \
	  --build-arg DATE=$(DATE) --build-arg CDXGOMOD_VERSION=$(CDXGOMOD_VERSION) .
	@$(DOCKER) run --rm --entrypoint cat $(DIST_IMAGE):$(DIST_VERSION) \
	  /usr/share/openpsirt/openpsirt.cdx.json > $(DIST_DIR)/openpsirt_$(DIST_VERSION).cdx.json
	@$(DOCKER) run --rm --entrypoint cat $(DIST_IMAGE):$(DIST_VERSION) \
	  /usr/share/openpsirt/image.cdx.json \
	  > $(DIST_DIR)/openpsirt-image_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH).cdx.json
	@echo "  openpsirt_$(DIST_VERSION).cdx.json"
	@echo "  openpsirt-image_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH).cdx.json"

# One file covering every other, so a download can be checked without holding
# a signature or trusting the page it came from.
dist-sums: dist-version
	@cd $(DIST_DIR) && rm -f SHA256SUMS \
	  && sha256sum $$(ls -1 | sort) > SHA256SUMS
	@echo "  SHA256SUMS"

# That every asset says which version it is, in both places somebody looks:
# the name of the file, and the thing inside it.
#
# An archive named 0.2.0 whose binary reports 0.1.9 is what makes a
# vulnerability report unanswerable — "which version were you running" then
# has two answers and nothing anywhere else checks that they agree.
#
# What it could not check, it names. Run as part of "dist" every asset is
# there and nothing is skipped; run on its own against half a directory, a
# silent pass would say the assets agree when three of the four checks never
# ran — which is the shape of green this repository refuses elsewhere.
#
# The checksum file and anything beside it carrying the same stem are exempt
# from the name check: a signature is written after the assets are built and
# named for what it signs, not for the release.
dist-verify: dist-version
	@command -v jq >/dev/null 2>&1 \
	  || { echo "jq is needed to read the version out of an inventory"; exit 1; }
	@set -e; fail=0; skipped=; \
	  for path in $(DIST_DIR)/*; do \
	    file=$$(basename "$$path"); \
	    case "$$file" in \
	      SHA256SUMS|SHA256SUMS.*) continue ;; \
	      *$(DIST_VERSION)*) ;; \
	      *) echo "$$file does not carry $(DIST_VERSION) in its name"; fail=1 ;; \
	    esac; \
	  done; \
	  archive=$(DIST_DIR)/openpsirt_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH).tar.gz; \
	  if [ -f "$$archive" ]; then \
	    work=$$(mktemp -d); trap 'rm -rf "$$work"' EXIT; \
	    tar -C "$$work" -xzf "$$archive"; \
	    binary="$$work"/openpsirt_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH)/openpsirt; \
	    said=$$("$$binary" -version | awk '{print $$2}'); \
	    [ "$$said" = "$(DIST_VERSION)" ] \
	      || { echo "the binary reports $$said and its archive says $(DIST_VERSION)"; fail=1; }; \
	    $(MAKE) --no-print-directory dist-serves BINARY="$$binary" \
	      || fail=1; \
	  else skipped="$$skipped the binary (no archive for $(DIST_IMAGE_ARCH))"; fi; \
	  chart=$(DIST_DIR)/openpsirt-$(DIST_VERSION).tgz; \
	  if [ ! -f "$$chart" ]; then skipped="$$skipped the chart (not packaged)"; \
	  elif ! command -v helm >/dev/null 2>&1; then skipped="$$skipped the chart (no helm)"; \
	  else \
	    for field in version appVersion; do \
	      said=$$(helm show chart "$$chart" | awk -v f="$$field:" '$$1==f {print $$2}' | tr -d '"'); \
	      [ "$$said" = "$(DIST_VERSION)" ] \
	        || { echo "the chart's $$field is $$said and the release is $(DIST_VERSION)"; fail=1; }; \
	    done; \
	  fi; \
	  for inventory in \
	    $(DIST_DIR)/openpsirt_$(DIST_VERSION).cdx.json \
	    $(DIST_DIR)/openpsirt-image_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH).cdx.json; do \
	    [ -f "$$inventory" ] || { skipped="$$skipped $$(basename $$inventory) (not built)"; continue; }; \
	    said=$$(jq -r '.metadata.component.version' "$$inventory"); \
	    [ "$$said" = "$(DIST_VERSION)" ] \
	      || { echo "$$(basename $$inventory) describes $$said and the release is $(DIST_VERSION)"; fail=1; }; \
	  done; \
	  [ "$$fail" = 0 ] || exit 1; \
	  echo "  every asset names $(DIST_VERSION), and every one that carries it inside agrees"; \
	  [ -z "$$skipped" ] || echo "  not checked:$$skipped"

# That a released binary serves the interface, asked of the binary rather than
# of the tree it was built from.
#
# The same question "check-packaging" asks of the image, for the same reason
# and in the same words: the Go build embeds a git-ignored directory, so a
# binary built from a clean checkout answers every API route and no page. The
# image grew this check when that happened; the archives a person downloads
# did not have it, and are the half somebody runs by hand.
#
# The port is chosen here and moved when it is taken. A fixed one collides
# with whatever else is on this machine, and the release path is not the place
# to discover that.
dist-serves:
	@test -n "$(BINARY)" || { echo "dist-serves needs BINARY=<path>"; exit 1; }
	@set -e; \
	  dir=$$(mktemp -d); pid=; answered=; port=$$((20000 + $$$$ % 20000)); \
	  trap '[ -z "$$pid" ] || kill $$pid 2>/dev/null || true; rm -rf "$$dir"' EXIT; \
	  attempt=0; \
	  while [ $$attempt -lt 5 ]; do \
	    OPENPSIRT_DATABASE_URL="sqlite://$$dir/serves.db" \
	    OPENPSIRT_ADDR="127.0.0.1:$$port" \
	    OPENPSIRT_PLAIN_HTTP=1 \
	    OPENPSIRT_BOOTSTRAP_ADMINS=check \
	      "$(BINARY)" >"$$dir/log" 2>&1 & \
	    pid=$$!; \
	    waited=0; \
	    while kill -0 $$pid 2>/dev/null; do \
	      if curl -fsS --noproxy '*' "http://127.0.0.1:$$port/readyz" >/dev/null 2>&1; then \
	        answered=yes; break; \
	      fi; \
	      waited=$$((waited + 1)); \
	      [ $$waited -gt 60 ] && break; \
	      sleep 1; \
	    done; \
	    [ -n "$$answered" ] && break; \
	    kill $$pid 2>/dev/null || true; wait $$pid 2>/dev/null || true; pid=; \
	    attempt=$$((attempt + 1)); port=$$((port + 1)); \
	  done; \
	  [ -n "$$answered" ] \
	    || { echo "the archive's binary never answered on five ports:"; \
	         sed 's/^/    /' "$$dir/log"; exit 1; }; \
	  curl -fsS --noproxy '*' "http://127.0.0.1:$$port/" | grep -qi '<!doctype html' \
	    || { echo "the archive's binary serves no interface: it was built without one"; exit 1; }

# The document is generated from the running registrations, never hand-written.
openapi:
	@mkdir -p docs/reference
	$(GO) run ./cmd/openpsirt -openapi > docs/reference/openapi.yaml
	@echo "wrote docs/reference/openapi.yaml"

# Everything CI runs, reachable from one command. Container and chart checks
# are included because CI runs them; omitting them meant four of nine jobs
# could not be reproduced locally.
check: build vet lint unreachable unclaimed reserved confined granted narrowed attached readable negatives pins-check test-all sbom-shape govulncheck licenses secrets openapi-current sbom web-check
ifneq ($(ENGINES_MISSING),)
	@echo
	@echo "NOT TESTED ON: $(ENGINES_MISSING). Those engines were not configured,"
	@echo "so nothing here exercised them. Run 'make check-engines' before committing."
endif

# The interface, built into the directory the binary embeds. Kept out of
# "build" so a checkout with no node toolchain still produces a working
# API-only binary — the embed tolerates an empty directory on purpose.
web: web-deps
	$(NPM) --prefix web run build
	# The build output only. The directory itself and its two dotfiles are
	# tracked, because the embed needs the directory to exist in a fresh
	# clone — removing the directory wholesale would delete them.
	rm -rf internal/webui/dist/assets internal/webui/dist/index.html
	cp -r web/dist/. internal/webui/dist/
	@git check-ignore -q internal/webui/dist/index.html \
	  || { echo "internal/webui/dist is not ignored: build output would be committed"; exit 1; }

# Reproducible, like every other dependency here: npm ci installs exactly what
# the lockfile pins rather than re-resolving ranges at build time.
web-deps:
	@command -v $(NPM) >/dev/null 2>&1 \
	  || { echo "$(NPM) is needed to build the interface"; exit 1; }
	$(NPM) --prefix web ci

# The client is generated from the committed document, so a drifted
# document is a compile error in the interface rather than a runtime surprise.
web-api: openapi
	$(NPM) --prefix web run api
	@git diff --exit-code -- web/src/api/schema.d.ts \
	  || { echo "web/src/api/schema.d.ts is stale: run make web-api and commit it"; exit 1; }

# What CI runs for the interface.
#
# It refuses without node rather than skipping, like "licenses" and
# "web-audit" on the identical condition. A skip here is indistinguishable
# from a pass, and what it covers is the whole tier: the typecheck, the lint,
# the stylelint, the tests and their coverage, the class collisions, the
# tokens and the severity ladder. "make gate" routes a change touching only
# web/ to this one target, so a skip would let such a change report green
# having been checked by nothing.
#
# A machine without node can still gate a Go-only change: that change lands in
# the code tier, which does not reach here. What needs node is "make check",
# which is everything CI checks and is meant to.
web-check:
	@command -v $(NPM) >/dev/null 2>&1 || { \
	  echo "npm not found, so the interface cannot be checked here."; \
	  echo "Install node, or run this on a machine that has it."; exit 1; }
	$(MAKE) web-deps
	$(NPM) --prefix web run typecheck
	$(NPM) --prefix web run format
	$(NPM) --prefix web run lint
	$(NPM) --prefix web run stylelint
	$(NPM) --prefix web run coverage
	$(NPM) --prefix web run classes
	$(NPM) --prefix web run tokens
	$(NPM) --prefix web run ladder
	$(MAKE) web-audit
	$(MAKE) web-api

# Credentials in the tree.
#
# REQ-75 names secret scanning as a gate. The platform product that provides
# it is a paid add-on on a private repository and is not enabled, so the gate
# is this: the same scan, pinned, running against the working tree, locally
# and in CI with one command.
#
# What it does not cover is history — a credential committed and then removed
# is still in the objects, and finding that is what the platform product is
# for. Nothing here should ever have been in a commit, which is the point of
# running this before one.
secrets:
	$(GO) run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) dir . \
		--no-banner --redact

# Known vulnerabilities in what the interface installs.
#
# The counterpart to govulncheck, and the other half of REQ-75's vulnerability
# scanning: govulncheck reads Go modules and says nothing at all about npm.
# The advisory data is the registry's, so this needs a network and says so
# rather than passing when it cannot reach one.
#
# High and above fails. Everything is reported, because "one moderate" and
# "forty moderates" are different facts and only one of them is worth a look.
web-audit:
	@command -v $(NPM) >/dev/null 2>&1 \
	  || { echo "npm not found, so the interface's dependencies are unscanned here"; exit 1; }
	$(NPM) --prefix web audit --audit-level=high

# Exported code nothing reaches. The analysis gate only reports unexported
# symbols, which left ten real defects invisible in one review — a store method
# with no route to it, a renderer nothing rendered with, a rule enforced in a
# second place nothing called. Every one looked like working code.
unreachable:
	$(GO) run ./internal/tools/unreachable

# Source files a text tool will not read. A stray control character makes grep
# treat a file as binary, and every text-based check here then skips it without
# saying so — which is how the busiest screen in the interface came to be
# invisible to all of them at once.
readable:
	$(GO) run ./internal/tools/readable

# A 404 whose body is an error's own text. It asserts that a name reaches
# nothing and publishes whatever the error carried: thirty handlers wrote one,
# the catalog readers under them returned the driver's message unwrapped, and a
# connection failure reached whoever asked as "that product does not exist"
# with the database host and port in the detail.
negatives:
	$(GO) run ./internal/tools/negatives

# Names this code invents that an engine refuses to parse. Queries are written
# once and run against four engines, and the four do not reserve the same
# words: `groups` is PostgreSQL's, `usage` is MySQL's, and either would leave
# the suite green on three engines and a deployment on the fourth unable to
# answer.
reserved:
	$(GO) run ./internal/tools/reserved

# That no query outside the database package asks an engine what it is. The
# list of places where that is allowed lives here and in DESIGN-database.md,
# and widening one without the other is what fails.
confined:
	$(GO) run ./internal/tools/confined

# That no query outside the access package asks one grant table and not the
# other. A role is held against one product or across every product, and a
# predicate seeing only the first answers no for somebody who holds the second —
# which compiles, passes, and refuses them.
granted:
	$(GO) run ./internal/tools/granted

# That a build resolved for somebody brought into one case is then read with a
# subject. The resolver admits them deliberately — the names their own issue
# sits at have to resolve — and what makes that safe is that every read past it
# asks the product question again. Nothing enforced that, and a collaborator
# received the approved statements for a whole build.
narrowed:
	$(GO) run ./internal/tools/narrowed

# A doc comment describing something other than what it sits on, which is what
# a file split leaves behind and what nothing else here can see: the code is
# correct, and godoc renders one symbol's documentation under another's name.
attached:
	$(GO) run ./internal/tools/attached

# The word list the check above reads, asked of the engines rather than typed.
# Needs them running: "make engines-up" first. MariaDB has no KEYWORDS table,
# so the words it reserves that MySQL does not are held by hand in words.go and
# this leaves them alone.
reserved-words:
	$(GO) run ./internal/tools/reserved generate
	$(GO) run ./internal/tools/reserved

# The weakness names a published advisory has to carry.
#
# The standard states a weakness as the identifier and the name the catalog
# gives it, and a consumer's validator compares the pair — so the name comes
# from the authority that assigns it rather than from anything typed here.
#
# Not in any gate, unlike "reserved-current". The engines that list asks are
# pinned in CI and this authority is not, so a check against what it publishes
# today would fail the build on the day MITRE ships a version, for a reason no
# change here caused. Run it deliberately and commit what it writes; the
# version it read is in the generated file.
weakness-names:
	$(GO) run ./internal/tools/weakness

# That the generated half of the word list is what the engines say today.
#
# The same generate-and-diff "openapi-current" does, and for the same reason:
# a list regenerated by hand is a list somebody stops regenerating. Here
# rather than in "check" because it has to reach the engines, and the gate it
# protects — "reserved" — reads the committed file, so an engine upgrade that
# adds a word would leave that gate passing while a query inventing the alias
# fails as a syntax error on the engine the deployment runs.
reserved-current: reserved-words
	@git diff --exit-code -- internal/tools/reserved/words_asked.go \
	  || { echo "the reserved-word list is stale: the engines reserve words this"; \
	       echo "list does not carry. Commit the regenerated file."; exit 1; }

# Decisions no design document names. The chain that makes this auditable runs
# code to design document to decision, and nothing checked that it was whole:
# 71 decisions in force were named nowhere, five of them cited by code that
# runs. A decision not built yet is not exempt — its design document says so.
unclaimed:
	$(GO) run ./internal/tools/unclaimed

# CI fails when the committed document has drifted, so check the same thing.
openapi-current: openapi
	@git diff --exit-code -- docs/reference/openapi.yaml \
	  || { echo "docs/reference/openapi.yaml is stale: commit the regenerated file"; exit 1; }

# Everything CI's test job asserts beyond the suite passing.
#
# A skipped test passes, so "go test" being green does not mean an engine ran —
# it means nothing failed, which is also what a skip looks like. CI greps its
# own output for each engine by name; without the same check locally, "the
# suite is green" and "the suite ran" are two different facts with one command
# behind them. This is the command to run before committing.
#
# The names it greps for come from the application's own enumeration rather
# than from a list here. They were written out by hand three times, so a fifth
# engine would not have been looked for by any of them — and a grep for
# nothing reports the same "OK" as a grep that found nothing wrong. The empty
# check below is for the same reason: an enumeration that came back empty would
# make every loop vacuous.
check-engines:
ifneq ($(ENGINES_MISSING),)
	@echo "Not configured: $(ENGINES_MISSING). SQLite alone tests none of the"
	@echo "portability traps, so this refuses rather than passing. See AGENTS.md."
	@exit 1
endif
	@every=$$($(GO) run ./internal/tools/engines) || exit 1; \
	  servers=$$($(GO) run ./internal/tools/engines servers) || exit 1; \
	  [ -n "$$every" ] && [ -n "$$servers" ] \
	    || { echo "the engine list came back empty, so these greps check nothing"; exit 1; }; \
	  out=$$(mktemp); trap 'rm -f "$$out"' EXIT; \
	  $(GO) test ./internal/schema/ -count=1 -v -run TestMigrationsApplyOnEveryEngine \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  for engine in $$every; do \
	    grep -q "PASS: TestMigrationsApplyOnEveryEngine/$$engine" "$$out" \
	      || { echo "$$engine did not run"; exit 1; }; \
	  done; \
	  $(GO) test ./internal/database/migrate/ -count=1 -v -run TestLockExcludes \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  for engine in $$servers; do \
	    grep -q "PASS: TestLockExcludesAnotherConnection/$$engine" "$$out" \
	      || { echo "the migration lock was not exercised on $$engine"; exit 1; }; \
	  done; \
	  $(GO) test ./internal/dbtest/ -count=1 -v -run TestEachEngineIsTheEngineItSaysItIs \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  for engine in $$every; do \
	    grep -q "PASS: TestEachEngineIsTheEngineItSaysItIs/$$engine" "$$out" \
	      || { echo "$$engine was not checked for being itself"; exit 1; }; \
	  done
	$(MAKE) reserved-current
ifneq ($(strip $(OPENPSIRT_TEST_TOO_OLD_URL)),)
	@out=$$(mktemp); trap 'rm -f "$$out"' EXIT; \
	  $(GO) test ./internal/database/ -count=1 -v -run TestOpenRefuses \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  grep -q "PASS: TestOpenRefusesAServerBelowTheFloor" "$$out" \
	    || { echo "the version floor test did not run"; exit 1; }
	@echo "every engine ran, and each was the engine it claimed to be"
else
	@echo "note: OPENPSIRT_TEST_TOO_OLD_URL unset, so the version floor refusal"
	@echo "      was not exercised here. CI runs it against postgres:13."
	@echo "every engine ran, and each was the engine it claimed to be,"
	@echo "except the version floor, which is noted above as not run."
endif

# The four servers the URLs above point at, started, waited for, and written
# into local.mk. Running against every engine is ordinary development here
# rather than something CI does afterwards (DAT-12), so a machine that can run
# the suite properly is one command rather than a setup document followed by
# hand — and a document followed by hand is how three of four engines end up
# unconfigured while the suite reports green.
#
# Idempotent: an engine already running is left alone, and a stopped container
# is started rather than replaced, so whatever is in it survives.
# A server whose only job is to be written to and thrown away.
#
# **The gate spends most of its time waiting for these three to fsync.** Every
# commit a test makes is flushed to disk for durability nobody wants: the
# databases are created by `make engines-up` and recreated the next time, and
# a crash mid-suite is answered by running the suite again. Measured on the
# largest package, four engines, everything else the same: PostgreSQL 68.8s to
# 35.1s, MySQL 48.8s to 9.5s, MariaDB 20.1s to 8.5s — and the whole test step
# 310s to 191s.
#
# **These belong to the test containers and nowhere near a deployment.** Both
# lists say "lose my writes if you crash", which is the right answer for a
# database that exists for ninety seconds and the wrong one everywhere else;
# the packaging chart sets none of them.
PG_AS_A_TEST_SERVER := -c fsync=off -c synchronous_commit=off -c full_page_writes=off
MY_AS_A_TEST_SERVER := --innodb-flush-log-at-trx-commit=0 --innodb-doublewrite=0 \
	--sync-binlog=0 --skip-log-bin

engines-up: engines-check
	@# Everything up to "--" belongs to docker and everything after it to the
	@# server: the tuning below is the server's own command line, and passed as
	@# a docker option it is read as one — "-c fsync=off" is --cpu-shares.
	@set -u; \
	up() { \
	  name="$$1"; image="$$2"; ports="$$3"; shift 3; \
	  if [ -n "$$($(DOCKER) ps -q -f name="^$$name$$")" ]; then \
	    echo "  $$name: already running"; return 0; \
	  fi; \
	  if [ -n "$$($(DOCKER) ps -aq -f name="^$$name$$")" ]; then \
	    $(DOCKER) start "$$name" >/dev/null; echo "  $$name: started again"; return 0; \
	  fi; \
	  opts=""; \
	  while [ $$# -gt 0 ] && [ "$$1" != "--" ]; do opts="$$opts $$1"; shift; done; \
	  if [ $$# -gt 0 ]; then shift; fi; \
	  $(DOCKER) run -d --name "$$name" -p "$$ports" $$opts "$$image" "$$@" >/dev/null; \
	  echo "  $$name: created from $$image"; \
	}; \
	up $(ENGINE_PREFIX)-pg16 $(ENGINE_PG_IMAGE) $(ENGINE_PG_PORT):5432 \
	   -e POSTGRES_PASSWORD=test -e POSTGRES_DB=openpsirt -- $(PG_AS_A_TEST_SERVER); \
	up $(ENGINE_PREFIX)-mysql $(ENGINE_MYSQL_IMAGE) $(ENGINE_MYSQL_PORT):3306 \
	   -e MYSQL_ROOT_PASSWORD=test -e MYSQL_DATABASE=openpsirt -- $(MY_AS_A_TEST_SERVER); \
	up $(ENGINE_PREFIX)-mariadb $(ENGINE_MARIADB_IMAGE) $(ENGINE_MARIADB_PORT):3306 \
	   -e MARIADB_ROOT_PASSWORD=test -e MARIADB_DATABASE=openpsirt -- $(MY_AS_A_TEST_SERVER); \
	up $(ENGINE_PREFIX)-floor $(ENGINE_FLOOR_IMAGE) $(ENGINE_FLOOR_PORT):5432 \
	   -e POSTGRES_PASSWORD=test -e POSTGRES_DB=openpsirt -- $(PG_AS_A_TEST_SERVER)
	@# A container reported "Up" is not one that answers. Each server is asked
	@# with its own client, inside its own container, so nothing here depends on
	@# a client being installed on this machine. MariaDB renamed mysqladmin to
	@# mariadb-admin, so the two lines differ by more than the server they name.
	@set -u; \
	ready() { \
	  name="$$1"; shift; waited=0; \
	  while [ "$$waited" -lt $(ENGINE_WAIT) ]; do \
	    if $(DOCKER) exec "$$name" "$$@" >/dev/null 2>&1; then \
	      echo "  $$name: answering"; return 0; \
	    fi; \
	    sleep 1; waited=$$((waited + 1)); \
	  done; \
	  echo "  $$name: no answer in $(ENGINE_WAIT)s. '$(DOCKER) logs $$name' says why."; \
	  return 1; \
	}; \
	ready $(ENGINE_PREFIX)-pg16 pg_isready -U postgres -d openpsirt; \
	ready $(ENGINE_PREFIX)-floor pg_isready -U postgres -d openpsirt; \
	ready $(ENGINE_PREFIX)-mysql mysqladmin ping -uroot -ptest --silent; \
	ready $(ENGINE_PREFIX)-mariadb mariadb-admin ping -uroot -ptest --silent
	@# Never overwritten. The file is machine-local and somebody may be pointing
	@# at servers of their own; silently replacing that is how a run tests
	@# something other than what its author thinks it is testing.
	@if [ -e local.mk ]; then \
	  echo; echo "local.mk already exists, so it was left alone."; \
	else \
	  printf '%s\n' \
	    "# Written by 'make engines-up'. Git-ignored, so a checkout with one is" \
	    "# not different from a checkout without one." \
	    "#" \
	    "# '?=' rather than ':=', so setting a URL in the environment for a" \
	    "# single run still wins: a makefile assignment beats an environment" \
	    "# variable, and the conditional form does not." \
	    "OPENPSIRT_TEST_POSTGRES_URL ?= postgres://postgres:test@127.0.0.1:$(ENGINE_PG_PORT)/openpsirt?sslmode=disable" \
	    "OPENPSIRT_TEST_MYSQL_URL    ?= mysql://root:test@127.0.0.1:$(ENGINE_MYSQL_PORT)/openpsirt" \
	    "OPENPSIRT_TEST_MARIADB_URL  ?= mariadb://root:test@127.0.0.1:$(ENGINE_MARIADB_PORT)/openpsirt" \
	    "# A server below the supported floor, so the refusal to run against one" \
	    "# is exercised rather than skipped." \
	    "OPENPSIRT_TEST_TOO_OLD_URL  ?= postgres://postgres:test@127.0.0.1:$(ENGINE_FLOOR_PORT)/openpsirt?sslmode=disable" \
	    > local.mk; \
	  echo; echo "wrote local.mk"; \
	fi
	@# The URLs are read when make starts, so this run still has none of them.
	@echo "The URLs are read at startup, so they reach the next command, not this one:"
	@echo "    make check && make check-engines"

# Stops them. The containers are removed rather than stopped, because a
# half-migrated database left behind by an interrupted run is a confusing thing
# to come back to; local.mk is left alone, since it is yours.
# Leaving local.mk behind is deliberate — "engines-up" reuses it — but a
# checkout that names three servers and has none is a state worth saying out
# loud. Between them, "check" and "test-engines" ask for exactly the engines
# named there, and what they report when nothing answers is a connection
# error per subtest, which reads like a code regression rather than a stopped
# container. The quick loop and the race run are narrowed to SQLite and are
# unaffected.
engines-down:
	@$(DOCKER) rm -f $(ENGINE_PREFIX)-pg16 $(ENGINE_PREFIX)-mysql \
	  $(ENGINE_PREFIX)-mariadb $(ENGINE_PREFIX)-floor >/dev/null 2>&1 || true
	@echo "removed. local.mk was left alone, so 'make engines-up' reuses it —"
	@echo "and until you run it, 'make check' and 'make test-engines' ask for"
	@echo "three servers that are no longer there. 'make test' is unaffected."

engines-status:
	@$(DOCKER) ps -a --filter "name=^$(ENGINE_PREFIX)-" \
	  --format '{{.Names}}: {{.Image}}, {{.Status}}' | sed 's/^/  /' || true
ifeq ($(ENGINES_MISSING),)
	@echo "  configured: postgres, mysql, mariadb"
else
	@echo "  NOT configured: $(ENGINES_MISSING). The suite would skip those, and a"
	@echo "  skipped engine passes. Run 'make engines-up'."
endif
ifeq ($(strip $(OPENPSIRT_TEST_TOO_OLD_URL)),)
	@echo "  NOT configured: the below-floor server, so the version refusal is skipped."
endif

# That the engines started here are the engines CI runs. Two pinned lists in
# two files drift, and the drift is invisible exactly when it matters: a suite
# green against MariaDB 11.4 says nothing about the 11.8 CI moved to. Checked
# in both directions, so an engine CI adds and this does not start is caught
# as well as the reverse.
engines-check:
	@ours="$(ENGINE_PG_IMAGE) $(ENGINE_MYSQL_IMAGE) $(ENGINE_MARIADB_IMAGE) $(ENGINE_FLOOR_IMAGE)"; \
	theirs=$$(grep -oE '^[[:space:]]+image: [^[:space:]]+' .github/workflows/ci.yml \
	  | awk '{print $$2}' | sort -u); \
	for image in $$ours; do \
	  echo "$$theirs" | grep -qxF "$$image" \
	    || { echo "$$image is pinned here, and CI runs no such server."; exit 1; }; \
	done; \
	for image in $$theirs; do \
	  printf '%s\n' $$ours | grep -qxF "$$image" \
	    || { echo "CI runs $$image, and nothing here starts one."; exit 1; }; \
	done

# The documentation site, built the way CI builds it.
#
# A target because everything CI runs is one: this was the last check that
# existed only in the workflow, so a broken link or a page missing from the
# navigation failed there and nowhere a developer could reproduce it.
.PHONY: docs-site
docs-site:
	$(PYTHON) -m mkdocs build --strict

# The other pinned pairs, checked the same way and for the same reason.
#
# A version written in two files is one somebody moves in one of them. The
# database images had a check and these did not, so the toolchain the container
# builds with could drift from the one the module declares, the Node the image
# uses from the one CI runs, and the SBOM generator in the image from the one
# the SBOM target invokes — each silently, and each producing an artifact built
# with something other than what was tested.
#
# Named rather than folded into engines-check, because that one is about what
# the tests run against and this is about what the release is built from.
# The tidy run rewrites the tree, so what it found there is put back on every
# exit path — including an interrupt, which used to leave the tree as tidy had
# made it and the copies behind under a name every checkout on the machine
# shared.
.PHONY: pins-check
pins-check:
	@fail=0; \
	block() { sed -n '/^## Scope$$/,/^- Build or deploy fixes$$/p' "$$1"; }; \
	[ -n "$$(block README.md)" ] || { \
	  echo "the shared block is empty in README.md, so this compared nothing."; fail=1; }; \
	[ -n "$$(block docs/index.md)" ] || { \
	  echo "the shared block is empty in docs/index.md, so this compared nothing."; fail=1; }; \
	[ "$$(block README.md)" = "$$(block docs/index.md)" ] || { \
	  echo "README.md and docs/index.md describe what this does in different words."; \
	  echo "They are the same list maintained twice; make them the same words."; fail=1; }; \
	declared=$$(awk '/^go /{print $$2}' go.mod); \
	image=$$(sed -n 's/^FROM golang:\([0-9.]*\)-.*/\1/p' Dockerfile); \
	[ "$$declared" = "$$image" ] || { \
	  echo "go.mod declares Go $$declared and the image builds with $$image."; \
	  echo "The patch counts: the release ships a binary built by each."; fail=1; }; \
	here=$$(awk -F'= ' '/^CDXGOMOD_VERSION/{print $$2}' Makefile | tr -d ' \t'); \
	there=$$(awk -F= '/^ARG CDXGOMOD_VERSION/{print $$2}' Dockerfile); \
	[ "$$here" = "$$there" ] || { \
	  echo "the SBOM generator is $$here here and $$there in the image."; fail=1; }; \
	node=$$(awk -F'[:-]' '/^FROM node:/{print $$2}' Dockerfile); \
	for flow in .github/workflows/*.yml; do \
	  for said in $$(awk -F': ' '/node-version:/{print $$2}' "$$flow" | tr -d ' '); do \
	    [ "$$said" = "$$node" ] || { \
	      echo "the image builds the interface with Node $$node and $$flow uses $$said."; \
	      fail=1; }; \
	  done; \
	done; \
	defaults=$$(grep -c '^ARG VERSION=' Dockerfile); \
	distinct=$$(grep '^ARG VERSION=' Dockerfile | sort -u | wc -l); \
	[ "$$distinct" -le 1 ] || { \
	  echo "the image has $$defaults version defaults and they differ, so an"; \
	  echo "unpassed build says one thing in the binary and another in its SBOM."; \
	  fail=1; }; \
	# Every count is taken with "|| true": grep exits 1 on a count of zero, \
	# recipes run under -e, and a check that dies on the empty case is one \
	# that says nothing where it has the most to say. \
	pinned=$$(grep -cE '^[A-Za-z0-9][^ ]*==' docs/requirements.txt || true); \
	hashed=$$(grep -cE '^[A-Za-z0-9][^ ]*==.*\\$$' docs/requirements.txt || true); \
	[ "$$pinned" -gt 0 ] || { \
	  echo "docs/requirements.txt names no packages, so nothing about it is pinned."; fail=1; }; \
	[ "$$pinned" = "$$hashed" ] || { \
	  echo "$$pinned packages are named in docs/requirements.txt and $$hashed carry a hash."; \
	  echo "Regenerate it from docs/requirements.in rather than editing it:"; \
	  echo "  pip-compile --generate-hashes --no-index --output-file=docs/requirements.txt docs/requirements.in"; \
	  fail=1; }; \
	asked=0; \
	for wanted in $$(grep -E '^[A-Za-z0-9]' docs/requirements.in); do \
	  asked=$$((asked + 1)); \
	  grep -q "^$$wanted " docs/requirements.txt || { \
	    echo "docs/requirements.in asks for $$wanted and the lock beside it does not."; fail=1; }; \
	done; \
	[ "$$asked" -gt 0 ] || { \
	  echo "docs/requirements.in asks for nothing, so the lock was compared against nothing."; fail=1; }; \
	installs=0; \
	for flow in .github/workflows/*.yml; do \
	  bare=$$(grep -c 'pip install' "$$flow" || true); \
	  [ "$$bare" -gt 0 ] || continue; \
	  installs=$$((installs + bare)); \
	  hashes=$$(grep -c 'pip install --require-hashes' "$$flow" || true); \
	  [ "$$bare" = "$$hashes" ] || { \
	    echo "$$flow installs the documentation closure $$bare times and $$hashes of those"; \
	    echo "require hashes, so the hashes beside every package buy that job nothing."; fail=1; }; \
	done; \
	[ "$$installs" -gt 0 ] || { \
	  echo "no workflow installs the documentation closure, so --require-hashes was checked nowhere."; \
	  fail=1; }; \
	python=$$(awk -F': ' '/python-version:/{gsub(/['"'"'" ]/, "", $$2); print $$2}' \
	  .github/workflows/*.yml | sort -u | tr '\n' ' '); \
	lock=$$(awk '/autogenerated by pip-compile with Python /{print $$NF; exit}' docs/requirements.txt); \
	[ -n "$$python" ] || { \
	  echo "no workflow names a Python version, so the lock was compared against nothing."; fail=1; }; \
	[ -n "$$lock" ] || { \
	  echo "docs/requirements.txt does not say which Python resolved it."; fail=1; }; \
	case "$$python" in \
	  *" "*" "*) echo "the workflows build the documentation on more than one Python: $$python."; \
	    echo "The lock was resolved on one of them."; fail=1 ;; \
	  "$$lock "*) ;; \
	  *) echo "the workflows use Python $${python% } and the lock was resolved on $$lock."; fail=1 ;; \
	esac; \
	kept=$$(mktemp -d) || { echo "no temporary directory, so go.mod could not be kept"; exit 1; }; \
	trap 'cp "$$kept"/go.mod go.mod; cp "$$kept"/go.sum go.sum; rm -rf "$$kept"' EXIT; \
	trap 'exit 130' INT TERM; \
	cp go.mod go.sum "$$kept"/; \
	$(GO) mod tidy; \
	cmp -s go.mod "$$kept"/go.mod && cmp -s go.sum "$$kept"/go.sum || { \
	  echo "go.mod or go.sum is not what go mod tidy produces: a dependency is"; \
	  echo "declared that nothing imports, or one is imported and not declared."; \
	  echo "A requirement nothing uses stays in the vulnerability and license"; \
	  echo "surface for code that never runs. Run go mod tidy and commit it."; \
	  fail=1; }; \
	[ "$$fail" = 0 ] || exit 1

# Measurements, not gates.
#
# These take minutes, assert almost nothing, and produce numbers to write down.
# They are behind a build tag so that "check" never runs them and nobody has to
# decide whether a slow run is a failure — a decision here carries the
# measurement that forced it, and this is where those come from.
#
# Point it at a real server. SQLite answers a different question: one writer,
# one connection, and nothing a deployment runs on.
# Which packages hold a measurement. Named here rather than globbed, because a
# package with no measurement in it is a run that reports "no tests to run",
# which -run already refuses for the whole invocation.
MEASURED := ./internal/finding/ ./internal/triage/

measure:
ifneq ($(ENGINES_MISSING),)
	@echo "Not configured: $(ENGINES_MISSING). A measurement taken on SQLite alone"
	@echo "describes one writer on one connection, which is not what a deployment"
	@echo "runs — so this refuses rather than producing a number that reads like"
	@echo "four engines and is one. Run 'make engines-up'."
	@exit 1
endif
	@# -run has to match something, in every package. A renamed test or a
	@# mistyped tag makes "no tests to run" a green exit, which is the same
	@# green as a measurement nobody took — and a package matching nothing
	@# still exits 0 while its neighbour's output satisfies one grep, so the
	@# check is per package rather than over the combined run.
	@for pkg in $(MEASURED); do \
	  out=$$(mktemp); \
	  $(GO) test -tags measure -count=1 -v -timeout 60m \
	    -run 'TestMeasure' "$$pkg" 2>&1 | tee "$$out"; \
	  grep -q "^=== RUN   TestMeasure" "$$out" \
	    || { echo "no measurement ran in $$pkg: -run matched nothing"; rm -f "$$out"; exit 1; }; \
	  rm -f "$$out"; \
	done

# Requires docker and helm. Skipped by "check" so that a machine without them
# can still run everything else.
# CHECK_IMAGE is what the packaging checks run against. Left at the default it
# is built here; CI passes the tag it has already built, so the same checks run
# in both places rather than being written twice and drifting.
CHECK_IMAGE ?= openpsirt:check

# Whether the two tools this needs are here, asked once rather than per line.
PACKAGING_TOOLS := $(shell command -v docker >/dev/null 2>&1 && \
                     command -v helm >/dev/null 2>&1 && echo yes)

check-packaging:
ifeq ($(PACKAGING_TOOLS),)
	@# Said rather than passed silently. The gate runs this now, so a machine
	@# without docker or helm must still be able to run the gate — and a skip
	@# that looks like a pass is what every other check here is written to
	@# avoid, which is why it names what it did not do.
	@echo "docker or helm is not installed, so the image and the chart are unchecked here."
	@echo "CI runs both on every push; install them to run these before one."
else
	@# Not quiet, for the reason dist-inventories is not: a build that fails
	@# without saying why is diagnosed by running it again differently.
	@if [ "$(CHECK_IMAGE)" = "openpsirt:check" ]; then \
	  docker build -t $(CHECK_IMAGE) .; \
	fi
	docker run --rm $(CHECK_IMAGE) -version
	@test "$$(docker run --rm --entrypoint id $(CHECK_IMAGE) -u)" != "0" \
	  || { echo "image runs as root"; exit 1; }
	@docker run --rm --entrypoint /usr/local/bin/grype $(CHECK_IMAGE) version >/dev/null \
	  || { echo "image carries no working scanner, so it could ingest and never scan"; exit 1; }
	@# That the image serves the interface, not merely that it starts. The Go
	@# build embeds a git-ignored directory, so an image built from a clean
	@# checkout carried no interface at all and every other check here passed.
	@set -e; \
	  id=$$(docker run -d --rm -p 127.0.0.1:0:8080 \
	         --tmpfs /tmp \
	         -e OPENPSIRT_DATABASE_URL="sqlite:///tmp/check.db" \
	         -e OPENPSIRT_ADDR="0.0.0.0:8080" \
	         -e OPENPSIRT_PLAIN_HTTP=1 \
	         -e OPENPSIRT_BOOTSTRAP_ADMINS=check \
	         $(CHECK_IMAGE)); \
	  trap 'docker rm -f $$id >/dev/null 2>&1 || true' EXIT; \
	  port=$$(docker port $$id 8080/tcp | head -1 | sed 's/.*://'); \
	  waited=0; \
	  until curl -fsS --noproxy '*' "http://127.0.0.1:$$port/readyz" >/dev/null 2>&1; do \
	    waited=$$((waited + 1)); \
	    [ $$waited -gt 60 ] && { echo "the image never became ready"; exit 1; }; \
	    sleep 1; \
	  done; \
	  curl -fsS --noproxy '*' "http://127.0.0.1:$$port/" | grep -qi '<!doctype html' \
	    || { echo "the image serves no interface: it was built without one"; exit 1; }
	helm lint deploy/helm/openpsirt --set database.url=postgres://u:p@h:5432/d \
	  --set auth.bootstrapAdmins='{admin}' --set auth.trustedHeader.name=X-Forwarded-User \
	  --set auth.trustedHeader.sources='{10.0.0.0/8}'
	helm template t deploy/helm/openpsirt --set database.existingSecret=s \
	  --set auth.bootstrapAdmins='{admin}' --set auth.baseURL=https://psirt.example.com \
	  --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc \
	  --set auth.oidc.clientSecret=shh --set auth.oidc.usernameClaim=sub >/dev/null
	# An install that cannot reach a login is not an install, and mail that is
	# half configured is mail nobody gets. Each of these refuses at template
	# time rather than producing a deployment that starts, fails its own
	# administration check, and crash-loops with the reason in a log nobody is
	# watching yet — or one that comes up healthy and quietly tells nobody.
	@# Each case names the substring the chart's own fail must carry. Branching
	@# on the exit status alone with both streams discarded, any template error
	@# read as the refusal — so an unrelated fault reachable under one value
	@# combination looked exactly like the guard working, and the success line
	@# below printed anyway.
	@refusals=0; \
	for missing in \
	  "no database|needs a database|" \
	  "nobody can administer|set auth.bootstrapAdmins|--set database.existingSecret=s" \
	  "no way to sign in|configure a way to sign in|--set database.existingSecret=s --set auth.bootstrapAdmins={admin}" \
	  "no address to return to|set auth.baseURL|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.oidc.issuer=https://id.example.com" \
	  "a header anybody can set|set auth.trustedHeader.sources|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User" \
	  "half a mail configuration|set mail.server and mail.from together|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587" \
	  "a password that is never sent|set mail.username|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587 --set mail.from=psirt@example.com --set mail.password=shh" \
	  "a provider and no client secret|set auth.oidc.clientSecret|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc" \
	  "a provider and no username claim|set auth.oidc.usernameClaim|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.clientSecret=shh" \
	  "a GitHub app and no client secret|set auth.github.clientSecret|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.github.clientID=gh" \
	  "a secret given twice|not both|--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.baseURL=https://p.example.com --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.usernameClaim=sub --set auth.oidc.clientSecret=shh --set auth.oidc.existingSecret=mine"; do \
	  refusals=$$((refusals + 1)); \
	  what="$${missing%%|*}"; rest="$${missing#*|}"; \
	  expect="$${rest%%|*}"; args="$${rest#*|}"; \
	  out=$$(helm template t deploy/helm/openpsirt $$args 2>&1) && { \
	    echo "the chart accepted an install with $$what"; exit 1; }; \
	  case "$$out" in \
	    *"$$expect"*) ;; \
	    *) echo "the chart refused an install with $$what for the wrong reason:"; \
	       echo "$$out"; exit 1;; \
	  esac; \
	done; \
	  [ "$$refusals" -gt 0 ] || { echo "no refusal was examined, so this checked nothing"; exit 1; }; \
	  echo "  $$refusals installs the chart has to refuse, each for the reason it names"
	@echo "the chart refuses every install that could not be signed into or could not start, and every mail configuration that would send nothing"
	@# The refusals above assert that an install the chart cannot serve fails
	@# at render. These assert the other half: that a legal one renders a
	@# reference something answers. A secretKeyRef naming a Secret nothing
	@# creates, or a key nothing writes, renders perfectly and leaves a pod
	@# that can never start — the same failure the refusals exist to prevent,
	@# one step later and with no message anybody reads.
	@#
	@# Read out of the render rather than compared against a list written
	@# here: a fifth secret source added later gets no row in a list and the
	@# check stays green on exactly the defect it is for. Every reference a
	@# legal install renders is resolved against the Secrets that same install
	@# creates, and the count of what was examined is printed, because a walk
	@# that found nothing looks like a walk that found nothing wrong.
	@#
	@# Every value is held by the chart in these, because a Secret the
	@# operator manages is not in the render and a reference to one cannot be
	@# resolved here. That arm is asserted below, against what they named.
	@set -e; base="--set auth.bootstrapAdmins={admin} --set auth.baseURL=https://psirt.example.com"; \
	refs=0; \
	for install in \
	  "a database URL the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8}" \
	  "an OIDC secret the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.usernameClaim=sub --set auth.oidc.clientSecret=shh" \
	  "a GitHub secret the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.github.clientID=gh --set auth.github.clientSecret=shh" \
	  "a mail password the chart holds|--set database.url=postgres://u:p@h:5432/d --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587 --set mail.from=psirt@example.com --set mail.username=u --set mail.password=shh" \
	  "every secret the chart holds at once|--set database.url=postgres://u:p@h:5432/d --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc --set auth.oidc.usernameClaim=sub --set auth.oidc.clientSecret=shh --set mail.server=smtp:587 --set mail.from=psirt@example.com --set mail.username=u --set mail.password=shh"; do \
	  what="$${install%%|*}"; args="$${install#*|}"; \
	  out=$$(helm template t deploy/helm/openpsirt $$base $$args) \
	    || { echo "the chart refused $$what:"; echo "$$out"; exit 1; }; \
	  written=$$(printf '%s\n' "$$out" | awk '\
	    /^kind: Secret$$/ {secret=1; next} \
	    /^---/ {secret=0; holds=0; next} \
	    secret && /^  name:/ {name=$$2; next} \
	    secret && /^stringData:$$/ {holds=1; next} \
	    holds && /^  [A-Za-z0-9_-]+:/ {key=$$1; sub(":", "", key); print name "/" key}' | tr '\n' ' '); \
	  found=$$(printf '%s\n' "$$out" | awk '\
	    /secretKeyRef:/ {ref=1; next} \
	    ref && /name:/ {name=$$2; next} \
	    ref && /key:/ {print name "/" $$2; ref=0}'); \
	  [ -n "$$found" ] || { echo "$$what renders no secret reference at all"; exit 1; }; \
	  for one in $$found; do \
	    refs=$$((refs + 1)); \
	    case " $$written " in \
	      *" $$one "*) ;; \
	      *) echo "with $$what the chart asks for $$one and creates [$$written]"; exit 1 ;; \
	    esac; \
	  done; \
	done; \
	[ "$$refs" -gt 0 ] || { echo "no secret reference was examined, so this checked nothing"; exit 1; }; \
	echo "  $$refs secret references, every one of them answered by a Secret the same install writes"
	@# The operator's own Secret is the other arm, and cannot be resolved
	@# inside the render because it is theirs. What is asserted there is that
	@# the reference names what they named, rather than the chart's own key.
	@set -e; out=$$(helm template t deploy/helm/openpsirt \
	  --set database.existingSecret=s --set auth.bootstrapAdmins={admin} \
	  --set auth.baseURL=https://psirt.example.com \
	  --set auth.oidc.issuer=https://id.example.com --set auth.oidc.clientID=abc \
	  --set auth.oidc.usernameClaim=sub \
	  --set auth.oidc.existingSecret=mine --set auth.oidc.existingSecretKey=theirs); \
	  got=$$(printf '%s\n' "$$out" | awk '\
	    $$0 ~ "name: OPENPSIRT_OIDC_CLIENT_SECRET$$" {f=1; next} \
	    f && /secretKeyRef:/ {g=1; next} \
	    g && /name:/ {n=$$2; next} \
	    g && /key:/ {print n, $$2; exit}'); \
	  [ "$$got" = "mine theirs" ] \
	    || { echo "with a Secret the operator holds, the chart asks for [$$got]"; exit 1; }
	@echo "every secret the chart renders a reference to is one it creates, under the key it wrote"
endif

run:
	$(GO) run ./cmd/openpsirt

clean-web:
	rm -rf web/node_modules web/dist internal/webui/dist/assets internal/webui/dist/index.html

clean:
	rm -rf bin

include Makefile.demo
