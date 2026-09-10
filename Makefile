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

NPM ?= npm

# A throwaway deployment to click around in. Everything about it is
# overridable, because the two settings people get wrong are the host they
# browse to and who they arrive as.
#
#   DEMO_HOST   where this waits for the container to answer, and what the
#               status line prints. Not what you have to type: the demo is not
#               told a base address, so it answers on whatever name you reach
#               it by
#   DEMO_USER   who you arrive as. The trusted-header path prefixes it, so the
#               administrator is proxy:$(DEMO_USER)
DEMO_HOST ?= localhost
DEMO_PORT ?= 8080
DEMO_USER ?= dev
# The rest of the cast, one per line as port:identity:roles.
#
# **One person cannot demonstrate this tool.** Approving your own claim is
# refused, because a control one person completes alone is not one (TRI-41) —
# so a demo with a single identity can propose a judgment and can never show it
# agreed to, and the record an auditor reads says "same person" against every
# row. Somebody has to be somebody else.
#
# A port each rather than a switcher: the trusted-header path is a proxy
# stating who you are, and the smallest honest version of two people is two
# doors. Open two browser windows and you are two people, which is also what
# lets one of them watch the other's claim arrive.
#
# Roles are granted per product, so the seed grants each of these on every
# product it declares. Nobody is an administrator but the first: an approver
# who could also change the settings would not be exercising anything.
DEMO_CAST ?= 8081:ana:public-read,public-triage,approver \
             8082:ben:public-read,public-triage,approver
# What the demo and the dev loop seed, one build per entry:
#   inventory,product,display name,branch,variant
# The inventory is an .xz of a CycloneDX file under the SBOM package's
# testdata. Adding a variant is adding a line — a second variant of the same
# product is what exercises decisions carrying across variants (REL-01,
# REL-09), so the mellanox build of the switch image belongs here once it is
# saved beside the broadcom one.
DEMO_BUILDS ?= internal/sbom/testdata/switch-image.cdx.json.xz,sonic,SONiC,master,broadcom \
               internal/sbom/testdata/switch-image-mellanox.cdx.json.xz,sonic,SONiC,master,mellanox
# In the tree rather than under $HOME: a command that writes to somebody's home
# directory from a checkout is a surprise, and everything here is throwaway
# state that should be deleted by deleting the checkout. Git-ignored.
DEMO_DIR   ?= $(CURDIR)/.demo
DEMO_IMAGE ?= openpsirt:demo
DEMO_NET   ?= openpsirt-demo
# Fixed so the application can be told which addresses to trust the sign-in
# header from. A range docker hands out at random cannot be named in advance.
DEMO_SUBNET ?= 172.31.71.0/24
DEMO_URL    := http://$(DEMO_HOST):$(DEMO_PORT)

# The developer loop is a different thing and says so. It runs the binary and
# the interface's own dev server on this machine, for the fast edit-and-reload
# cycle; it needs Go, node and a scanner installed here, and it serves the
# interface from the dev server rather than from the binary — so it exercises a
# configuration nobody deploys.
DEV_HOST ?= localhost
DEV_PORT ?= 5173
DEV_API  ?= 127.0.0.1:8081
DEV_DIR  ?= $(DEMO_DIR)/dev
DEV_DB   ?= $(DEV_DIR)/dev.db
DEV_URL  := http://$(DEV_HOST):$(DEV_PORT)

.PHONY: secrets web-audit dist dist-clean dist-version dist-binaries dist-chart dist-inventories dist-sums dist-verify gate full docs-check unreachable unclaimed reserved reserved-words readable all build test test-all test-race test-engines vet lint fmt openapi openapi-current run clean check check-packaging check-engines measure engines-up engines-down engines-status engines-check tools govulncheck licenses sbom web web-deps web-api web-check scanner-db scanner-db-verify demo demo-image demo-up demo-down demo-seed demo-vex demo-triage demo-flaw demo-reset demo-status dev dev-up dev-down dev-seed dev-reset dev-status

all: check build

build:
	@mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/openpsirt

# The quick loop: SQLite only, packages in parallel, the build cache on, no
# race detector. Seconds, so it is run after every change. The four-engine,
# race-detected, uncached run is test-all, and the gate uses that.
test:
	OPENPSIRT_TEST_ENGINES=sqlite $(GO) test ./...

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
test-all: test-race test-engines

# The detector, on the engine every checkout has.
test-race:
	OPENPSIRT_TEST_ENGINES=sqlite $(GO) test -race -count=1 ./...

# The three server engines, without it. Their time is spent waiting on a
# socket, which is not where a race is found: 16.9 s against 12.0 s for the API
# package on MariaDB, where the same package on SQLite is 73.6 s against 10.1 s.
test-engines:
	OPENPSIRT_TEST_ENGINES=postgres,mysql,mariadb $(GO) test -count=1 ./...

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
	$(GO) vet ./...

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run

fmt:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) fmt

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# Both halves of what ships, against one allowlist.
#
# The interface is built into the binary, so its dependencies are shipped
# exactly as the Go ones are — and they went unchecked until the platform
# product that would have caught them turned out to be a paid add-on on a
# private repository. The allowlist is this variable, passed to both, because
# a policy written in two files is a policy that differs in one of them.
licenses:
	$(GO) run github.com/google/go-licenses@$(GOLICENSES_VERSION) check ./... \
		--allowed_licenses=$(ALLOWED_LICENSES) \
		$(foreach m,$(LICENSE_EXCEPTIONS),--ignore=$(m))
	@command -v $(NPM) >/dev/null 2>&1 \
	  || { echo "npm not found, so the interface's licenses are unchecked here"; exit 1; }
	@ALLOWED_LICENSES=$(ALLOWED_LICENSES) $(NPM) --prefix web run --silent licenses

# We ingest SBOMs, so we publish one for ourselves. CycloneDX because that is
# the format this project treats as authoritative on the way in.
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
dist:
	@$(MAKE) --no-print-directory dist-version
	@$(MAKE) --no-print-directory dist-clean
	@$(MAKE) --no-print-directory dist-binaries
	@$(MAKE) --no-print-directory dist-chart
	@$(MAKE) --no-print-directory dist-inventories
	@$(MAKE) --no-print-directory dist-sums
	@$(MAKE) --no-print-directory dist-verify
	@echo "$(DIST_DIR) holds $$(ls -1 $(DIST_DIR) | wc -l) files for $(DIST_VERSION)"

# A release is cut from a tag, and nothing else is a release.
#
# An untagged commit describes as a bare hash and a modified tree as
# "-dirty" — both name a version nobody can get back to, and neither is
# something a chart will accept. Overridable, because building the assets to
# look at them is a reasonable thing to want: DIST_VERSION=0.0.0-dev.
dist-version:
	@case "$(DIST_VERSION)" in \
	  *-dirty) echo "the tree is dirty, so $(DIST_VERSION) names no commit anybody else can get"; exit 1 ;; \
	esac
	@printf '%s' "$(DIST_VERSION)" \
	  | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)*$$' \
	  || { echo "$(DIST_VERSION) is not a version a chart can carry: tag the commit, or pass DIST_VERSION=0.0.0-dev"; exit 1; }

dist-clean:
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)

# The binaries, one archive per architecture, each carrying the license it is
# under. Cross-compiled rather than built in a container: the SQLite driver is
# pure Go and cgo is off, so every supported architecture builds here in
# seconds and none of them needs emulation.
dist-binaries: STAMP_VERSION := $(DIST_VERSION)
dist-binaries:
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
dist-chart:
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
dist-inventories:
	@mkdir -p $(DIST_DIR)
	@command -v $(DOCKER) >/dev/null 2>&1 \
	  || { echo "$(DOCKER) is needed to read the inventories out of the image"; exit 1; }
	@echo "  building $(DIST_IMAGE):$(DIST_VERSION) for $(DIST_IMAGE_ARCH)"
	@$(DOCKER) build -q -t $(DIST_IMAGE):$(DIST_VERSION) \
	  --build-arg VERSION=$(DIST_VERSION) --build-arg COMMIT=$(COMMIT) \
	  --build-arg DATE=$(DATE) --build-arg CDXGOMOD_VERSION=$(CDXGOMOD_VERSION) . >/dev/null
	@$(DOCKER) run --rm --entrypoint cat $(DIST_IMAGE):$(DIST_VERSION) \
	  /usr/share/openpsirt/openpsirt.cdx.json > $(DIST_DIR)/openpsirt_$(DIST_VERSION).cdx.json
	@$(DOCKER) run --rm --entrypoint cat $(DIST_IMAGE):$(DIST_VERSION) \
	  /usr/share/openpsirt/image.cdx.json \
	  > $(DIST_DIR)/openpsirt-image_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH).cdx.json
	@echo "  openpsirt_$(DIST_VERSION).cdx.json"
	@echo "  openpsirt-image_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH).cdx.json"

# One file covering every other, so a download can be checked without holding
# a signature or trusting the page it came from.
dist-sums:
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
dist-verify:
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
	    said=$$("$$work"/openpsirt_$(DIST_VERSION)_linux_$(DIST_IMAGE_ARCH)/openpsirt -version | awk '{print $$2}'); \
	    [ "$$said" = "$(DIST_VERSION)" ] \
	      || { echo "the binary reports $$said and its archive says $(DIST_VERSION)"; fail=1; }; \
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

# The document is generated from the running registrations, never hand-written.
openapi:
	@mkdir -p docs/reference
	$(GO) run ./cmd/openpsirt -openapi > docs/reference/openapi.yaml
	@echo "wrote docs/reference/openapi.yaml"

# Everything CI runs, reachable from one command. Container and chart checks
# are included because CI runs them; omitting them meant four of nine jobs
# could not be reproduced locally.
check: build vet lint unreachable unclaimed reserved readable pins-check test-all govulncheck licenses secrets openapi-current sbom web-check
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
	$(NPM) --prefix web ci

# The client is generated from the committed document (UIX-19), so a drifted
# document is a compile error in the interface rather than a runtime surprise.
web-api: openapi
	$(NPM) --prefix web run api
	@git diff --exit-code -- web/src/api/schema.d.ts \
	  || { echo "web/src/api/schema.d.ts is stale: run make web-api and commit it"; exit 1; }

# What CI runs for the interface. Skipped with a note rather than failing where
# there is no node, so the Go half still gates on a machine without it.
web-check:
	@command -v $(NPM) >/dev/null 2>&1 \
	  || { echo "npm not found, so the interface is unchecked here"; exit 0; }
	$(MAKE) web-deps
	$(NPM) --prefix web run typecheck
	$(NPM) --prefix web run format
	$(NPM) --prefix web run lint
	$(NPM) --prefix web run stylelint
	$(NPM) --prefix web test
	$(NPM) --prefix web run classes
	$(NPM) --prefix web run tokens
	$(NPM) --prefix web run ladder
	$(MAKE) web-audit
	$(MAKE) web-api

# Known vulnerabilities in what the interface installs.
#
# The counterpart to govulncheck, and the other half of REQ-75's vulnerability
# scanning: govulncheck reads Go modules and says nothing at all about npm.
# The advisory data is the registry's, so this needs a network and says so
# rather than passing when it cannot reach one.
#
# High and above fails. Everything is reported, because "one moderate" and
# "forty moderates" are different facts and only one of them is worth a look.
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

# Names this code invents that an engine refuses to parse. Queries are written
# once and run against four engines, and the four do not reserve the same
# words: `groups` is PostgreSQL's, `usage` is MySQL's, and either would leave
# the suite green on three engines and a deployment on the fourth unable to
# answer.
reserved:
	$(GO) run ./internal/tools/reserved

# The word list the check above reads, asked of the engines rather than typed.
# Needs them running: "make engines-up" first. MariaDB has no KEYWORDS table,
# so the words it reserves that MySQL does not are held by hand in words.go and
# this leaves them alone.
reserved-words:
	@echo "regenerate internal/tools/reserved/words.go from the running engines:"
	@echo "  PostgreSQL: SELECT word FROM pg_get_keywords() WHERE catcode IN ('R','T')"
	@echo "  MySQL:      SELECT LOWER(WORD) FROM INFORMATION_SCHEMA.KEYWORDS WHERE RESERVED=1"
	@echo "and merge with the MariaDB and SQLite words already listed there."

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
check-engines:
ifneq ($(ENGINES_MISSING),)
	@echo "Not configured: $(ENGINES_MISSING). SQLite alone tests none of the"
	@echo "portability traps, so this refuses rather than passing. See AGENTS.md."
	@exit 1
endif
	@out=$$(mktemp); trap 'rm -f "$$out"' EXIT; \
	  $(GO) test ./internal/schema/ -count=1 -v -run TestMigrationsApplyOnEveryEngine \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  for engine in sqlite postgres mysql mariadb; do \
	    grep -q "PASS: TestMigrationsApplyOnEveryEngine/$$engine" "$$out" \
	      || { echo "$$engine did not run"; exit 1; }; \
	  done
	@out=$$(mktemp); trap 'rm -f "$$out"' EXIT; \
	  $(GO) test ./internal/database/migrate/ -count=1 -v -run TestLockExcludes \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  for engine in postgres mysql mariadb; do \
	    grep -q "PASS: TestLockExcludesAnotherConnection/$$engine" "$$out" \
	      || { echo "the migration lock was not exercised on $$engine"; exit 1; }; \
	  done
	@out=$$(mktemp); trap 'rm -f "$$out"' EXIT; \
	  $(GO) test ./internal/dbtest/ -count=1 -v -run TestEachEngineIsTheEngineItSaysItIs \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  for engine in sqlite postgres mysql mariadb; do \
	    grep -q "PASS: TestEachEngineIsTheEngineItSaysItIs/$$engine" "$$out" \
	      || { echo "$$engine was not checked for being itself"; exit 1; }; \
	  done
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
engines-down:
	@$(DOCKER) rm -f $(ENGINE_PREFIX)-pg16 $(ENGINE_PREFIX)-mysql \
	  $(ENGINE_PREFIX)-mariadb $(ENGINE_PREFIX)-floor >/dev/null 2>&1 || true
	@echo "removed. local.mk was left alone; 'make engines-up' reuses it."

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
.PHONY: pins-check
pins-check:
	@fail=0; \
	block() { sed -n '/^## What it does$$/,/^- Build or deploy fixes$$/p' "$$1"; }; \
	[ "$$(block README.md)" = "$$(block docs/index.md)" ] || { \
	  echo "README.md and docs/index.md describe what this does in different words."; \
	  echo "They are the same list maintained twice; make them the same words."; fail=1; }; \
	declared=$$(awk '/^go /{print $$2}' go.mod | cut -d. -f1,2); \
	image=$$(awk -F'[:-]' '/^FROM golang:/{print $$2}' Dockerfile); \
	[ "$$declared" = "$$image" ] || { \
	  echo "go.mod declares Go $$declared and the image builds with $$image."; fail=1; }; \
	here=$$(awk -F'= ' '/^CDXGOMOD_VERSION/{print $$2}' Makefile | tr -d ' \t'); \
	there=$$(awk -F= '/^ARG CDXGOMOD_VERSION/{print $$2}' Dockerfile); \
	[ "$$here" = "$$there" ] || { \
	  echo "the SBOM generator is $$here here and $$there in the image."; fail=1; }; \
	node=$$(awk -F'[:-]' '/^FROM node:/{print $$2}' Dockerfile); \
	ci=$$(awk -F': ' '/node-version:/{print $$2}' .github/workflows/ci.yml | tr -d ' '); \
	[ "$$node" = "$$ci" ] || { \
	  echo "the image builds the interface with Node $$node and CI uses $$ci."; fail=1; }; \
	defaults=$$(grep -c '^ARG VERSION=' Dockerfile); \
	distinct=$$(grep '^ARG VERSION=' Dockerfile | sort -u | wc -l); \
	[ "$$distinct" -le 1 ] || { \
	  echo "the image has $$defaults version defaults and they differ, so an"; \
	  echo "unpassed build says one thing in the binary and another in its SBOM."; \
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
measure:
ifneq ($(ENGINES_MISSING),)
	@echo "Not configured: $(ENGINES_MISSING). A measurement taken on SQLite alone"
	@echo "describes one writer on one connection, which is not what a deployment"
	@echo "runs — so this refuses rather than producing a number that reads like"
	@echo "four engines and is one. Run 'make engines-up'."
	@exit 1
endif
	@# -run has to match something. A renamed test or a mistyped tag makes
	@# "no tests to run" a green exit, which is the same green as a
	@# measurement nobody took.
	@out=$$(mktemp); trap 'rm -f "$$out"' EXIT; \
	  $(GO) test -tags measure -count=1 -v -timeout 60m \
	    -run 'TestMeasure' ./internal/finding/ 2>&1 | tee "$$out"; \
	  grep -q "^=== RUN   TestMeasure" "$$out" \
	    || { echo "no measurement ran: -run matched nothing"; exit 1; }

# Requires docker and helm. Skipped by "check" so that a machine without them
# can still run everything else.
# CHECK_IMAGE is what the packaging checks run against. Left at the default it
# is built here; CI passes the tag it has already built, so the same checks run
# in both places rather than being written twice and drifting.
CHECK_IMAGE ?= openpsirt:check

check-packaging:
	@if [ "$(CHECK_IMAGE)" = "openpsirt:check" ]; then \
	  docker build -q -t $(CHECK_IMAGE) . >/dev/null; \
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
	  --set auth.oidc.clientSecret=shh >/dev/null
	# An install that cannot reach a login is not an install, and mail that is
	# half configured is mail nobody gets. Each of these refuses at template
	# time rather than producing a deployment that starts, fails its own
	# administration check, and crash-loops with the reason in a log nobody is
	# watching yet — or one that comes up healthy and quietly tells nobody.
	@for missing in \
	  "no database:" \
	  "nobody can administer:--set database.existingSecret=s" \
	  "no way to sign in:--set database.existingSecret=s --set auth.bootstrapAdmins={admin}" \
	  "no address to return to:--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.oidc.issuer=https://id.example.com" \
	  "a header anybody can set:--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User" \
	  "half a mail configuration:--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587" \
	  "a password that is never sent:--set database.existingSecret=s --set auth.bootstrapAdmins={admin} --set auth.trustedHeader.name=X-User --set auth.trustedHeader.sources={10.0.0.0/8} --set mail.server=smtp:587 --set mail.from=psirt@example.com --set mail.password=shh"; do \
	  what="$${missing%%:*}"; args="$${missing#*:}"; \
	  if helm template t deploy/helm/openpsirt $$args >/dev/null 2>&1; then \
	    echo "the chart accepted an install with $$what"; exit 1; \
	  fi; \
	done
	@echo "the chart refuses every install that could not be signed into, and every mail configuration that would send nothing"

run:
	$(GO) run ./cmd/openpsirt

# Bring up something to look at, seed it, and say where to go.
# Somewhere to click around in, as the thing that actually ships.
#
# One command, and the only thing it needs on this machine is docker: the image
# builds the interface and the binary inside itself, and carries the scanner.
# Testing a change is ordinary development, so standing an instance up has to be
# something anybody can do anywhere rather than a page of prerequisites.
#
# It is the real image behind a real proxy, which is the shape a deployment
# actually has (ACC-19, ACC-20) — not a development server standing in for one.
demo: demo-image demo-up demo-seed demo-status

# Built from the working tree, so what comes up is the change being tested.
# The offline scanner database, as a bundle an operator carries across the gap
# (ING-44).
#
# The scanner's vulnerability data is a hard requirement of a deployment rather
# than a packaging consideration (ING-22): without it the application ingests
# and never scans. An air-gapped install cannot fetch it, and what stood behind
# that requirement was a configuration variable and a paragraph — instructions
# somebody follows by hand, which is the kind of requirement that is discovered
# broken by the operator who most needs it, in the one situation where trying
# it out first is not available.
#
# Produced with the scanner the image carries, not with whatever is installed
# here: the database format is the scanner's, and a bundle built by a different
# version is a bundle that may not load.
#
# **It is verified before it is declared.** The check runs the same scanner
# against the bundle with the network off and auto-update refused, which is the
# configuration on the far side of the gap. A bundle that only exists is what
# this target refuses to produce.
SCANNER_DB_DIR ?= $(CURDIR)/dist
SCANNER_DB_TAG ?= $(shell date -u +%Y%m%d)
SCANNER_DB     := $(SCANNER_DB_DIR)/openpsirt-scanner-db-$(SCANNER_DB_TAG).tar.gz

scanner-db: demo-image
	@mkdir -p $(SCANNER_DB_DIR)
	@work=$$(mktemp -d); trap 'rm -rf "$$work"' EXIT; \
	  echo "downloading the vulnerability database with the image's own scanner"; \
	  $(DOCKER) run --rm -u "$$(id -u):$$(id -g)" -v "$$work:/db" \
	    -e GRYPE_DB_CACHE_DIR=/db -e HOME=/tmp \
	    --entrypoint /usr/local/bin/grype $(DEMO_IMAGE) db update >/dev/null; \
	  test -n "$$(ls -A "$$work")" \
	    || { echo "the scanner downloaded nothing"; exit 1; }; \
	  tar -czf "$(SCANNER_DB)" -C "$$work" .; \
	  ( cd $(SCANNER_DB_DIR) && sha256sum "$$(basename $(SCANNER_DB))" \
	      > "$$(basename $(SCANNER_DB)).sha256" )
	@$(MAKE) --no-print-directory scanner-db-verify BUNDLE=$(SCANNER_DB)
	@echo "  $(SCANNER_DB)"
	@echo "  $(SCANNER_DB).sha256"
	@echo "  carry both across; verify on the far side with:"
	@echo "    make scanner-db-verify BUNDLE=<the bundle>"
	@echo "  then unpack it into the scanner cache directory and set"
	@echo "    GRYPE_DB_AUTO_UPDATE=false"

# Prove a bundle is usable by a deployment that cannot reach the network.
#
# Runs with the network off and auto-update refused, which is the only
# configuration this is for. Available on the far side of the gap as well as
# here, because "it built" and "it loads where it has to" are different claims
# and the second is the one that matters.
scanner-db-verify:
ifndef BUNDLE
	@echo "name the bundle: make scanner-db-verify BUNDLE=dist/openpsirt-scanner-db-*.tar.gz"
	@exit 1
endif
	@test -f "$(BUNDLE)" || { echo "no such bundle: $(BUNDLE)"; exit 1; }
	@work=$$(mktemp -d); trap 'rm -rf "$$work"' EXIT; \
	  tar -xzf "$(BUNDLE)" -C "$$work"; \
	  $(DOCKER) run --rm --network none -u "$$(id -u):$$(id -g)" -v "$$work:/db:ro" \
	    -e GRYPE_DB_CACHE_DIR=/db -e HOME=/tmp \
	    -e GRYPE_DB_AUTO_UPDATE=false \
	    -e GRYPE_DB_VALIDATE_AGE=false \
	    --entrypoint /usr/local/bin/grype $(DEMO_IMAGE) db status \
	    || { echo "the bundle does not load with the network off, which is the" \
	         "only place it is for"; exit 1; }
	@echo "  the bundle loads with the network off and auto-update refused"

demo-image:
	@command -v $(DOCKER) >/dev/null 2>&1 \
	  || { echo "$(DOCKER) is needed to run the demo"; exit 1; }
	@echo "building $(DEMO_IMAGE) — the interface and the binary build inside it"
	@$(DOCKER) build -q -t $(DEMO_IMAGE) \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
	  --build-arg DATE=$(DATE) --build-arg CDXGOMOD_VERSION=$(CDXGOMOD_VERSION) . >/dev/null

demo-up: demo-down
	@mkdir -p $(DEMO_DIR)/data $(DEMO_DIR)/grype
	@$(DOCKER) network create --subnet $(DEMO_SUBNET) $(DEMO_NET) >/dev/null 2>&1 || true
	@# The vulnerability database is a gigabyte and does not change hourly, so
	@# it is kept between runs. Removing it is "make demo-reset --hard", which
	@# is deliberately not a thing: deleting .demo does it.
	@#
	@# Run as the invoking user rather than the image's own account, because
	@# the two mounts below come from the host and would otherwise be owned by
	@# somebody the container is not.
	@# The scanner fetches its vulnerability database on first use, so a
	@# machine that reaches the network through a proxy has to say so —
	@# a container inherits nothing of the shell that started it.
	@#
	@# And loopback is always excluded from it. Everything in the image that
	@# speaks HTTP honors these, including the health check, so passing a
	@# proxy through without this sends the container's own probe of itself to
	@# the proxy — which answers 403, and the container reports unhealthy while
	@# serving every request correctly.
	@$(DOCKER) run -d --name openpsirt-demo --network $(DEMO_NET) \
	  --user "$$(id -u):$$(id -g)" \
	  -e NO_PROXY="127.0.0.1,localhost,$${NO_PROXY}" \
	  -e no_proxy="127.0.0.1,localhost,$${no_proxy}" \
	  $${HTTP_PROXY:+-e HTTP_PROXY="$$HTTP_PROXY"} \
	  $${HTTPS_PROXY:+-e HTTPS_PROXY="$$HTTPS_PROXY"} \
	  $${http_proxy:+-e http_proxy="$$http_proxy"} \
	  $${https_proxy:+-e https_proxy="$$https_proxy"} \
	  -v "$(DEMO_DIR)/data:/data" \
	  -v "$(DEMO_DIR)/grype:/var/cache/openpsirt/grype" \
	  -e OPENPSIRT_DATABASE_URL="sqlite:///data/dev.db" \
	  -e OPENPSIRT_ADDR="0.0.0.0:8080" \
	  -e OPENPSIRT_PLAIN_HTTP=1 \
	  -e OPENPSIRT_BOOTSTRAP_ADMINS="proxy:$(DEMO_USER)" \
	  -e OPENPSIRT_TRUSTED_HEADER="X-User" \
	  -e OPENPSIRT_TRUSTED_SOURCES="$(DEMO_SUBNET)" \
	  -e OPENPSIRT_ATTACHMENT_DIR="/data/attachments" \
	  -e OPENPSIRT_PUBLISHER_NAME="OpenPSIRT Demo" \
	  -e OPENPSIRT_PUBLISHER_NAMESPACE="https://demo.openpsirt.invalid" \
	  $(DEMO_IMAGE) >/dev/null
	@# Files go on the container's disk rather than in an object store. That is
	@# the development backend and the demo says so on startup — one process
	@# and one disk — and standing a bucket up to show what attaching a file
	@# looks like would put a dependency between somebody and their first look.
	@# Deliberately no OPENPSIRT_BASE_URL. It is what a sign-in provider sends
	@# somebody back to, and the demo has no provider — but it is also what the
	@# forgery guard compares a browser's origin against, so setting it pins
	@# the demo to one hostname. Reaching it as anything else then reads
	@# perfectly and refuses every write with "not authorized", which is the
	@# guard working and looks nothing like it: somebody gets all the way
	@# through a decision and loses it at submit. Without it the guard compares
	@# against the request's own Host, which is sound for exactly this — a
	@# hostile page cannot make a browser send another site's Host.
	@# What authenticates. A deployment puts this application behind something
	@# that has already identified the caller and states who they are in a
	@# header; this is the smallest honest version of that, rather than a mode
	@# in the application that trusts anybody — which is a hole nobody should
	@# ship even switched off by default.
	@# One server block per person, each on its own port inside the proxy, so
	@# a second browser window is a second person. Written by a loop because
	@# the cast is configuration: adding somebody is adding a line to
	@# DEMO_CAST, not editing this three times.
	@: > $(DEMO_DIR)/proxy.conf
	@for entry in $(DEMO_USER):80 $(foreach c,$(DEMO_CAST),$(word 2,$(subst :, ,$(c))):$(word 1,$(subst :, ,$(c)))); do \
	    who=$${entry%%:*}; port=$${entry##*:}; \
	    printf '%s\n' \
	      'server {' \
	      "  listen $$port;" \
	      '  location / {' \
	      '    proxy_pass http://openpsirt-demo:8080;' \
	      "    proxy_set_header X-User $$who;" \
	      '    # $$http_host, not $$host: nginx strips the port from $$host, so a' \
	      '    # browser at name:8080 reaches an application that thinks it answers' \
	      '    # to name. Reads work and every write is refused by the forgery' \
	      '    # guard, which compares the origin the browser states against where' \
	      '    # this deployment believes it answers.' \
	      '    proxy_set_header Host $$http_host;' \
	      '    proxy_set_header X-Forwarded-For $$remote_addr;' \
	      '    client_max_body_size 256m;' \
	      '    proxy_read_timeout 300s;' \
	      '  }' \
	      '}' >> $(DEMO_DIR)/proxy.conf; \
	  done
	@# Said plainly before docker says it obscurely. A port already taken comes
	@# back as "driver failed programming external connectivity", which names
	@# neither the port nor what holds it — and the cast's ports are ordinary
	@# numbers somebody else's container may well be on.
	@# The "|| true" is load-bearing: recipes run under "-eo pipefail", so a
	@# grep that matches nothing — a free port, the good case — would otherwise
	@# end the recipe right here, before a word of any of this is printed.
	@for want in $(DEMO_PORT) $(foreach c,$(DEMO_CAST),$(word 1,$(subst :, ,$(c)))); do \
	  held=$$($(DOCKER) ps --format '{{.Names}} {{.Ports}}' | grep ":$$want->" | cut -d' ' -f1 || true); \
	  if [ -n "$$held" ]; then \
	    echo "  port $$want is already held by $$held."; \
	    echo "  Stop it, or set DEMO_PORT / DEMO_CAST to ports that are free."; \
	    exit 1; \
	  fi; \
	done
	@$(DOCKER) run -d --name openpsirt-demo-proxy --network $(DEMO_NET) \
	  -p $(DEMO_PORT):80 \
	  $(foreach c,$(DEMO_CAST),-p $(word 1,$(subst :, ,$(c))):$(word 1,$(subst :, ,$(c))) ) \
	  -v "$(DEMO_DIR)/proxy.conf:/etc/nginx/conf.d/default.conf:ro" \
	  nginx:1.29-alpine >/dev/null
	@# A container reported "Up" is not one that answers, the same trap the
	@# database servers have.
	@waited=0; \
	  until curl -fsS --noproxy '*' "$(DEMO_URL)/readyz" >/dev/null 2>&1; do \
	    waited=$$((waited + 1)); \
	    if [ $$waited -gt 60 ]; then \
	      echo "  it never answered. '$(DOCKER) logs openpsirt-demo' says why."; \
	      exit 1; \
	    fi; \
	    sleep 1; \
	  done
	@echo "  up at $(DEMO_URL)"

demo-down:
	@-$(DOCKER) rm -f openpsirt-demo openpsirt-demo-proxy >/dev/null 2>&1 || true
	@-$(DOCKER) network rm $(DEMO_NET) >/dev/null 2>&1 || true

# Declares somewhere to file scans against and sends the full-size fixture.
# Idempotent: declaring something that exists succeeds and changes nothing, so
# this can be run again without tearing anything down.
# The administrator grants themselves what they need on a product they have
# just declared.
#
# Declaring a product is administration; filing a build against it and reading
# what is open are not (ACC-64). So the bootstrap administrator grants
# themselves roles like anybody else, which is also the honest demonstration —
# the grant is visible in the same record everyone else's is, rather than
# implied by a flag. Idempotent, so re-seeding is not a special case.
demo-grant = curl -sS --noproxy '*' -o /dev/null -w "  grant dev on $(1) %{http_code}\n" \
	  -X POST -H "Origin: $(DEMO_URL)" -H 'Content-Type: application/json' \
	  -d "{\"identity\":\"proxy:$(DEMO_USER)\",\"display_name\":\"$(DEMO_USER)\",\"provider\":\"proxy\",\"username\":\"$(DEMO_USER)\",\"admin\":true,\"holds\":[{\"product\":\"$(1)\",\"role\":\"private-triage\"},{\"product\":\"$(1)\",\"role\":\"assigner\"},{\"product\":\"$(1)\",\"role\":\"approver\"}]}" \
	  "$(DEMO_URL)/v1/people"

demo-seed:
	@command -v xz >/dev/null || { echo "xz is needed to read the fixtures"; exit 1; }
	@for entry in $(DEMO_BUILDS); do \
	  IFS=',' read -r file product display stream variant <<< "$$entry"; \
	  xz -dc "$$file" > "$(DEMO_DIR)/$$product-$$stream-$$variant.cdx.json"; \
	  for spec in \
	    "/v1/products|{\"name\":\"$$product\",\"display_name\":\"$$display\"}" \
	    "/v1/products/$$product/streams|{\"name\":\"$$stream\",\"kind\":\"branch\"}" \
	    "/v1/products/$$product/variants|{\"name\":\"$$variant\",\"customer_facing\":true}"; do \
	    path=$${spec%%|*}; body=$${spec#*|}; \
	    curl -sS --noproxy '*' -o /dev/null -w "  $$path %{http_code}\n" \
	      -X POST -H "Origin: $(DEMO_URL)" \
	      -H 'Content-Type: application/json' -d "$$body" \
	      "$(DEMO_URL)$$path"; \
	  done; \
	  $(call demo-grant,$$product); \
	  curl -sS --noproxy '*' -o /dev/null -w "  upload $$product/$$stream/$$variant %{http_code}\n" \
	    -X POST -H "Origin: $(DEMO_URL)" \
	    -F "inventory=@$(DEMO_DIR)/$$product-$$stream-$$variant.cdx.json" \
	    "$(DEMO_URL)/v1/products/$$product/streams/$$stream/variants/$$variant/scans"; \
	done
	@# A second product: this deployment itself, from the two inventories the
	@# image carries. Two products is what makes the cross-product screens mean
	@# anything, and this one costs nobody a build pipeline.
	@#
	@# Two variants, and the difference between them is the point. "binary" is
	@# what the program was linked from — every Go module, and nothing else.
	@# "container" is what the image actually ships: musl, busybox, the
	@# certificate bundle, the scanner that rides along, and the modules of
	@# both binaries. A tool whose subject is knowing what is inside what you
	@# ship should be able to show somebody that those are not the same list,
	@# on itself, on the first screen they open.
	@$(DOCKER) cp openpsirt-demo:/usr/share/openpsirt/openpsirt.cdx.json $(DEMO_DIR)/openpsirt-binary.cdx.json
	@$(DOCKER) cp openpsirt-demo:/usr/share/openpsirt/image.cdx.json $(DEMO_DIR)/openpsirt-container.cdx.json
	@for spec in \
	  '/v1/products|{"name":"openpsirt","display_name":"OpenPSIRT"}' \
	  '/v1/products/openpsirt/streams|{"name":"main","kind":"branch"}' \
	  '/v1/products/openpsirt/streams|{"name":"v1.0","kind":"tag","parent":"main"}' \
	  '/v1/products/openpsirt/variants|{"name":"binary","customer_facing":true}' \
	  '/v1/products/openpsirt/variants|{"name":"container","customer_facing":true}'; do \
	  path=$${spec%%|*}; body=$${spec#*|}; \
	  curl -sS --noproxy '*' -o /dev/null -w "  $$path %{http_code}\n" \
	    -X POST -H "Origin: $(DEMO_URL)" \
	    -H 'Content-Type: application/json' -d "$$body" \
	    "$(DEMO_URL)$$path"; \
	done
	@$(call demo-grant,openpsirt)
	@for variant in binary container; do \
	  curl -sS --noproxy '*' -o /dev/null -w "  upload openpsirt/main/$$variant %{http_code}\n" \
	    -X POST -H "Origin: $(DEMO_URL)" \
	    -F "inventory=@$(DEMO_DIR)/openpsirt-$$variant.cdx.json" \
	    "$(DEMO_URL)/v1/products/openpsirt/streams/main/variants/$$variant/scans"; \
	done
	@# The tag as well, so there is something released to compare the branch
	@# against. Release readiness is a branch beside the last release cut from
	@# it, and a deployment with only branches cannot show it at all — which
	@# is also true of the alert about a critical on something shipped.
	@for variant in binary container; do \
	  curl -sS --noproxy '*' -o /dev/null -w "  upload openpsirt/v1.0/$$variant %{http_code}\n" \
	    -X POST -H "Origin: $(DEMO_URL)" \
	    -F "inventory=@$(DEMO_DIR)/openpsirt-$$variant.cdx.json" \
	    "$(DEMO_URL)/v1/products/openpsirt/streams/v1.0/variants/$$variant/scans"; \
	done
	@# The rest of the cast, with roles on every product just declared.
	@#
	@# Recorded rather than created on arrival: nobody appears here by having
	@# authenticated (ACC-21), so somebody who signs in through the proxy with
	@# no record is refused. The administrator records them, which is also the
	@# honest demonstration of how access works.
	@for entry in $(DEMO_CAST); do \
	  port=$${entry%%:*}; rest=$${entry#*:}; who=$${rest%%:*}; roles=$${rest#*:}; \
	  holds=""; \
	  products=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ p _ <<< "$$b"; echo "$$p"; done | sort -u); \
	  for product in $$products openpsirt; do \
	    IFS=',' read -ra each <<< "$$roles"; \
	    for role in "$${each[@]}"; do \
	      holds="$$holds{\"product\":\"$$product\",\"role\":\"$$role\"},"; \
	    done; \
	  done; \
	  curl -sS --noproxy '*' -o /dev/null -w "  person $$who %{http_code}\n" \
	    -X POST -H "Origin: $(DEMO_URL)" -H 'Content-Type: application/json' \
	    -d "{\"identity\":\"$$who\",\"display_name\":\"$$who\",\"provider\":\"proxy\",\"username\":\"$$who\",\"holds\":[$${holds%,}]}" \
	    "$(DEMO_URL)/v1/people"; \
	done
	@echo "  the scans run in the background; make demo-status shows when they land"
	@echo "  once they have, make demo-vex, make demo-triage and make demo-flaw"
	@echo "  fill in the rest"

# What a distribution has published, as a VEX document (REL-10, ING-42).
#
# Separate from the seed rather than part of it, because it is derived from
# what the scans found and the scans run in the background: a document written
# before them would name issues the demo does not have, and the layer would
# come up empty — which is the one thing this exists to stop somebody
# concluding about it.
#
# Written from the export rather than by hand for the same reason. Two
# statements per kind, because what the layer is worth showing is the pair: a
# distribution saying "affected, not fixing it here" is not a distribution
# saying "not affected", and only the second offers a dismissal (TRI-55).
demo-vex:
	@product=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ p _ <<< "$$b"; echo "$$p"; done | head -1); 	rows=$$(curl -sS --noproxy '*' 	    "$(DEMO_URL)/v1/products/$$product/findings.csv?fix_state=none&limit=6" 	  | awk -F',' 'NR>1 { gsub(/"/,""); if ($$1 ~ /^CVE-/ && $$5 != "") print $$1 "|" $$5 }'); 	if [ -z "$$rows" ]; then 	  echo "  no findings to speak about yet — run make demo-status and try again"; exit 0; 	fi; 	{ printf '{"@context":"https://openvex.dev/ns/v0.2.0",'; 	  printf '"@id":"https://demo.openpsirt.invalid/vex/debian-1",'; 	  printf '"author":"Debian Security Team","version":1,'; 	  printf '"timestamp":"%s","statements":[' "$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; 	  n=0; 	  while IFS='|' read -r cve name; do 	    [ -n "$$cve" ] || continue; 	    [ $$n -gt 0 ] && printf ','; 	    if [ $$((n % 2)) -eq 0 ]; then 	      printf '{"vulnerability":{"name":"%s"},"products":[{"@id":"pkg:generic/%s"}],' "$$cve" "$$name"; 	      printf '"status":"affected","action_statement":"Minor issue in %s; no update planned for this release. Will be fixed in a later point release."}' "$$name"; 	    else 	      printf '{"vulnerability":{"name":"%s"},"products":[{"@id":"pkg:generic/%s"}],' "$$cve" "$$name"; 	      printf '"status":"not_affected","justification":"vulnerable_code_not_in_execute_path",'; 	      printf '"impact_statement":"The affected code path is not built in the Debian package of %s."}' "$$name"; 	    fi; 	    n=$$((n + 1)); 	  done <<< "$$rows"; 	  printf ']}'; } > $(DEMO_DIR)/debian.vex.json; 	curl -sS --noproxy '*' -o /dev/null -w "  VEX from debian %{http_code}\n" 	  -X POST -H "Origin: $(DEMO_URL)" 	  -F "statements=@$(DEMO_DIR)/debian.vex.json" 	  "$(DEMO_URL)/v1/products/$$product/vex-statements?publisher=debian"

# A few judgments, so the screens that report on triage have something to
# report (RPT-26, TRI-63).
#
# **A demo where every figure reads zero demonstrates nothing.** The seed gives
# a deployment two products, six builds and a quarter of a million findings and
# nobody who has ever decided anything — so the review queue, the record of
# judgments, how long triage is taking, what is planned and what is being
# backported are all empty, and the screens that exist to answer those
# questions look broken rather than idle.
#
# **Recorded through the cast's own doors**, one port per person, because that
# is how this deployment authenticates: the identity is a header a proxy sets
# and the application trusts nothing else. It is also the control this tool
# rests on — one person proposes and a second agrees — and a demo where one
# identity did both would show the opposite of the rule.
#
# Separate from the seed for the same reason the VEX document is: it reads what
# the scans found, and the scans run in the background.
# A name a build ships at several versions cannot be decided about without
# saying which is meant, and this is a seed rather than a person making that
# choice — so those rows are left alone.
# The upgrade goes on a different package from the ones decided above, because
# it answers *everything* open on its component: planning one where a judgment
# already stands at some of those places is refused, and rightly — one act
# cannot answer what another has already answered.
demo-triage:
	@command -v curl >/dev/null || { echo "curl is needed"; exit 1; }
	@product=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ p _ <<< "$$b"; echo "$$p"; done | head -1); \
	stream=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ _ _ s _ <<< "$$b"; echo "$$s"; done | head -1); \
	variant=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ _ _ _ v <<< "$$b"; echo "$$v"; done | head -1); \
	proposer=$$(echo "$(word 1,$(DEMO_CAST))" | cut -d: -f1); \
	approver=$$(echo "$(word 2,$(DEMO_CAST))" | cut -d: -f1); \
	at="http://$(DEMO_HOST):$$proposer"; \
	agrees="http://$(DEMO_HOST):$$approver"; \
	rows=$$(curl -sS --noproxy '*' \
	    "$(DEMO_URL)/v1/products/$$product/findings.csv?fix_state=fixed&limit=60&stream=$$stream&variant=$$variant" \
	  | awk -F',' 'NR>1 { gsub(/"/,""); \
	      if ($$1 !~ /^CVE-/ || $$5 == "" || $$5 ~ /\//) next; \
	      keep[++k] = $$1 "|" $$5 "|" $$8; at[k] = $$5; \
	      if (!($$5 SUBSEP $$6 in seen)) { seen[$$5 SUBSEP $$6] = 1; versions[$$5]++ } } \
	    END { for (i = 1; i <= k; i++) if (versions[at[i]] == 1) print keep[i] }'); \
	if [ -z "$$rows" ]; then \
	  echo "  nothing to decide yet — run make demo-status and try again"; exit 0; \
	fi; \
	n=0; \
	while IFS='|' read -r cve component fixed; do \
	  [ -n "$$cve" ] || continue; \
	  n=$$((n + 1)); \
	  case $$n in \
	  1) body='{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path","reasoning":"The affected path is not compiled into this kernel: the driver is not built and nothing loads it."}';; \
	  2) body='{"outcome":"deferred","deferred_until":"'"$$(date -u -d '+21 days' +%Y-%m-%d)"'","reasoning":"Held until the next point release, which is already scheduled."}';; \
	  3) body='{"outcome":"patch-needed","committed_to":"'"$$(date -u -d '+10 days' +%Y-%m-%d)"'","reasoning":"Taking the upstream commit as a carried patch; the version does not move."}';; \
	  *) break;; \
	  esac; \
	  curl -sS --noproxy '*' -o /dev/null -w "  $$cve decided %{http_code}\n" \
	    -X POST -H "Origin: $$at" -H 'Content-Type: application/json' -d "$$body" \
	    "$$at/v1/products/$$product/streams/$$stream/variants/$$variant/findings/$$cve/components/$$component/decision"; \
	done <<< "$$rows"; \
	claim=$$(curl -sS --noproxy '*' "$$agrees/v1/review-queue?limit=1" \
	  | grep -o '"claim":{"id":[0-9]*' | head -1 | tr -dc '0-9' || true); \
	if [ -n "$$claim" ]; then \
	  curl -sS --noproxy '*' -o /dev/null -w "  claim $$claim agreed %{http_code}\n" \
	    -X POST -H "Origin: $$agrees" -H 'Content-Type: application/json' -d '{}' \
	    "$$agrees/v1/claims/$$claim/approval"; \
	else \
	  echo "  nothing was waiting for a second person"; \
	fi; \
	curl -sS --noproxy '*' -o /dev/null -w "  team platform %{http_code}\n" \
	  -X POST -H "Origin: $(DEMO_URL)" -H 'Content-Type: application/json' \
	  -d '{"name":"platform","display_name":"Platform","members":["'"$$(echo "$(word 1,$(DEMO_CAST))" | cut -d: -f2)"'"]}' \
	  "$(DEMO_URL)/v1/teams"; \
	decided=$$(echo "$$rows" | awk -F'|' 'NR == 1 { print $$2 }'); \
	one=$$(echo "$$rows" | awk -F'|' -v skip="$$decided" \
	  '$$2 != skip && !found { print; found = 1 }'); \
	component=$$(echo "$$one" | cut -d'|' -f2); to=$$(echo "$$one" | cut -d'|' -f3); \
	if [ -n "$$component" ] && [ -n "$$to" ]; then \
	  curl -sS --noproxy '*' -o /dev/null -w "  upgrade $$component to $$to %{http_code}\n" \
	    -X POST -H "Origin: $(DEMO_URL)" -H 'Content-Type: application/json' \
	    -d '{"to":"'"$$to"'","by":"'"$$(date -u -d '+3 days' +%Y-%m-%d)"'","team":"platform","reasoning":"Taking the kernel bump in the next build; the team is tracking it.","builds":[{"stream":"'"$$stream"'","variant":"'"$$variant"'"}]}' \
	    "$(DEMO_URL)/v1/products/$$product/components/$$component/upgrade"; \
	fi; \
	echo "  seeded. A 422 or 409 above is this having been run before: a"; \
	echo "  decision already stands there, which is the refusal working."
	@# Somebody who reads nothing and holds work, which is the one shape the
	@# cast had nobody for (ACC-75, ACC-77). An approver holds a capability
	@# and no read role, so what they can reach is exactly what has been
	@# assigned to them: their assignments, and the dependency paths their own
	@# findings sit on. Everything else in the product answers as a product
	@# that does not exist, which is the rule rather than a gap.
	@product=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ p _ <<< "$$b"; echo "$$p"; done | head -1); \
	stream=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ _ _ s _ <<< "$$b"; echo "$$s"; done | head -1); \
	variant=$$(for b in $(DEMO_BUILDS); do IFS=',' read -r _ _ _ _ v <<< "$$b"; echo "$$v"; done | head -1); \
	curl -sS --noproxy '*' -o /dev/null -w "  person holly %{http_code}\n" \
	  -X POST -H "Origin: $(DEMO_URL)" -H 'Content-Type: application/json' \
	  -d '{"identity":"holly","display_name":"Holly","provider":"proxy","username":"holly","holds":[{"product":"'"$$product"'","role":"approver"}]}' \
	  "$(DEMO_URL)/v1/people"; \
	rows=$$(curl -sS --noproxy '*' \
	    "$(DEMO_URL)/v1/products/$$product/findings.csv?limit=40&stream=$$stream&variant=$$variant" \
	  | awk -F',' 'NR>2 { gsub(/"/,""); if ($$1 ~ /^CVE-/ && $$5 != "" && $$5 !~ /\//) print $$1 "|" $$5 }'); \
	row=$$(echo "$$rows" | awk 'NR == 1'); \
	cve=$$(echo "$$row" | cut -d'|' -f1); component=$$(echo "$$row" | cut -d'|' -f2); \
	if [ -n "$$cve" ] && [ -n "$$component" ]; then \
	  curl -sS --noproxy '*' -o /dev/null -w "  $$cve handed to holly %{http_code}\n" \
	    -X PUT -H "Origin: $(DEMO_URL)" -H 'Content-Type: application/json' \
	    -d '{"person":"holly"}' \
	    "$(DEMO_URL)/v1/products/$$product/streams/$$stream/variants/$$variant/findings/$$cve/components/$$component/assignment"; \
	fi

# One flaw in what this deployment ships, recorded by hand (MDL-27 to MDL-31).
#
# **The demo had none, and a whole path was undemonstrable because of it.** A
# scanner's report about somebody else's component cannot be closed by a
# person, cannot carry a reporter, has no builds to correct and is refused an
# advisory — which is right, and it means the four screens built for a flaw we
# found ourselves had nothing to draw. An advisory in particular is the one
# output of this tool that leaves the company, and on the demo it answered 422
# for every issue there was.
#
# Undisclosed, which is what a flaw looks like before anybody announces it, and
# recorded against the container builds because that is what the image is.
demo-flaw:
	@command -v curl >/dev/null || { echo "curl is needed"; exit 1; }
	@# Nothing here refuses a second one: an identifier is minted per record,
	@# so recording the same flaw twice files two of them. Asked first rather
	@# than left to the reader to notice they have three.
	@held=$$(curl -sS --noproxy '*' \
	    "$(DEMO_URL)/v1/products/openpsirt/findings?recorded=true&limit=1" \
	  | sed -e 's/.*"total":\([0-9]*\).*/\1/' -e 's/^{.*/0/'); \
	if [ "$${held:-0}" != "0" ]; then \
	  echo "  a flaw is already recorded here — nothing to do"; exit 0; \
	fi; \
	filed=$$(curl -sS --noproxy '*' \
	  -X POST -H "Origin: $(DEMO_URL)" -H 'Content-Type: application/json' \
	  -d '{"builds":[{"stream":"main","variant":"container"},{"stream":"v1.0","variant":"container"}],"summary":"The inventory upload accepts a document nobody authenticated and files it against whichever build the document names.","severity":"high","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","weaknesses":["CWE-306"],"reported_by":"A. Researcher","contact":"researcher@example.invalid","credit":"anonymous"}' \
	  "$(DEMO_URL)/v1/products/openpsirt/findings"); \
	echo "$$filed" | sed -e 's/.*"identifier":"\([^"]*\)".*/  filed as \1, undisclosed/' \
	  -e 's/^{.*/  it was refused: '"$$filed"'/'

demo-status:
	@builds=""; for entry in $(DEMO_BUILDS); do \
	  IFS=',' read -r file product display stream variant <<< "$$entry"; \
	  builds="$$builds $$product:$$stream:$$variant"; \
	done; \
	for triple in $$builds openpsirt:main:binary openpsirt:main:container \
	    openpsirt:v1.0:binary openpsirt:v1.0:container; do \
	  IFS=':' read -r product stream variant <<< "$$triple"; \
	  build="$$product/streams/$$stream/variants/$$variant"; \
	  printf "  %-46s scan " "$$build"; curl -sS --noproxy '*' \
	    "$(DEMO_URL)/v1/products/$$build/scans" \
	    | sed -e 's/.*"state":"\([a-z]*\)".*/\1/' -e 's/^{.*/no scans yet/' | tr -d '\n'; \
	  printf " · open "; curl -sS --noproxy '*' \
	    "$(DEMO_URL)/v1/products/$$product/findings?stream=$$stream&variant=$$variant&limit=1" \
	    | sed -e 's/.*"total":\([0-9]*\).*/\1 findings/' -e 's/^{.*/unreadable/'; \
	done
	@echo "  open $(DEMO_URL) — you arrive as proxy:$(DEMO_USER), no sign-in"
	@# The rest of the cast, one door each. Two windows is two people, which is
	@# what it takes to show a claim being agreed to: approving your own is
	@# refused, so a single identity can propose a judgment and never finish
	@# one.
	@#
	@# Named without the provider, unlike the line above: the administrator is
	@# named in configuration, where an identity says which path it arrives by,
	@# and the cast is recorded through the API, where the identity is the bare
	@# name and the path is recorded beside it.
	@for entry in $(DEMO_CAST); do \
	  port=$${entry%%:*}; rest=$${entry#*:}; who=$${rest%%:*}; roles=$${rest#*:}; \
	  echo "       http://$(DEMO_HOST):$$port — as $$who ($$roles)"; \
	done


# Start over, keeping the vulnerability database: it is a gigabyte, it is not
# what anybody is resetting, and downloading it again is the slow part.
demo-reset: demo-down
	@rm -rf $(DEMO_DIR)/data $(DEMO_DIR)/image.cdx.json
	@echo "  removed the demo database. The scanner cache in $(DEMO_DIR)/grype was kept."

# The developer loop: this machine's binary and the interface's dev server, for
# editing the interface and seeing it reload. Needs Go, node and a scanner
# here. It does not exercise the embedded interface, so what it shows is not
# quite what ships — "make demo" is.
dev: build web dev-up dev-seed dev-status

dev-up: dev-down
	@mkdir -p $(DEV_DIR)
	@OPENPSIRT_DATABASE_URL="sqlite://$(DEV_DB)" \
	 OPENPSIRT_ADDR="$(DEV_API)" \
	 OPENPSIRT_PLAIN_HTTP=1 \
	 OPENPSIRT_BOOTSTRAP_ADMINS="proxy:$(DEMO_USER)" \
	 OPENPSIRT_TRUSTED_HEADER="X-User" \
	 OPENPSIRT_TRUSTED_SOURCES="127.0.0.0/8" \
	 OPENPSIRT_ATTACHMENT_DIR="$(DEV_DIR)/attachments" \
	 OPENPSIRT_BASE_URL="$(DEV_URL)" \
	 nohup ./$(BIN) > $(DEV_DIR)/api.log 2>&1 & echo $$! > $(DEV_DIR)/api.pid
	@OPENPSIRT_DEV_USER="$(DEMO_USER)" \
	 OPENPSIRT_DEV_HOSTS="$(DEV_HOST)" \
	 OPENPSIRT_DEV_API="http://$(DEV_API)" \
	 nohup $(NPM) --prefix web run dev -- --host --port $(DEV_PORT) \
	   > $(DEV_DIR)/web.log 2>&1 & echo $$! > $(DEV_DIR)/web.pid
	@sleep 6
	@echo "api  $(DEV_API)   log $(DEV_DIR)/api.log"
	@echo "web  $(DEV_URL)   log $(DEV_DIR)/web.log"

dev-down:
	@-pkill -f "$(BIN)" 2>/dev/null || true
	@-pkill -f "vite.*--port $(DEV_PORT)" 2>/dev/null || true
	@rm -f $(DEV_DIR)/api.pid $(DEV_DIR)/web.pid
	@sleep 1

dev-seed:
	@command -v xz >/dev/null || { echo "xz is needed to read the fixtures"; exit 1; }
	@for entry in $(DEMO_BUILDS); do \
	  IFS=',' read -r file product display stream variant <<< "$$entry"; \
	  xz -dc "$$file" > "$(DEV_DIR)/$$product-$$stream-$$variant.cdx.json"; \
	  for spec in \
	    "/v1/products|{\"name\":\"$$product\",\"display_name\":\"$$display\"}" \
	    "/v1/products/$$product/streams|{\"name\":\"$$stream\",\"kind\":\"branch\"}" \
	    "/v1/products/$$product/variants|{\"name\":\"$$variant\",\"customer_facing\":true}"; do \
	    path=$${spec%%|*}; body=$${spec#*|}; \
	    curl -sS --noproxy '*' -o /dev/null -w "  $$path %{http_code}\n" \
	      -X POST -H "X-User: $(DEMO_USER)" -H "Origin: $(DEV_URL)" \
	      -H 'Content-Type: application/json' -d "$$body" \
	      "http://$(DEV_API)$$path"; \
	  done; \
	  curl -sS --noproxy '*' -o /dev/null -w "  upload $$product/$$stream/$$variant %{http_code}\n" \
	    -X POST -H "X-User: $(DEMO_USER)" -H "Origin: $(DEV_URL)" \
	    -F "inventory=@$(DEV_DIR)/$$product-$$stream-$$variant.cdx.json" \
	    "http://$(DEV_API)/v1/products/$$product/streams/$$stream/variants/$$variant/scans"; \
	done
	@# A second product: this deployment itself, from its own inventory.
	@#
	@# One variant here, not the two the container demo seeds. There is no
	@# container in this loop — it runs the binary on this machine — so the
	@# inventory of what an image ships does not exist to upload. Naming the
	@# one that does exist the same thing it is called there keeps the two
	@# loops describing one product rather than two that look alike.
	@$(MAKE) --no-print-directory sbom >/dev/null
	@for spec in \
	  '/v1/products|{"name":"openpsirt","display_name":"OpenPSIRT"}' \
	  '/v1/products/openpsirt/streams|{"name":"main","kind":"branch"}' \
	  '/v1/products/openpsirt/variants|{"name":"binary","customer_facing":true}'; do \
	  path=$${spec%%|*}; body=$${spec#*|}; \
	  curl -sS --noproxy '*' -o /dev/null -w "  $$path %{http_code}\n" \
	    -X POST -H "X-User: $(DEMO_USER)" -H "Origin: $(DEV_URL)" \
	    -H 'Content-Type: application/json' -d "$$body" \
	    "http://$(DEV_API)$$path"; \
	done
	@curl -sS --noproxy '*' -o /dev/null -w "  upload %{http_code}\n" \
	  -X POST -H "X-User: $(DEMO_USER)" -H "Origin: $(DEV_URL)" \
	  -F "inventory=@bin/openpsirt.cdx.json" \
	  "http://$(DEV_API)/v1/products/openpsirt/streams/main/variants/binary/scans"
	@echo "  the scans run in the background; make dev-status shows when they land"

dev-status:
	@builds=""; for entry in $(DEMO_BUILDS); do \
	  IFS=',' read -r file product display stream variant <<< "$$entry"; \
	  builds="$$builds $$product/streams/$$stream/variants/$$variant"; \
	done; \
	for build in $$builds openpsirt/streams/main/variants/binary; do \
	  printf "  %-46s scan " "$$build"; curl -sS --noproxy '*' -H "X-User: $(DEMO_USER)" \
	    "http://$(DEV_API)/v1/products/$$build/scans" \
	    | sed -e 's/.*"state":"\([a-z]*\)".*/\1/' -e 's/^{.*/no scans yet/' | tr -d '\n'; \
	  printf " · open "; curl -sS --noproxy '*' -H "X-User: $(DEMO_USER)" \
	    "http://$(DEV_API)/v1/products/$$build/findings?limit=1" \
	    | sed -e 's/.*"total":\([0-9]*\).*/\1 findings/' -e 's/^{.*/unreadable/'; \
	done
	@echo "  open $(DEV_URL) — you arrive as proxy:$(DEMO_USER), no sign-in"


dev-reset: dev-down
	@rm -f $(DEV_DB)
	@echo "  removed $(DEV_DB)"

clean-web:
	rm -rf web/node_modules web/dist internal/webui/dist/assets internal/webui/dist/index.html

clean:
	rm -rf bin
