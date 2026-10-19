# Copyright Nexthop Systems Inc.
# SPDX-License-Identifier: Apache-2.0

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
# 1 where the MySQL and MariaDB servers above are throwaways, so the harness
# may turn off their commit durability, which is global on those two and
# outlives the run. "engines-up" writes it beside the URLs of the containers it
# starts; a server of somebody's own is left as it is.
export OPENPSIRT_TEST_RELAX_DURABILITY
ENGINES_SET := $(strip $(OPENPSIRT_TEST_POSTGRES_URL)$(OPENPSIRT_TEST_MYSQL_URL)$(OPENPSIRT_TEST_MARIADB_URL))
# Named one at a time, because "all three are missing" and "one is missing" are
# different states and only the first used to be reported. With postgres alone
# configured the warning stayed silent and the run tested two engines of four.
ENGINES_MISSING := $(strip \
  $(if $(OPENPSIRT_TEST_POSTGRES_URL),,postgres) \
  $(if $(OPENPSIRT_TEST_MYSQL_URL),,mysql) \
  $(if $(OPENPSIRT_TEST_MARIADB_URL),,mariadb))

# The container and Python commands, for every recipe that runs one.
DOCKER ?= docker
PYTHON ?= python3


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
# release targets in mk/dist.mk override it per target — a tag is "v0.2.0" and
# a chart version is "0.2.0", and the assets a release publishes have to agree
# with each other rather than differing by one character. Recursive rather
# than immediate for exactly that: an immediate assignment would bake the
# default in before a target-specific value could reach it.
STAMP_VERSION ?= $(VERSION)
# The version reaches the linker through the environment rather than the
# recipe's text. It comes from git describe, so it is a tag name, and a tag
# name may carry shell syntax; substituted into a recipe it would be script.
# The shell expands $STAMPED inside the double quotes the recipes put around
# LDFLAGS, and treats what it expands to as data. Exported by the two targets
# that link, so nothing else pays for asking git.
build dist-binaries: export STAMPED = $(STAMP_VERSION)
LDFLAGS       = -s -w \
	-X '$(PKG).version=$$STAMPED' \
	-X '$(PKG).commit=$(COMMIT)' \
	-X '$(PKG).date=$(DATE)'


# Every Go tool is pinned, each by a module of its own under tools/: the
# directory is named for the command, its go.mod requires the tool at one
# version, and its go.sum holds the checksum of everything the tool is built
# from. "latest" resolves at run time, so CI would not be reproducible against
# last week's run and a compromised upstream release would execute here on the
# day it shipped. A module rather than a version in this file, because a
# requirement in a go.mod is what the dependency updates read, and a version
# here is one nothing moves. One module per tool, so that moving one tool never
# moves a library another is built against.
#
# The gitleaks module path is not its repository path: the project moved to the
# gitleaks organization and the module still declares zricethezav.
tool = $(GO) tool -modfile=$(CURDIR)/tools/$(1)/go.mod $(1)

NPM ?= npm

.PHONY: gate full docs-check all build test test-all test-race test-engines lint fmt openapi run clean check measure web web-deps web-api web-check clean-web

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
# Two ways of asking, because a machine with neither would assert two cores and
# give each pass one package at a time — fewer than either pass had alone, and
# nothing printed to say why.
TEST_HALF := $(shell n=$$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2); h=$$((n / 2)); if [ $$h -lt 1 ]; then h=1; fi; echo $$h)

# One spelling of each pass. test-all adds a package count and a label; the
# standalone targets run the same command with the whole machine. Written twice,
# a flag added to the target somebody runs by hand never reaches the gate, which
# runs only test-all.
#
# A race-instrumented binary sleeps before it exits, so that a goroutine still
# running can report a race first. The default is a second, and every test
# binary pays it: 1.02 s against 0.015 s for a package whose tests take
# milliseconds, and the better part of a minute across the tree on a runner
# that runs the pass one package at a time. 100 ms keeps a window for a
# goroutine mid-operation; nothing in the tests leaves one running on purpose.
#
# The SQLite engine is C translated to Go, and instrumenting it is most of what
# the detector costs: an empty test under the detector spends 48% of its time in
# the engine parsing the schema, and the pointer checks the detector turns on
# another 16 to 22%. The translated engine and the C library it runs on are
# compiled without either. The engine's Go driver stays instrumented: an error
# it fills in uninstrumented leaves no record of that write, so our code reading
# it is checked against whatever last used the memory and reported as a race.
# Our code, the query builder and the standard library stay instrumented and
# checked, and a race inside the translated C is the one thing no longer seen.
# The compiler flags are not documented for this use; a Go release that
# rejects one fails the build.
RACE_UNWATCHED = -gcflags='modernc.org/sqlite/lib=-race=false -d=checkptr=0' \
	-gcflags='modernc.org/libc/...=-race=false -d=checkptr=0'
RACE_PASS    = GORACE=atexit_sleep_ms=100 OPENPSIRT_TEST_ENGINES=sqlite $(GO) test -race $(RACE_UNWATCHED) -count=1
SERVERS_PASS = OPENPSIRT_TEST_ENGINES=postgres,mysql,mariadb $(GO) test -count=1

# Both passes at once. They share no engine — the detector runs on SQLite and
# the portability pass on the three servers — so neither can see the other's
# rows, and the guard against two binaries meeting in one database on a server
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
	@( $(RACE_PASS) -p $(TEST_HALF) \
	    $(PACKAGES) 2>&1 | awk '{ print "[sqlite -race] " $$0; fflush() }' ) & detector=$$!; \
	( $(SERVERS_PASS) -p $(TEST_HALF) \
	    $(PACKAGES) 2>&1 | awk '{ print "[servers]      " $$0; fflush() }' ) & portability=$$!; \
	failed=0; \
	wait $$detector || failed=1; \
	wait $$portability || failed=1; \
	exit $$failed

# The detector, on the engine every checkout has. Its own target, for running
# one pass by hand; the gate runs both at once through test-all.
test-race:
	$(RACE_PASS) $(PACKAGES)

# The three server engines, without it. Their time is spent waiting on a
# socket, which is not where a race is found: 16.9 s against 12.0 s for the API
# package on MariaDB, where the same package on SQLite is 73.6 s against 10.1 s.
test-engines:
	$(SERVERS_PASS) $(PACKAGES)

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
# has been renamed, the style the design documents are written in, and every
# Go test that reads a document — the build document's tables and the
# configuration reference are held to the code by tests in those packages, and
# a test in internal/build holds this list to them. Seconds. The other half of
# that tier is "unclaimed", which is a check of its own.
DOCS_PACKAGES := ./internal/docs/ ./internal/build/ ./internal/config/
docs-check:
	$(GO) test $(DOCS_PACKAGES)

# The linter is also the vet. Its govet runs every analyzer go vet does, over
# test files and over the file behind the "measure" tag, so a separate go vet
# ran the same analysis twice: 50 s of a two-core runner. A test in
# internal/build holds the linter's configuration to that.
#
# The tag matters because "make measure" is the only other thing that passes
# it — a target which refuses outright unless three server engines are
# configured, so nothing else would notice the file had stopped compiling.
lint:
# Verified before it is run. The loader drops a key it does not recognize
# without a word, so a setting spelled at the wrong level reads as configured
# and does nothing — which is how the "measure"-tagged file went on being
# unlinted under a comment saying it was not.
	$(call tool,golangci-lint) config verify
	$(call tool,golangci-lint) run

# The files a build constraint keeps off Linux, type-checked. Every runner and
# every other target builds for Linux, so a file marked !linux is compiled by
# nothing else here, and a signature it shares with its Linux twin can change
# under it with every check green. Vet type-checks without linking.
.PHONY: vet-other-os
vet-other-os:
	GOOS=darwin $(GO) vet $(PACKAGES)

fmt:
	$(call tool,golangci-lint) fmt

# The document is generated from the running registrations, never hand-written.
openapi:
	@mkdir -p docs/reference
	$(GO) run ./cmd/openpsirt -openapi > docs/reference/openapi.yaml
	@echo "wrote docs/reference/openapi.yaml"

# Everything CI runs, reachable from one command, except the container and the
# chart: those need docker and helm, and check-packaging holds them.
check: build lint vet-other-os unreachable unclaimed vendored spdx reserved confined granted narrowed subjected attached readable negatives pins-check test-all sbom-shape govulncheck licenses secrets openapi-current sbom web-check
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
	$(NPM) --prefix web run copy
	$(MAKE) web-audit
	$(MAKE) web-api

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
MEASURED := ./internal/finding/ ./internal/notify/ ./internal/triage/ ./internal/database/migrate/migrations/ ./internal/publish/ ./internal/upstream/

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

run:
	$(GO) run ./cmd/openpsirt

clean-web:
	rm -rf web/node_modules web/dist internal/webui/dist/assets internal/webui/dist/index.html

clean:
	rm -rf bin

# The rest of the build, one file per responsibility. Included last, so the
# first target above stays the default goal.
include mk/engines.mk
include mk/gates.mk
include mk/dist.mk
include mk/packaging.mk
include Makefile.demo
