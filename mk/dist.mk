# Copyright Nexthop Systems Inc.
# SPDX-License-Identifier: Apache-2.0

# The release: every asset it carries, built into one directory and checked
# there, and the record of a release's migrations that a tag is checked against.

.PHONY: dist dist-version dist-clean dist-binaries dist-chart dist-inventories dist-sums dist-verify dist-serves release-freeze release-check

# What a release is made of, and where it is built.
#
# The tag is the only place a version is typed. VERSION, in the makefile, is
# derived from it, DIST_VERSION is that tag with the leading v removed, and
# every asset takes its version from there — nothing is read from a file somebody has to
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
	@# The image is gated here, so a machine that cannot run the gate cannot
	@# make a release: the skip check-packaging answers elsewhere is refused.
	@test -n "$(PACKAGING_TOOLS)" \
	  || { echo "dist needs $(DOCKER) and helm, to gate the image and the chart it builds"; exit 1; }
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
	  --build-arg DATE=$(DATE) .
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
# Every architecture's binary is asked its version. One built for another
# architecture runs only where an emulator is registered, and is named as not
# checked where none is: a stripped binary built with -trimpath records no
# linker flags to read the stamp from without running it.
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
	  work=$$(mktemp -d); trap 'rm -rf "$$work"' EXIT; \
	  for arch in $(DIST_ARCHES); do \
	    archive=$(DIST_DIR)/openpsirt_$(DIST_VERSION)_linux_$$arch.tar.gz; \
	    if [ ! -f "$$archive" ]; then \
	      skipped="$$skipped the $$arch binary (no archive)"; continue; \
	    fi; \
	    tar -C "$$work" -xzf "$$archive"; \
	    binary="$$work"/openpsirt_$(DIST_VERSION)_linux_$$arch/openpsirt; \
	    if ! said=$$("$$binary" -version 2>/dev/null | awk '{print $$2}') || [ -z "$$said" ]; then \
	      [ "$$arch" != "$(DIST_IMAGE_ARCH)" ] \
	        || { echo "the $$arch binary does not run on the machine it was built for"; fail=1; continue; }; \
	      skipped="$$skipped the $$arch binary (cannot run here)"; continue; \
	    fi; \
	    [ "$$said" = "$(DIST_VERSION)" ] \
	      || { echo "the $$arch binary reports $$said and its archive says $(DIST_VERSION)"; fail=1; }; \
	    [ "$$arch" != "$(DIST_IMAGE_ARCH)" ] \
	      || $(MAKE) --no-print-directory dist-serves BINARY="$$binary" \
	      || fail=1; \
	  done; \
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

# The tag a release target is handed, as text. A value given on the command
# line is a make variable, and expanding it expands whatever "$(...)" a tag
# name carries — every character of that is legal in a ref — so the text is
# taken unexpanded. The default from git describe is expanded as usual.
tag-as-given = $(if $(filter command line,$(origin VERSION)),$(value VERSION),$(VERSION))

# A release's record of its migrations: the schema they build on every engine,
# and each file with its digest. Run on a branch from the head of main, with
# the four engines up (make engines-up), and land what it writes before the tag.
# A release a database may be built from is one nothing may edit afterwards, and
# the record is what holds it there.
#
# The version reaches the recipe through the environment and is quoted there.
# In a tag push it is a name somebody chose, and pasted into the recipe it would
# be shell text.
release-freeze: export RELEASE_TAG = $(tag-as-given)
release-freeze:
	$(GO) run ./internal/tools/release guard "$$RELEASE_TAG"
	OPENPSIRT_TEST_ENGINES=sqlite,postgres,mysql,mariadb OPENPSIRT_RELEASE_FREEZE="$$RELEASE_TAG" \
	  $(GO) test -count=1 -run '^TestWriteTheSchemaAReleaseTags$$' ./internal/database/migrate/migrations/
	$(GO) run ./internal/tools/release freeze "$$RELEASE_TAG"
	$(GO) run ./internal/tools/release check "$$RELEASE_TAG"

# That the release a tag names was frozen, and that the tree still ships what
# it froze. The release workflow runs it before anything is built, so a tag
# nobody froze publishes nothing.
release-check: export RELEASE_TAG = $(tag-as-given)
release-check:
	$(GO) run ./internal/tools/release check "$$RELEASE_TAG"
