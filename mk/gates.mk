# Copyright Nexthop Systems Inc.
# SPDX-License-Identifier: Apache-2.0

# The checks beside the linter and the suite: vulnerable and unlicensed
# dependencies, the inventory, credentials in the tree, the gate programs under
# internal/tools, the generated files that must match what generates them, and
# the pinned versions that must agree with each other.

.PHONY: govulncheck licenses sbom secrets web-audit unreachable readable negatives reserved confined granted narrowed subjected attached reserved-words weakness-names reserved-current unclaimed vendored spdx spdx-fix openapi-current

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

# Known vulnerabilities in Go modules and the toolchain. A change fails for one
# the branch it targets was not already affected by; one it was is reported and
# does not fail it (REQ-75). AUDIT_BASE names that branch, origin/main unless
# set. DESIGN-build.md § Known vulnerabilities has the rules.
govulncheck:
	$(GO) run ./internal/tools/advisories go -- \
	  $(call tool,govulncheck) -format json $(PACKAGES)

# Both halves of what ships, against one allowlist.
#
# The interface is built into the binary, so its dependencies are shipped
# exactly as the Go ones are — and they went unchecked until the platform
# product that would have caught them turned out to be a paid add-on on a
# private repository. The allowlist is this variable, passed to both, because
# a policy written in two files is a policy that differs in one of them.
licenses:
	$(call tool,go-licenses) check $(PACKAGES) \
		--allowed_licenses=$(ALLOWED_LICENSES) \
		$(foreach m,$(LICENSE_EXCEPTIONS),--ignore=$(m))
	@command -v $(NPM) >/dev/null 2>&1 \
	  || { echo "npm not found, so the interface's licenses are unchecked here"; exit 1; }
	@# The npm half parses the interface's source with the TypeScript compiler
	@# to find what it imports, so it needs an install. One already there is
	@# used: the licenses are read from the lockfile, and the compiler only reads.
	@[ -d web/node_modules/typescript ] || $(MAKE) --no-print-directory web-deps
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
	$(call tool,cyclonedx-gomod) \
		app -main cmd/openpsirt -json -packages -output bin/openpsirt.cdx.json .
	@echo "wrote bin/openpsirt.cdx.json"

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
#
# What is scanned is what a commit could carry: every tracked file as it stands
# in the working tree, and every untracked file git does not ignore, copied
# aside. The scanner reads no ignore file, so pointed at the checkout it walks
# the demo's data and the build output as well: 14.6 MB that a commit carries
# scans in a second, and beside the demo's 7.7 GB the scan runs past twenty
# minutes.
secrets:
	@into=$$(mktemp -d) && trap 'rm -rf "$$into"' EXIT && \
	git ls-files -z --cached --others --exclude-standard \
	  | while IFS= read -r -d '' file; do if [ -f "$$file" ]; then printf '%s\0' "$$file"; fi; done \
	  | tar --null -T - -cf - | tar -C "$$into" -xf - && \
	cd "$$into" && $(call tool,gitleaks) dir . \
		--no-banner --redact --config .gitleaks.toml

# Known vulnerabilities in what the interface installs.
#
# The counterpart to govulncheck, and the other half of REQ-75's vulnerability
# scanning: govulncheck reads Go modules and says nothing at all about npm.
# The advisory data is the registry's, so this needs a network and says so
# rather than passing when it cannot reach one.
#
# High and above fails, where the change introduced it: the branch it targets
# was not already affected, which is asked by auditing that branch's lockfile
# as well. One it was is reported and does not fail it (REQ-75). Everything is
# reported, because "one moderate" and "forty moderates" are different facts
# and only one of them is worth a look.
web-audit:
	@command -v $(NPM) >/dev/null 2>&1 \
	  || { echo "npm not found, so the interface's dependencies are unscanned here"; exit 1; }
	$(GO) run ./internal/tools/advisories npm -- $(NPM) audit --json

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

# A store method that queries with no subject. Visibility is enforced in the
# data layer and every query carries one; a method taking none reads whatever a
# caller's identifier names, whoever asked. The ones that rightly take none are
# named in the tool's exempt list, each with its reason.
subjected:
	$(GO) run ./internal/tools/subjected

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
# code to design document to decision, and this is what holds it whole. A
# decision not built yet is not exempt — its design document says so.
unclaimed:
	$(GO) run ./internal/tools/unclaimed

# Files copied into the tree rather than imported: each accounted for, under a
# license this tree may carry, and named in NOTICE where the license asks.
vendored:
	@ALLOWED_LICENSES=$(ALLOWED_LICENSES) $(GO) run ./internal/tools/vendored

# Every source file opens with its copyright and its license identifier, so a
# scanner reads the license file by file. spdx-fix writes the header into every
# file missing one.
spdx:
	$(GO) run ./internal/tools/spdx

spdx-fix:
	$(GO) run ./internal/tools/spdx -fix

# CI fails when the committed document has drifted, so check the same thing.
openapi-current: openapi
	@git diff --exit-code -- docs/reference/openapi.yaml \
	  || { echo "docs/reference/openapi.yaml is stale: commit the regenerated file"; exit 1; }

# The documentation site, built the way CI builds it.
#
# A target because everything CI runs is one: this was the last check that
# existed only in the workflow, so a broken link or a page missing from the
# navigation failed there and nowhere a developer could reproduce it.
.PHONY: docs-site
docs-site:
	$(PYTHON) -m mkdocs build --strict

# The Go release the image builds with. It is written once, in the image's
# build stage, and every workflow installs the release this prints, so the
# tarball and the image are built by one toolchain.
.PHONY: go-version
go-version:
	@sed -n 's/^FROM golang:\([0-9.]*\)-.*/\1/p' Dockerfile

# The Node release the image builds the interface with, read the same way and
# for the same reason: the workflows install what this prints, so the image's
# node tag is the one pin of it, and the pull request moving the tag moves the
# interface's toolchain everywhere.
.PHONY: node-version
node-version:
	@sed -n 's/^FROM node:\([0-9.]*\)-.*/\1/p' Dockerfile

# The other pinned pairs, checked the same way and for the same reason.
#
# A version written in two files is one somebody moves in one of them, so the
# toolchain the container builds with could drift from the one a module
# declares, or a workflow could install a Node of its own — each silently, and
# each producing an artifact built with something other than what was tested.
#
# Named rather than folded into engines-check, because that one is about what
# the tests run against and this is about what the release is built from.
#
# A base image is the first word after FROM that is not a flag, unless it names
# an earlier stage, scratch, or a build argument, whose default is read from its
# ARG line instead. A name with no tag is still a base, since alpine is
# alpine:latest, and every base is named by digest.
#
# go.mod's go line is the oldest Go release the module accepts, and is held at
# or below the image's: the image moves first, through its own pull request,
# and a dependency raising the go line past it fails here until it has. Each
# tool's module under tools/ is held to the same line, because the image and
# the workflows build the tools with that toolchain too. A tool's directory is
# named for the command its module declares, because that name is what the
# targets call it by.
#
# A workflow reads Node from the image, as it reads Go, and never names a
# release itself.
#
# The tidy run rewrites the tree, so what it found there is put back on every
# exit path — including an interrupt, which used to leave the tree as tidy had
# made it and the copies behind under a name every checkout on the machine
# shared.
.PHONY: pins-check
pins-check:
	@fail=0; \
	block() { awk '/^## Product security in one place$$/ { p = 1 } /^## (Evaluation|Next steps)$$/ { p = 0 } p' "$$1" \
	  | sed -E 's/\]\([^)]*\)/]()/g'; }; \
	[ -n "$$(block README.md)" ] || { \
	  echo "the shared block is empty in README.md, so this compared nothing."; fail=1; }; \
	[ -n "$$(block docs/index.md)" ] || { \
	  echo "the shared block is empty in docs/index.md, so this compared nothing."; fail=1; }; \
	[ "$$(block README.md)" = "$$(block docs/index.md)" ] || { \
	  echo "README.md and docs/index.md describe what this does in different words."; \
	  echo "They are the same list maintained twice; make them the same words."; fail=1; }; \
	declared=$$(awk '/^go /{print $$2}' go.mod); \
	image=$$($(MAKE) -s --no-print-directory go-version); \
	[ -n "$$declared" ] && [ -n "$$image" ] || { \
	  echo "go.mod's go line or the image's Go release was not found, so they were not compared."; fail=1; }; \
	[ -z "$$declared" ] || [ -z "$$image" ] || \
	  [ "$$(printf '%s\n%s\n' "$$declared" "$$image" | sort -V | head -n 1)" = "$$declared" ] || { \
	  echo "go.mod declares Go $$declared and the image builds with $$image, which is older."; \
	  echo "Move the image's golang tag first: it is the one pin of the toolchain."; fail=1; }; \
	tools=0; \
	for mod in tools/*/go.mod; do \
	  [ -f "$$mod" ] || continue; \
	  tools=$$((tools + 1)); \
	  dir=$$(basename "$$(dirname "$$mod")"); \
	  wants=$$(awk '/^go /{print $$2}' "$$mod"); \
	  [ -z "$$wants" ] || [ -z "$$image" ] || \
	    [ "$$(printf '%s\n%s\n' "$$wants" "$$image" | sort -V | head -n 1)" = "$$wants" ] || { \
	    echo "$$mod declares Go $$wants and the image builds with $$image, which is older."; \
	    echo "Move the image's golang tag first: it is the one pin of the toolchain."; fail=1; }; \
	  named=$$(awk '/^tool /{print $$2}' "$$mod" | sed -E 's#/v[0-9]+$$##; s#.*/##'); \
	  [ "$$named" = "$$dir" ] || { \
	    echo "$$mod declares the tool \"$$named\" and sits in tools/$$dir, so the targets"; \
	    echo "calling it by its directory reach nothing. One tool per module, named for it."; \
	    fail=1; }; \
	done; \
	[ "$$tools" -gt 0 ] || { echo "tools/ holds no module, so no tool's pin was compared."; fail=1; }; \
	[ -n "$$($(MAKE) -s --no-print-directory node-version)" ] || { \
	  echo "the Dockerfile names no node release, so the workflows have nothing to read."; fail=1; }; \
	for flow in .github/workflows/*.yml; do \
	  for said in $$(awk -F': ' '/node-version:/{print $$2}' "$$flow" | tr -d ' '); do \
	    [ "$$said" = '$${{steps.node.outputs.version}}' ] || { \
	      echo "$$flow names Node $$said itself. Read it from the image with"; \
	      echo "make node-version, as the Go release is read, so the image's tag is the one pin."; \
	      fail=1; }; \
	  done; \
	done; \
	defaults=$$(grep -c '^ARG VERSION=' Dockerfile); \
	distinct=$$(grep '^ARG VERSION=' Dockerfile | sort -u | wc -l); \
	[ "$$distinct" -le 1 ] || { \
	  echo "the image has $$defaults version defaults and they differ, so an"; \
	  echo "unpassed build says one thing in the binary and another in its SBOM."; \
	  fail=1; }; \
	bases=$$(awk '/^ARG [A-Z_]*IMAGE=/ { sub(/^ARG [A-Z_]*IMAGE=/, ""); print; next } \
	  /^FROM / { i = 2; while ($$i ~ /^--/) i++; base = $$i; known = (base in stage); \
	    if (tolower($$(i + 1)) == "as") stage[$$(i + 2)] = 1; \
	    if (known || base == "scratch" || base ~ /^\$$/) next; print base }' Dockerfile); \
	[ -n "$$bases" ] || { echo "the image names no base, so no pin was compared."; fail=1; }; \
	for base in $$bases; do \
	  case "$$base" in \
	    *@sha256:*) ;; \
	    *) echo "the base $$base is named by a tag alone, which its owner can move under a rebuild."; \
	       echo "Name it by digest as well: $$base@sha256:..."; fail=1 ;; \
	  esac; \
	done; \
	services=$$(awk '/^[[:space:]]+image:/ { print $$2 }' .github/workflows/*.yml); \
	[ -n "$$services" ] || { echo "no workflow names a service image, so no pin was compared."; fail=1; }; \
	for service in $$services; do \
	  case "$$service" in \
	    *@sha256:*) ;; \
	    *) echo "the service image $$service is named by a tag alone, which its owner can move under a rebuild."; \
	       echo "Name it by digest as well: $$service@sha256:..."; fail=1 ;; \
	  esac; \
	done; \
	quota=$$(sed -n 's/^const DefaultQuota = \([0-9]*\) << \([0-9]*\)$$/\1 \2/p' internal/patchbranch/copies.go); \
	chart=$$(sed -n 's/.*patchBranches\.quota | default \([0-9]*\).*/\1/p' $(CHART_DIR)/templates/deployment.yaml); \
	[ -n "$$quota" ] && [ -n "$$chart" ] || { \
	  echo "the patch branch quota was not found in copies.go or the chart, so it was not compared."; fail=1; }; \
	[ -z "$$quota" ] || [ "$$(( $${quota% *} << $${quota#* } ))" = "$$chart" ] || { \
	  echo "the chart sizes the patch branch volume for a quota of $$chart and the binary's is $$(( $${quota% *} << $${quota#* } ))."; \
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
