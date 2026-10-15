# Copyright Nexthop Systems Inc.
# SPDX-License-Identifier: Apache-2.0

# The database servers the suite runs against, as containers: starting, stopping
# and emptying them, and the check that all four engines ran and were the
# engines they claimed to be.

.PHONY: check-engines engines-up engines-down engines-clean engines-status engines-check

# The servers the test URLs point at, as containers. Pinned for the same reason
# every Go tool is, and to the versions CI runs: an engine that has drifted
# from CI's turns "it passed locally" into a different claim from "it passes".
# Two pinned lists in two files drift silently, so "engines-check" asserts they
# still agree rather than trusting that whoever moved one moved the other. Each
# is named by digest as well as tag, because a tag is moved by a rebuild
# upstream, and "pins-check" refuses one named by tag alone. Dependabot reads
# no workflow service, so these move by hand, the two lists together.
ENGINE_PG_IMAGE      ?= postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
ENGINE_MYSQL_IMAGE   ?= mysql:8.4@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70
ENGINE_MARIADB_IMAGE ?= mariadb:11.4@sha256:1292844148b311e4ed4300022a996d39083f415a963e970cf47cad1b3b18e3a6
# Deliberately below the supported floor, so the refusal to run against an old
# server is exercised rather than skipped.
ENGINE_FLOOR_IMAGE   ?= postgres:13-alpine@sha256:fb9065b6e3e213bdc07edd372a5b2a26245840b7fb65d1fd8b6700106d51805c
ENGINE_PG_PORT       ?= 5432
ENGINE_MYSQL_PORT    ?= 3306
ENGINE_MARIADB_PORT  ?= 3307
ENGINE_FLOOR_PORT    ?= 5433
ENGINE_PREFIX        ?= openpsirt
# Seconds to wait for a server to start accepting connections. A container
# reported "Up" is not one that answers yet, and MySQL takes the longest.
ENGINE_WAIT          ?= 120

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
	  done; \
	  $(GO) test ./internal/database/migrate/migrations/ -count=1 -v \
	    -run TestAMigrationThatFailedPartWayThroughCanBeRunAgain \
	    > "$$out" 2>&1 || { cat "$$out"; exit 1; }; \
	  for engine in mysql mariadb; do \
	    grep -q "PASS: TestAMigrationThatFailedPartWayThroughCanBeRunAgain/$$engine" "$$out" \
	      || { echo "a half-applied migration was not run again on $$engine"; exit 1; }; \
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

# The four servers the test URLs point at, started, waited for, and written
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

# The data directories are in memory. The settings above govern commits, and a
# schema change syncs the files it creates whatever they say: building the
# schema took MySQL 9.8 s and MariaDB 7.2 s on a workstation's disk and
# 0.83 s and 0.18 s in memory. A stopped container loses its databases, which
# the harness answers by migrating again. CI keeps its servers on disk: the
# runner's memory is what the suite runs in, and its disk pays little for DDL.
PG_TEST_DATA := --tmpfs /var/lib/postgresql/data
MY_TEST_DATA := --tmpfs /var/lib/mysql

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
	up $(ENGINE_PREFIX)-pg16 $(ENGINE_PG_IMAGE) 127.0.0.1:$(ENGINE_PG_PORT):5432 \
	   $(PG_TEST_DATA) -e POSTGRES_PASSWORD=test -e POSTGRES_DB=openpsirt -- $(PG_AS_A_TEST_SERVER); \
	up $(ENGINE_PREFIX)-mysql $(ENGINE_MYSQL_IMAGE) 127.0.0.1:$(ENGINE_MYSQL_PORT):3306 \
	   $(MY_TEST_DATA) -e MYSQL_ROOT_PASSWORD=test -e MYSQL_DATABASE=openpsirt -- $(MY_AS_A_TEST_SERVER); \
	up $(ENGINE_PREFIX)-mariadb $(ENGINE_MARIADB_IMAGE) 127.0.0.1:$(ENGINE_MARIADB_PORT):3306 \
	   $(MY_TEST_DATA) -e MARIADB_ROOT_PASSWORD=test -e MARIADB_DATABASE=openpsirt -- $(MY_AS_A_TEST_SERVER); \
	up $(ENGINE_PREFIX)-floor $(ENGINE_FLOOR_IMAGE) 127.0.0.1:$(ENGINE_FLOOR_PORT):5432 \
	   $(PG_TEST_DATA) -e POSTGRES_PASSWORD=test -e POSTGRES_DB=openpsirt -- $(PG_AS_A_TEST_SERVER)
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
	    "# The servers above are throwaways, so the harness may turn off their" \
	    "# commit durability. A server of somebody's own needs this left out." \
	    "OPENPSIRT_TEST_RELAX_DURABILITY ?= 1" \
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

# Drops the test databases on the configured servers that no running test
# binary holds. Safe while other checkouts run their tests: each binary holds
# the lock of the slot it leases for as long as it uses the slot's database,
# and a database is dropped only while this holds that lock instead
# (internal/dbtest).
engines-clean:
	$(GO) run ./internal/tools/dbclean

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
