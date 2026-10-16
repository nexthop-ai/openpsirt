// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command rehearsal carries a database a tagged release built through an
// upgrade to this tree, and checks what arrives.
//
//	rehearsal -from v0.7.0 -engine postgres -dir .demo/rehearsal
//
// A server engine's URL is read from OPENPSIRT_TEST_<ENGINE>_URL, the variable
// the test suite reads, so the password is never on the command line.
//
// The release seeds its own database: its image is built from its own tag,
// and its own demo targets declare the products, upload the inventories, let
// the scans land and record the VEX document, the judgments and the flaw. That
// is the data a deployment of that release actually holds, which no fixture
// written today can stand in for. The tag's targets run unedited; only the
// docker command they call is wrapped, so its containers, network and ports
// stay clear of a demo already running, and its database is the one named.
//
// Then this tree's image takes the database over:
//
//  1. The row count of every table, with the release stopped.
//  2. The migrations, applied on their own, and the version they reach.
//  3. The counts again: a table the release held keeps its count, and a
//     table the upgrade adds starts empty, except where an upgrade merges
//     rows or fills a table from rows the release held.
//  4. The server started on it with the configuration the release's demo
//     started its own with, the open findings of every build against what
//     the release showed, and every GET its API document lists asked once,
//     none of which may answer 5xx.
//
// Everything it made is removed at the end, pass, fail or interrupt, unless
// -keep.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/released"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// The names this run gives what it makes. None is a name the demo uses, so a
// demo somebody has running is left alone.
const (
	app      = "openpsirt-rehearsal"
	proxy    = "openpsirt-rehearsal-proxy"
	network  = "openpsirt-rehearsal-net"
	subnet   = "172.31.72.0/24"
	dbName   = "openpsirt_rehearsal"
	port     = 18080
	admin    = "dev"
	releases = "internal/database/migrate/released"
)

type run struct {
	from, engine string
	adminURL     string   // the engine's own URL, for creating the database
	work         string   // this run's directory
	tag          string   // the release's worktree
	demo         string   // what the release's demo writes: its data, its fixtures
	grype        string   // the scanner's database, shared between runs
	image        string   // this tree's image
	hostURL      string   // the rehearsal database, as this process reaches it
	appURL       string   // the same database, as a container reaches it
	attached     string   // the engine's container, joined to the rehearsal's network
	env          []string // what the release's demo started its server with, beyond its image
	base         string   // where the proxy answers, as the administrator
	log          *os.File
}

func main() {
	var r run
	var dir string
	var keep bool
	flag.StringVar(&r.from, "from", "", "the release to upgrade from, as v0.7.0")
	flag.StringVar(&r.engine, "engine", "", "sqlite, postgres, mysql or mariadb")
	flag.StringVar(&dir, "dir", ".demo/rehearsal", "where the run keeps what it makes")
	flag.StringVar(&r.grype, "grype", "", "the scanner's database directory, shared between runs")
	flag.StringVar(&r.image, "image", "openpsirt-rehearsal:current", "this tree's image")
	flag.BoolVar(&keep, "keep", false, "leave the containers and the database behind")
	flag.Parse()

	if r.from == "" || r.engine == "" {
		fmt.Fprintln(os.Stderr, "usage: rehearsal -from vX.Y.Z -engine sqlite|postgres|mysql|mariadb")
		os.Exit(2)
	}
	if err := usable(r.from, r.engine); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	r.adminURL = engineURL(r.engine, os.Getenv)
	if r.engine != "sqlite" && r.adminURL == "" {
		fmt.Fprintf(os.Stderr, "%s needs %s: the rehearsal makes its database beside the one it names\n",
			r.engine, engineVariable(r.engine))
		os.Exit(2)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	r.work = filepath.Join(abs, r.from+"-"+r.engine)
	r.tag = filepath.Join(abs, "tag-"+r.from)
	r.demo = filepath.Join(r.work, "demo")
	if r.grype == "" {
		r.grype = filepath.Join(abs, "grype")
	}
	r.base = fmt.Sprintf("http://127.0.0.1:%d", port)

	// An interrupt cancels the run and still removes what it made: the
	// cleanup takes a context the interrupt does not cancel. The signals are
	// released before the cleanup, so a second interrupt stops a cleanup that
	// hangs.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	began := time.Now()
	faults, err := r.rehearse(ctx)
	stop()
	if !keep {
		r.clean(context.WithoutCancel(ctx))
	}
	elapsed := time.Since(began).Round(time.Second)
	switch {
	case err != nil:
		fmt.Printf("%s on %s: stopped after %s: %v\n", r.from, r.engine, elapsed, err)
		os.Exit(1)
	case len(faults) > 0:
		fmt.Printf("%s on %s: %d faults in %s\n", r.from, r.engine, len(faults), elapsed)
		for _, fault := range faults {
			fmt.Println("  " + fault)
		}
		os.Exit(1)
	}
	fmt.Printf("%s on %s: upgraded clean in %s\n", r.from, r.engine, elapsed)
}

func (r *run) rehearse(ctx context.Context) ([]string, error) {
	r.clean(ctx)
	if err := os.RemoveAll(r.work); err != nil {
		return nil, err
	}
	for _, d := range []string{r.work, filepath.Join(r.demo, "data"), filepath.Join(r.demo, "repositories"), r.grype} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	var err error
	if r.log, err = os.OpenFile(filepath.Join(r.work, "rehearsal.log"), //nolint:gosec // G304: a name this tool chose, under its own directory
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err != nil {
		return nil, err
	}
	// The release's demo mounts its own directory for the scanner's database.
	// A link keeps the gigabyte in one place for every run.
	if err := os.Symlink(r.grype, filepath.Join(r.demo, "grype")); err != nil {
		return nil, err
	}

	r.step("the %s tree", r.from)
	if _, err := os.Stat(r.tag); err != nil {
		if err := r.cmd(ctx, "", nil, "git", "worktree", "add", "--detach", r.tag, r.from); err != nil {
			return nil, err
		}
	}
	// Read to refuse a release with no record, which has no schema to compare.
	record, err := released.Read(releases, r.from)
	if err != nil {
		return nil, fmt.Errorf("the release record for %s: %w", r.from, err)
	}
	current, err := schema.Expected()
	if err != nil {
		return nil, err
	}
	fromTables, err := tablesOf(filepath.Join(releases, r.from, released.Schema(r.engine)))
	if err != nil {
		return nil, err
	}

	r.step("a database of its own on %s", r.engine)
	if err := r.database(ctx); err != nil {
		return nil, err
	}
	wrapper, err := r.wrapper()
	if err != nil {
		return nil, err
	}

	r.step("%s's image, and its demo seeded", r.from)
	release := "openpsirt-rehearsal:" + r.from
	// A tag names one set of bytes, so an image built from it once is the
	// image. The build stamps the date, which would otherwise rebuild it on
	// every run.
	if exec.CommandContext(ctx, "docker", "image", "inspect", release).Run() != nil { //nolint:gosec // G204: the image name is built from a release tag this tool was given
		if err := r.cmd(ctx, r.tag, nil, "make", "demo-image", "DEMO_IMAGE="+release); err != nil {
			return nil, err
		}
	}
	overrides, err := r.overrides(ctx, wrapper, release)
	if err != nil {
		return nil, err
	}
	env := []string{"REHEARSAL_DB=" + r.appURL}
	if err := r.cmd(ctx, r.tag, env, "make", append([]string{"demo-up", "demo-seed"}, overrides...)...); err != nil {
		return nil, err
	}
	if _, err := r.settle(ctx, overrides, env); err != nil {
		return nil, err
	}
	if err := r.cmd(ctx, r.tag, env, "make", append([]string{"demo-vex", "demo-triage", "demo-flaw"}, overrides...)...); err != nil {
		return nil, err
	}
	before, err := r.settle(ctx, overrides, env)
	if err != nil {
		return nil, err
	}
	if r.env, err = r.startedWith(ctx, release); err != nil {
		return nil, err
	}
	r.saveLogs(ctx, r.from)
	if err := r.cmd(ctx, "", nil, "docker", "rm", "-f", app); err != nil {
		return nil, err
	}

	var faults []string
	r.step("the rows %s left", r.from)
	held, err := r.count(ctx, fromTables)
	if err != nil {
		return nil, err
	}
	r.note("%d tables, %d findings, %d decisions, %d claims", len(held), held["finding"], held["decision"], held["claim"])
	// An upgrade of an empty database passes every check here, so a seed
	// that filled nothing is a failed rehearsal rather than a clean one.
	var empty []string
	for _, table := range []string{"finding", "decision", "claim", "vex_statement", "flaw_report"} {
		if held[table] == 0 {
			empty = append(empty, table)
		}
	}
	if len(empty) > 0 {
		return nil, fmt.Errorf("%s's seed left nothing in %s, so an upgrade of it would check nothing",
			r.from, strings.Join(empty, ", "))
	}

	images, err := r.images(ctx)
	if err != nil {
		return nil, err
	}
	var words Words
	var rated Ratings
	if record.Last < wordsAndRatings {
		if words, rated, err = r.heldWordsAndRatings(ctx); err != nil {
			return nil, err
		}
	}

	r.step("migrated to %d by this tree", current)
	if err := r.migrate(ctx, "up"); err != nil {
		return nil, err
	}
	if applied, err := r.version(ctx); err != nil {
		return nil, err
	} else if applied != current {
		faults = append(faults, fmt.Sprintf("the upgrade reached schema version %d, and this tree carries %d", applied, current))
	}
	upgradedTables := unionTables(fromTables, dbtest.Tables())
	upgraded, err := r.count(ctx, upgradedTables)
	if err != nil {
		return nil, err
	}
	moved := Moved(record.Last, images)
	if record.Last < wordsAndRatings {
		left, err := r.ratings(ctx)
		if err != nil {
			return nil, err
		}
		restated, wrong := Restated(record.Last, words, rated, left)
		maps.Copy(moved, restated)
		faults = append(faults, prefix("upgrade", wrong)...)
	}
	faults = append(faults, prefix("upgrade", Compare(held, upgraded, moved))...)

	r.step("served by this tree")
	if err := r.serve(ctx); err != nil {
		return nil, err
	}
	after, err := r.open(ctx, before)
	if err != nil {
		return nil, err
	}
	faults = append(faults, CompareTotals("open findings", before, after)...)
	swept, err := r.sweep(ctx, before)
	if err != nil {
		return nil, err
	}
	faults = append(faults, swept...)
	r.saveLogs(ctx, "current")
	return faults, nil
}

// engineVariable is the environment variable holding an engine's URL.
func engineVariable(engine string) string {
	return "OPENPSIRT_TEST_" + strings.ToUpper(engine) + "_URL"
}

// engineURL is the URL the environment holds for the engine. Never an
// argument: a command line is readable by every local user for the whole run
// and is written to the rehearsal's log.
func engineURL(engine string, getenv func(string) string) string {
	if engine == "sqlite" {
		return ""
	}
	return getenv(engineVariable(engine))
}

// database makes an empty database for the release to build, and works out
// how a container and this process each reach it.
func (r *run) database(ctx context.Context) error {
	if r.engine == "sqlite" {
		r.appURL = "sqlite:///data/dev.db"
		r.hostURL = "sqlite://" + filepath.Join(r.demo, "data", "dev.db")
		return nil
	}
	// Parsed by the database package first. The URL parser's own error
	// quotes the text it could not read, and that text holds the password.
	target, err := database.ParseURL(r.adminURL)
	if err != nil {
		return err
	}
	u, err := url.Parse(r.adminURL)
	if err != nil {
		return err
	}
	own := *u
	own.Path = "/" + dbName
	r.hostURL = own.String()
	inside := own
	if inside.Host, r.attached, err = reachEngine(ctx, u, runDocker); err != nil {
		return fmt.Errorf("reaching the engine from a container: %w", err)
	}
	r.appURL = inside.String()
	if r.attached != "" {
		r.note("reached as %s, on the rehearsal's network", inside.Host)
	} else {
		r.note("reached as %s", inside.Host)
	}

	db, err := database.Open(ctx, target)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	for _, stmt := range []string{`DROP DATABASE IF EXISTS "` + dbName + `"`, `CREATE DATABASE "` + dbName + `"`} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

// wrapper writes the docker command the release's targets call. It renames
// what they make, points the application at the rehearsal database, and lets
// the proxy the release configured still reach the application by the name it
// wrote into its configuration.
//
// The database URL carries a password, so it reaches docker through the
// environment and never as an argument, which every local user can read.
func (r *run) wrapper() (string, error) {
	path := filepath.Join(r.work, "docker")
	script := `#!/usr/bin/env bash
args=()
for a in "$@"; do
  case "$a" in
    openpsirt-demo) a=` + app + ` ;;
    openpsirt-demo-proxy) a=` + proxy + ` ;;
    openpsirt-demo:*) a="` + app + `:${a#openpsirt-demo:}" ;;
    OPENPSIRT_DATABASE_URL=*) export OPENPSIRT_DATABASE_URL="$REHEARSAL_DB"; a=OPENPSIRT_DATABASE_URL ;;
  esac
  args+=("$a")
done
if [ "${args[0]}" = run ] && printf '%s\n' "${args[@]}" | grep -qx ` + app + `; then
  args=(run --network-alias openpsirt-demo --add-host host.docker.internal:host-gateway "${args[@]:1}")
fi
exec docker "${args[@]}"
`
	return path, os.WriteFile(path, []byte(script), 0o700) //nolint:gosec // G306: the wrapper is a script the release's targets execute
}

// overrides are the variables the release's targets are run with: its own
// cast and builds, moved onto ports and a network of the rehearsal's.
func (r *run) overrides(ctx context.Context, wrapper, image string) ([]string, error) {
	var out bytes.Buffer
	c := exec.CommandContext(ctx, "make", "-s", "--no-print-directory", "--eval", "rehearsal-cast: ; @echo $(DEMO_CAST)", "rehearsal-cast")
	c.Dir, c.Stdout, c.Stderr = r.tag, &out, r.log
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("read %s's cast: %w", r.from, err)
	}
	cast, err := shiftCast(out.String(), port)
	if err != nil {
		return nil, fmt.Errorf("%s's %w", r.from, err)
	}
	return []string{
		"DOCKER=" + wrapper,
		"DEMO_IMAGE=" + image,
		"DEMO_DIR=" + r.demo,
		"DEMO_NET=" + network,
		"DEMO_SUBNET=" + subnet,
		"DEMO_HOST=127.0.0.1",
		"DEMO_PORT=" + strconv.Itoa(port),
		"DEMO_USER=" + admin,
		"DEMO_CAST=" + strings.Join(cast, " "),
	}, nil
}

// settle waits for every scan the release queued to finish, asking the
// release's own status target, and answers what it reports open per build.
func (r *run) settle(ctx context.Context, overrides, env []string) (Totals, error) {
	deadline := time.Now().Add(90 * time.Minute)
	for {
		var out bytes.Buffer
		c := exec.CommandContext(ctx, "make", append([]string{"-s", "--no-print-directory", "demo-status"}, overrides...)...) //nolint:gosec // G204: overrides this tool built itself
		c.Dir, c.Stdout, c.Stderr, c.Env = r.tag, &out, r.log, append(os.Environ(), env...)
		if err := c.Run(); err != nil {
			return nil, fmt.Errorf("%s's status: %w", r.from, err)
		}
		_, _ = fmt.Fprint(r.log, out.String())
		totals, busy, failed, unread := parseStatus(out.String())
		if len(failed) > 0 {
			return nil, fmt.Errorf("%s failed to scan %s, so what it seeds is not what a deployment holds",
				r.from, strings.Join(failed, ", "))
		}
		if !busy && len(totals) > 0 {
			_, _ = fmt.Fprintf(r.log, "settled: %v\n", totals)
			return totals, nil
		}
		if time.Now().After(deadline) {
			if len(unread) > 0 {
				return nil, fmt.Errorf("%s's status never gave a count for:\n  %s",
					r.from, strings.Join(unread, "\n  "))
			}
			return nil, fmt.Errorf("the scans did not finish:\n%s", out.String())
		}
		if err := pause(ctx, 15*time.Second); err != nil {
			return nil, err
		}
	}
}

// connect opens a database by its URL, parsed by the database package so a
// malformed one is refused without quoting the password it holds.
func connect(ctx context.Context, raw string) (*database.DB, error) {
	target, err := database.ParseURL(raw)
	if err != nil {
		return nil, err
	}
	return database.Open(ctx, target)
}

// count reads how many rows each table holds, with nothing running against
// the database.
func (r *run) count(ctx context.Context, tables []string) (Counts, error) {
	db, err := connect(ctx, r.hostURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	counts := Counts{}
	for _, table := range tables {
		var n int64
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "`+table+`"`).Scan(&n); err != nil {
			// A table the side being counted does not hold is absent from
			// the answer, which Compare reads as gone or not made.
			_, _ = fmt.Fprintf(r.log, "count %s: %v\n", table, err)
			continue
		}
		counts[table] = n
	}
	return counts, nil
}

// images counts the rows the release held for container images: components
// whose package identifier is of type oci or docker, their nodes, and the
// edges at those nodes. Matched on the identifier's prefix in its lowest
// spelling, which is the one every recorded producer writes.
func (r *run) images(ctx context.Context) (Images, error) {
	db, err := connect(ctx, r.hostURL)
	if err != nil {
		return Images{}, err
	}
	defer func() { _ = db.Close() }()
	const image = `SELECT "id" FROM "component" WHERE "purl" LIKE 'pkg:oci/%' OR "purl" LIKE 'pkg:docker/%'`
	const nodes = `SELECT "id" FROM "graph_node" WHERE "component_id" IN (` + image + `)`
	var out Images
	for _, each := range []struct {
		query string
		into  *int64
	}{
		{`SELECT COUNT(*) FROM (` + image + `) AS "i"`, &out.Components},
		{`SELECT COUNT(*) FROM (` + nodes + `) AS "n"`, &out.Nodes},
		{`SELECT COUNT(*) FROM "graph_edge" WHERE "parent_id" IN (` + nodes + `) OR "child_id" IN (` + nodes + `)`, &out.Edges},
	} {
		if err := db.QueryRowContext(ctx, each.query).Scan(each.into); err != nil {
			return Images{}, fmt.Errorf("count the release's images: %w", err)
		}
	}
	return out, nil
}

// heldWordsAndRatings reads what the release held that the upgrade stores
// reasoning and recorded ratings from.
func (r *run) heldWordsAndRatings(ctx context.Context) (Words, Ratings, error) {
	db, err := connect(ctx, r.hostURL)
	if err != nil {
		return Words{}, Ratings{}, err
	}
	defer func() { _ = db.Close() }()
	words, err := distinctWords(ctx, db)
	if err != nil {
		return Words{}, Ratings{}, err
	}
	rated, err := ratingsOf(ctx, db, false)
	if err != nil {
		return Words{}, Ratings{}, err
	}
	// A recorded flaw on an issue rated by a word or by a score naming no
	// publisher, and whether the issue holds a scanned finding and absorbed
	// another in a merge.
	const recorded = `SELECT DISTINCT "v"."id", "st"."product_id" FROM "finding" AS "f"
		JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"
		JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"
		JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
		WHERE "f"."kind" = 'entered' AND `
	// A scanned issue kept in a merge, as the upgrade tells one apart.
	const kept = `(EXISTS (SELECT 1 FROM "finding" AS "scanned"
			WHERE "scanned"."vulnerability_id" = "v"."id" AND "scanned"."kind" <> 'entered')
		AND EXISTS (SELECT 1 FROM "vulnerability_merge" AS "vm" WHERE "vm"."kept_id" = "v"."id"))`
	for _, each := range []struct {
		query string
		into  *int64
	}{
		{`SELECT COUNT(*) FROM (` + recorded + `NOT ` + kept + ` AND (COALESCE("v"."severity", '') <> ''
			OR (COALESCE("v"."score_source", '') = '' AND "v"."score_centi" IS NOT NULL))) AS "p"`, &rated.Plain},
		{`SELECT COUNT(*) FROM (` + recorded + kept + `) AS "k"`, &rated.Kept},
	} {
		if err := db.QueryRowContext(ctx, each.query).Scan(each.into); err != nil {
			return Words{}, Ratings{}, fmt.Errorf("count the release's recorded flaws: %w", err)
		}
	}
	return words, rated, nil
}

// distinctWords counts the reasoning the release held across every claim and
// every supplier statement, compared byte for byte once kept as the upgrade
// keeps it. A comparison in SQL follows the column's collation, which on
// MySQL and MariaDB ignores trailing spaces.
func distinctWords(ctx context.Context, db *database.DB) (Words, error) {
	rows, err := db.QueryContext(ctx, `SELECT "statement" FROM "suppression" WHERE "statement" IS NOT NULL
		UNION ALL
		SELECT "statement" FROM "vex_statement" WHERE "statement" IS NOT NULL`)
	if err != nil {
		return Words{}, fmt.Errorf("read the release's reasoning: %w", err)
	}
	seen := map[[sha256.Size]byte]bool{}
	for rows.Next() {
		var said string
		if err := rows.Scan(&said); err != nil {
			_ = rows.Close()
			return Words{}, err
		}
		if kept := KeptWords(said); kept != "" {
			seen[sha256.Sum256([]byte(kept))] = true
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return Words{}, fmt.Errorf("read the release's reasoning: %w", err)
	}
	return Words{Distinct: int64(len(seen))}, nil
}

// ratings reads the ratings the upgrade moved, on the upgraded database.
func (r *run) ratings(ctx context.Context) (Ratings, error) {
	db, err := connect(ctx, r.hostURL)
	if err != nil {
		return Ratings{}, err
	}
	defer func() { _ = db.Close() }()
	return ratingsOf(ctx, db, true)
}

// ratingsOf reads each issue's unsourced ratings, the sourced ones, and the
// words in force, and after the upgrade the recorded ratings too.
func ratingsOf(ctx context.Context, db *database.DB, upgraded bool) (Ratings, error) {
	out := Ratings{Unsourced: map[int64]int64{}, InForce: map[Pair]bool{}, Recorded: map[Pair]bool{}}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "vulnerability_rating"
		WHERE COALESCE("score_source", '') <> ''`).Scan(&out.Sourced); err != nil {
		return Ratings{}, fmt.Errorf("count the sourced ratings: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT "vulnerability_id", COUNT(*) FROM "vulnerability_rating"
		WHERE COALESCE("score_source", '') = '' GROUP BY "vulnerability_id"`)
	if err != nil {
		return Ratings{}, fmt.Errorf("count the unsourced ratings: %w", err)
	}
	for rows.Next() {
		var issue, n int64
		if err := rows.Scan(&issue, &n); err != nil {
			_ = rows.Close()
			return Ratings{}, err
		}
		out.Unsourced[issue] = n
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return Ratings{}, err
	}
	pairs := []struct {
		query string
		into  map[Pair]bool
	}{{`SELECT "vulnerability_id", "product_id", 1 FROM "issue_rating"`, out.InForce}}
	if upgraded {
		pairs = append(pairs, struct {
			query string
			into  map[Pair]bool
		}{`SELECT "vulnerability_id", "product_id", CASE WHEN "severity" IS NULL THEN 0 ELSE 1 END
			FROM "recorded_rating"`, out.Recorded})
	}
	for _, each := range pairs {
		rows, err := db.QueryContext(ctx, each.query)
		if err != nil {
			return Ratings{}, fmt.Errorf("read the ratings by issue and product: %w", err)
		}
		for rows.Next() {
			var p Pair
			var worded int
			if err := rows.Scan(&p.Issue, &p.Product, &worded); err != nil {
				_ = rows.Close()
				return Ratings{}, err
			}
			each.into[p] = worded == 1
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return Ratings{}, err
		}
	}
	return out, nil
}

// container is what every run of this tree's image shares: the release's
// network, its data, and the database.
func (r *run) container(extra ...string) []string {
	args := []string{"run", "--network", network,
		"--add-host", "host.docker.internal:host-gateway",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", filepath.Join(r.demo, "data") + ":/data",
		"-v", r.grype + ":/var/cache/openpsirt/grype",
		"-v", filepath.Join(r.demo, "repositories") + ":/var/cache/openpsirt/repositories",
		// Named without a value, so docker takes it from the environment
		// withDatabase sets: an argument is readable by every local user and
		// is written to the log.
		"-e", "OPENPSIRT_DATABASE_URL",
	}
	// The release's demo configuration, named the same way, since nothing
	// says which of its values is a secret.
	for _, entry := range r.env {
		name, _, _ := strings.Cut(entry, "=")
		args = append(args, "-e", name)
	}
	return append(args, extra...)
}

// withDatabase is the environment a container run takes its database and the
// release's demo configuration from.
func (r *run) withDatabase() []string {
	return append([]string{"OPENPSIRT_DATABASE_URL=" + r.appURL}, r.env...)
}

// startedWith reads the environment the release's server container was
// started with beyond its image's own.
func (r *run) startedWith(ctx context.Context, image string) ([]string, error) {
	read := func(kind, name string) ([]string, error) {
		var out, stderr bytes.Buffer
		c := exec.CommandContext(ctx, "docker", kind, "inspect", "--format", "{{json .Config.Env}}", name) //nolint:gosec // G204: a name this tool chose
		c.Stdout, c.Stderr = &out, &stderr
		if err := c.Run(); err != nil {
			return nil, fmt.Errorf("docker %s inspect %s: %w: %s", kind, name, err, strings.TrimSpace(stderr.String()))
		}
		var env []string
		if err := json.Unmarshal(out.Bytes(), &env); err != nil {
			return nil, fmt.Errorf("docker %s inspect %s: %w", kind, name, err)
		}
		return env, nil
	}
	container, err := read("container", app)
	if err != nil {
		return nil, err
	}
	own, err := read("image", image)
	if err != nil {
		return nil, err
	}
	env := started(container, own)
	if len(env) == 0 {
		return nil, fmt.Errorf("%s's server was started with no configuration of its own, so there is none to serve this tree with", r.from)
	}
	return env, nil
}

func (r *run) migrate(ctx context.Context, action string) error {
	args := r.container("--rm", r.image, "migrate", action)
	return r.cmd(ctx, "", r.withDatabase(), "docker", args...)
}

// version asks this tree's binary where the schema stands.
func (r *run) version(ctx context.Context) (int64, error) {
	var out bytes.Buffer
	c := exec.CommandContext(ctx, "docker", r.container("--rm", r.image, "migrate", "status")...) //nolint:gosec // G204: arguments this tool built itself
	c.Stdout, c.Stderr = &out, r.log
	c.Env = append(os.Environ(), r.withDatabase()...)
	if err := c.Run(); err != nil {
		return 0, fmt.Errorf("migrate status: %w", err)
	}
	m := regexp.MustCompile(`schema version (\d+) of`).FindStringSubmatch(out.String())
	if m == nil {
		return 0, fmt.Errorf("migrate status said %q", out.String())
	}
	return strconv.ParseInt(m[1], 10, 64)
}

// serve starts this tree's image on the database, where the release's proxy
// reaches it by the name it was configured with.
func (r *run) serve(ctx context.Context) error {
	args := r.container("-d", "--name", app, "--network-alias", "openpsirt-demo", r.image)
	if err := r.cmd(ctx, "", r.withDatabase(), "docker", args...); err != nil {
		return err
	}
	// The proxy resolved the application's address when it started, and this
	// is a different container.
	if err := r.cmd(ctx, "", nil, "docker", "restart", proxy); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if status, _, err := r.get(ctx, "/readyz"); err == nil && status == http.StatusOK {
			return nil
		}
		if err := pause(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	return errors.New("this tree's server never answered ready")
}

// open is what this tree's server reports open for each build the release
// reported on.
func (r *run) open(ctx context.Context, builds Totals) (Totals, error) {
	out := Totals{}
	for build := range builds {
		parts := strings.SplitN(build, "/", 3)
		q := url.Values{"stream": {parts[1]}, "variant": {parts[2]}, "limit": {"1"}}
		status, body, err := r.get(ctx, "/v1/products/"+url.PathEscape(parts[0])+"/findings?"+q.Encode())
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			_, _ = fmt.Fprintf(r.log, "open %s: %d %s\n", build, status, body)
			continue
		}
		var page struct {
			Total int64 `json:"total"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("open %s: %w", build, err)
		}
		out[build] = page.Total
	}
	return out, nil
}

// sweep asks every GET the served API document lists, with the names the
// seed made standing in for its path parameters, and reports any 5xx. An
// operation whose parameter the seed has no name for is skipped.
func (r *run) sweep(ctx context.Context, builds Totals) ([]string, error) {
	status, body, err := r.get(ctx, "/openapi.json")
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("the API document: %d %v", status, err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	product, stream, variant, ok := firstBuild(builds)
	if !ok {
		return nil, errors.New("the release reported no build, so the sweep has no names to ask with")
	}
	names := map[string]string{"product": product, "stream": stream, "variant": variant,
		"team": "platform", "identity": admin, "format": "csv"}
	paths := make([]string, 0, len(doc.Paths))
	for path, ops := range doc.Paths {
		if _, ok := ops["get"]; ok {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	var faults []string
	asked, skipped, answered := 0, 0, 0
	for _, path := range paths {
		filled, complete := fillPath(path, names)
		if !complete {
			skipped++
			continue
		}
		asked++
		status, body, err := r.get(ctx, filled)
		switch {
		case err != nil:
			faults = append(faults, fmt.Sprintf("GET %s: %v", filled, err))
		case status >= 500:
			faults = append(faults, fmt.Sprintf("GET %s answered %d: %s", filled, status, head(body)))
		case status < 300:
			answered++
		default:
			_, _ = fmt.Fprintf(r.log, "GET %s: %d %s\n", filled, status, head(body))
		}
	}
	r.note("asked %d GET operations, %d answered 2xx; skipped %d whose parameters the seed has no name for",
		asked, answered, skipped)
	// A sweep that reached nothing but refusals asked as nobody, and a
	// refusal says nothing about whether the query behind it works.
	if answered == 0 {
		return nil, errors.New("no GET answered 2xx, so the sweep checked nothing")
	}
	return faults, nil
}

func (r *run) get(ctx context.Context, path string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	res, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	return res.StatusCode, body, err
}

// clean removes the containers, the network and the database. The worktree
// of the release and the scanner's database are kept for the next run.
func (r *run) clean(ctx context.Context) {
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", app, proxy).Run()
	// The engine leaves the network rather than going with it: a network with
	// a container on it is not removed.
	if r.attached != "" {
		_ = exec.CommandContext(ctx, "docker", "network", "disconnect", "-f", network, r.attached).Run() //nolint:gosec // G204: the container this run attached
	}
	_ = exec.CommandContext(ctx, "docker", "network", "rm", network).Run()
	if r.engine != "sqlite" && r.adminURL != "" {
		if db, err := connect(ctx, r.adminURL); err == nil {
			_, _ = db.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+dbName+`"`)
			_ = db.Close()
		}
	}
	_ = os.RemoveAll(filepath.Join(r.demo, "data"))
}

func (r *run) saveLogs(ctx context.Context, name string) {
	f, err := os.Create(filepath.Join(r.work, name+".log")) //nolint:gosec // G304: a name this tool chose, under its own directory
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	c := exec.CommandContext(ctx, "docker", "logs", app)
	c.Stdout, c.Stderr = f, f
	_ = c.Run()
}

func (r *run) cmd(ctx context.Context, dir string, env []string, name string, args ...string) error {
	_, _ = fmt.Fprintf(r.log, "$ %s %s\n", name, strings.Join(args, " "))
	c := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: every caller names a fixed program
	c.Dir, c.Stdout, c.Stderr = dir, r.log, r.log
	c.Env = append(os.Environ(), env...)
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (see %s)", name, strings.Join(args[:min(2, len(args))], " "), err, r.log.Name())
	}
	return nil
}

func (r *run) step(format string, args ...any) {
	line := fmt.Sprintf("%s %s: ", r.from, r.engine) + fmt.Sprintf(format, args...)
	fmt.Println(line)
	_, _ = fmt.Fprintln(r.log, "== "+line)
}

func (r *run) note(format string, args ...any) {
	line := "  " + fmt.Sprintf(format, args...)
	fmt.Println(line)
	_, _ = fmt.Fprintln(r.log, line)
}

// tablesOf reads the tables a release's schema record names.
func tablesOf(path string) ([]string, error) {
	content, err := os.ReadFile(path) //nolint:gosec // G304: a schema snapshot in this checkout
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "column" {
			continue
		}
		table, _, _ := strings.Cut(fields[1], ".")
		if table != migrate.VersionTable {
			seen[table] = true
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("%s names no tables, so counting it would check nothing", path)
	}
	return unionTables(nil, keys(seen)), nil
}

func unionTables(a, b []string) []string {
	seen := map[string]bool{}
	for _, t := range append(slices.Clone(a), b...) {
		if t != migrate.VersionTable {
			seen[t] = true
		}
	}
	return keys(seen)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func prefix(what string, faults []string) []string {
	for i, f := range faults {
		faults[i] = what + ": " + f
	}
	return faults
}

func head(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// usable refuses a release and an engine that are not one, before either is
// joined into a path. The directory named by the two is removed and replaced
// by a worktree, so a -from like "../../elsewhere" would remove a directory
// outside the run's own.
func usable(from, engine string) error {
	if _, err := released.Base(from); err != nil {
		return err
	}
	for _, known := range database.Engines() {
		if string(known) == engine {
			return nil
		}
	}
	return fmt.Errorf("%q is not an engine: one of sqlite, postgres, mysql or mariadb", engine)
}
