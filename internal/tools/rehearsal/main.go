// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command rehearsal carries a database a tagged release built through an
// upgrade to this tree, and checks what arrives.
//
//	rehearsal -from v0.1.0 -engine postgres -url postgres://… -dir .demo/rehearsal
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
//  3. The counts again, against what the upgrade tables in the database
//     design document say happens to each table's rows.
//  4. Rolled back to the release's last migration and applied again, and the
//     counts each time.
//  5. The server started on it, the open findings of every build against
//     what the release showed, and every GET its API document lists asked
//     once, none of which may answer 5xx.
//
// Everything it made is removed at the end, pass or fail, unless -keep.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
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
	adminURL     string // the engine's own URL, for creating the database
	work         string // this run's directory
	tag          string // the release's worktree
	demo         string // what the release's demo writes: its data, its fixtures
	grype        string // the scanner's database, shared between runs
	image        string // this tree's image
	hostURL      string // the rehearsal database, as this process reaches it
	appURL       string // the same database, as a container reaches it
	base         string // where the proxy answers, as the administrator
	log          *os.File
}

func main() {
	var r run
	var dir string
	var keep bool
	flag.StringVar(&r.from, "from", "", "the release to upgrade from, as v0.1.0")
	flag.StringVar(&r.engine, "engine", "", "sqlite, postgres, mysql or mariadb")
	flag.StringVar(&r.adminURL, "url", "", "the engine's URL; the rehearsal makes a database of its own beside the one named")
	flag.StringVar(&dir, "dir", ".demo/rehearsal", "where the run keeps what it makes")
	flag.StringVar(&r.grype, "grype", "", "the scanner's database directory, shared between runs")
	flag.StringVar(&r.image, "image", "openpsirt-rehearsal:current", "this tree's image")
	flag.BoolVar(&keep, "keep", false, "leave the containers and the database behind")
	flag.Parse()

	if r.from == "" || r.engine == "" {
		fmt.Fprintln(os.Stderr, "usage: rehearsal -from vX.Y.Z -engine sqlite|postgres|mysql|mariadb [-url …]")
		os.Exit(2)
	}
	if r.engine != "sqlite" && r.adminURL == "" {
		fmt.Fprintf(os.Stderr, "%s needs -url: the rehearsal makes its database beside the one it names\n", r.engine)
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

	ctx := context.Background()
	started := time.Now()
	faults, err := r.rehearse(ctx)
	if !keep {
		r.clean(ctx)
	}
	elapsed := time.Since(started).Round(time.Second)
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
	if r.log, err = os.Create(filepath.Join(r.work, "rehearsal.log")); err != nil {
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
	faults = append(faults, prefix("upgrade", Compare(held, upgraded, rules(r.from)))...)

	r.step("rolled back to %d and applied again", record.Last)
	for i := record.Last; i < current; i++ {
		if err := r.migrate(ctx, "down"); err != nil {
			return nil, err
		}
	}
	if applied, err := r.version(ctx); err != nil {
		return nil, err
	} else if applied != record.Last {
		faults = append(faults, fmt.Sprintf("rolled back, the schema is at %d, and %s's last migration is %d", applied, r.from, record.Last))
	}
	rolled, err := r.count(ctx, fromTables)
	if err != nil {
		return nil, err
	}
	faults = append(faults, prefix("rollback", Compare(held, rolled, nil))...)
	if err := r.migrate(ctx, "up"); err != nil {
		return nil, err
	}
	again, err := r.count(ctx, upgradedTables)
	if err != nil {
		return nil, err
	}
	faults = append(faults, prefix("reapplied", Compare(upgraded, again, nil))...)

	if _, ok := notes[r.from]; ok {
		r.step("what the upgrade note asks of an operator")
		n, err := r.grantImplied(ctx)
		if err != nil {
			return nil, err
		}
		r.note("%d disclosed roles granted beside undisclosed ones", n)
	}

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

// notes names the releases whose upgrade note asks an operator to act before
// the upgraded deployment serves what it served. Before v0.2.0 an undisclosed
// role reached disclosed work too, and nothing grants the disclosed role on
// upgrade (docs/configuration.md, Upgrading).
var notes = map[string]bool{"v0.1.0": true}

// database makes an empty database for the release to build, and works out
// how a container and this process each reach it.
func (r *run) database(ctx context.Context) error {
	if r.engine == "sqlite" {
		r.appURL = "sqlite:///data/dev.db"
		r.hostURL = "sqlite://" + filepath.Join(r.demo, "data", "dev.db")
		return nil
	}
	u, err := url.Parse(r.adminURL)
	if err != nil {
		return err
	}
	own := *u
	own.Path = "/" + dbName
	r.hostURL = own.String()
	inside := own
	inside.Host = "host.docker.internal:" + u.Port()
	r.appURL = inside.String()

	target, err := database.ParseURL(r.adminURL)
	if err != nil {
		return err
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
func (r *run) wrapper() (string, error) {
	path := filepath.Join(r.work, "docker")
	script := `#!/usr/bin/env bash
args=()
for a in "$@"; do
  case "$a" in
    openpsirt-demo) a=` + app + ` ;;
    openpsirt-demo-proxy) a=` + proxy + ` ;;
    openpsirt-demo:*) a="` + app + `:${a#openpsirt-demo:}" ;;
    OPENPSIRT_DATABASE_URL=*) a="OPENPSIRT_DATABASE_URL=$REHEARSAL_DB" ;;
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
	var cast []string
	for _, entry := range strings.Fields(out.String()) {
		p, rest, ok := strings.Cut(entry, ":")
		n, err := strconv.Atoi(p)
		if !ok || err != nil {
			return nil, fmt.Errorf("%s's cast entry %q has no port", r.from, entry)
		}
		cast = append(cast, fmt.Sprintf("%d:%s", n-8080+port, rest))
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

// statusLine is a build in the release's own status report, with the state
// of its last scan and what is open.
var statusLine = regexp.MustCompile(`^\s+(\S+)/streams/(\S+)/variants/(\S+)\s+scan (.*?) · open (\d+) findings`)

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
		totals := Totals{}
		busy := false
		var failed []string
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			m := statusLine.FindStringSubmatch(scanner.Text())
			if m == nil {
				continue
			}
			build := m[1] + "/" + m[2] + "/" + m[3]
			// A scan reads its inventory, then scans it. Only the last two
			// states are an end; anything else, including a build nothing
			// has reached yet, is still on its way.
			switch m[4] {
			case "scanned":
			case "failed":
				failed = append(failed, build)
			default:
				busy = true
			}
			n, _ := strconv.ParseInt(m[5], 10, 64)
			totals[build] = n
		}
		if len(failed) > 0 {
			return nil, fmt.Errorf("%s failed to scan %s, so what it seeds is not what a deployment holds",
				r.from, strings.Join(failed, ", "))
		}
		if !busy && len(totals) > 0 {
			_, _ = fmt.Fprintf(r.log, "settled: %v\n", totals)
			return totals, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the scans did not finish:\n%s", out.String())
		}
		time.Sleep(15 * time.Second)
	}
}

// count reads how many rows each table holds, with nothing running against
// the database.
func (r *run) count(ctx context.Context, tables []string) (Counts, error) {
	target, err := database.ParseURL(r.hostURL)
	if err != nil {
		return nil, err
	}
	db, err := database.Open(ctx, target)
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

// container is what every run of this tree's image shares: the release's
// network, its data, and the database.
func (r *run) container(extra ...string) []string {
	args := []string{"run", "--network", network,
		"--add-host", "host.docker.internal:host-gateway",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", filepath.Join(r.demo, "data") + ":/data",
		"-v", r.grype + ":/var/cache/openpsirt/grype",
		"-v", filepath.Join(r.demo, "repositories") + ":/var/cache/openpsirt/repositories",
		"-e", "OPENPSIRT_DATABASE_URL=" + r.appURL,
		"-e", "OPENPSIRT_ADDR=0.0.0.0:8080",
		"-e", "OPENPSIRT_PLAIN_HTTP=1",
		"-e", "OPENPSIRT_BOOTSTRAP_ADMINS=" + admin,
		"-e", "OPENPSIRT_TRUSTED_HEADER=X-User",
		"-e", "OPENPSIRT_TRUSTED_SOURCES=" + subnet,
		"-e", "OPENPSIRT_ATTACHMENT_DIR=/data/attachments",
		"-e", "OPENPSIRT_PUBLISHER_NAME=OpenPSIRT Demo",
		"-e", "OPENPSIRT_PUBLISHER_NAMESPACE=https://demo.openpsirt.invalid",
		"-e", "OPENPSIRT_ADVISORY_PREFIX=DEMO",
	}
	return append(args, extra...)
}

func (r *run) migrate(ctx context.Context, action string) error {
	args := r.container("--rm", r.image, "migrate", action)
	return r.cmd(ctx, "", nil, "docker", args...)
}

// version asks this tree's binary where the schema stands.
func (r *run) version(ctx context.Context) (int64, error) {
	var out bytes.Buffer
	c := exec.CommandContext(ctx, "docker", r.container("--rm", r.image, "migrate", "status")...) //nolint:gosec // G204: arguments this tool built itself
	c.Stdout, c.Stderr = &out, r.log
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
	if err := r.cmd(ctx, "", nil, "docker", args...); err != nil {
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
		time.Sleep(2 * time.Second)
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
	var product, stream, variant string
	for build := range builds {
		parts := strings.SplitN(build, "/", 3)
		if product == "" || parts[0] < product {
			product, stream, variant = parts[0], parts[1], parts[2]
		}
	}
	names := map[string]string{"product": product, "stream": stream, "variant": variant,
		"team": "platform", "identity": admin, "format": "csv"}
	param := regexp.MustCompile(`\{(\w+)\}`)
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
		missing := false
		filled := param.ReplaceAllStringFunc(path, func(p string) string {
			v, ok := names[strings.Trim(p, "{}")]
			if !ok {
				missing = true
			}
			return url.PathEscape(v)
		})
		if missing {
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
	_ = exec.CommandContext(ctx, "docker", "network", "rm", network).Run()
	if r.engine != "sqlite" && r.adminURL != "" {
		if target, err := database.ParseURL(r.adminURL); err == nil {
			if db, err := database.Open(ctx, target); err == nil {
				_, _ = db.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+dbName+`"`)
				_ = db.Close()
			}
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
		if table != "goose_db_version" {
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
		if t != "goose_db_version" {
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
