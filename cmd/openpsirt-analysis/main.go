// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command openpsirt-analysis sends an analyzer's run from a build pipeline
// to OpenPSIRT, as the SARIF the deployment reads best.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/analysisclient"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

const usage = `openpsirt-analysis sends an analyzer's run to OpenPSIRT.

  openpsirt-analysis upload --product P --stream S --variant V --series NAME [flags] OUTPUT...
  openpsirt-analysis write  --series NAME [flags] --output FILE OUTPUT...
  openpsirt-analysis version

Each OUTPUT is clang plist-multi-file, cppcheck XML version 2, or any tool's
SARIF 2.1.0, compressed with gzip or not. The address is --url, or
OPENPSIRT_URL where the flag is not given. The key is read from OPENPSIRT_KEY
alone, so it is never on a command line a process listing shows.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "openpsirt-analysis:", err)
		os.Exit(1)
	}
}

// many is a flag that may be given more than once.
type many []string

func (m *many) String() string     { return strings.Join(*m, ",") }
func (m *many) Set(v string) error { *m = append(*m, v); return nil }

// count is a whole-number flag that may be left unset.
type count struct{ n *int }

func (c *count) String() string {
	if c.n == nil {
		return ""
	}
	return strconv.Itoa(*c.n)
}

func (c *count) Set(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("%q is not a whole number", v)
	}
	c.n = &n
	return nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return errors.New("name a command")
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintln(stdout, "openpsirt-analysis", version.Get().Version)
		return err
	case "upload", "write":
	case "help", "-h", "--help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return fmt.Errorf("%q is not a command", args[0])
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		to                               analysisclient.Target
		series, commit, built, root, out string
		toolVersion, saltFile, rulesFile string
		compileCommands                  string
		snippets                         bool
		rules, thirdParty                many
		expected, analyzed, exitStatus   count
	)
	fs.StringVar(&to.URL, "url", os.Getenv("OPENPSIRT_URL"), "the deployment's address")
	fs.StringVar(&to.Product, "product", "", "the declared product the build is of")
	fs.StringVar(&to.Stream, "stream", "", "the declared branch or tag")
	fs.StringVar(&to.Variant, "variant", "", "the declared way the stream is built")
	fs.StringVar(&series, "series", "", "which analysis this is, the same for every build: the tool and its configuration")
	fs.StringVar(&commit, "commit", "", "the commit analyzed; the checked-out commit where unset")
	fs.StringVar(&built, "built", "", "when the build was made, in RFC 3339; the deployment dates the run on arrival where unset")
	fs.StringVar(&root, "source-root", "", "the top of the checkout; the git working tree holding the current directory where unset")
	fs.StringVar(&toolVersion, "tool-version", "", "the analyzer's version, where its output states none")
	fs.Var(&rules, "rule", "a rule enabled; repeat for each")
	fs.StringVar(&rulesFile, "rules-file", "", "a file naming the rules enabled, one per line")
	fs.Var(&thirdParty, "third-party", "a path, relative to the checkout, holding code the product did not write; repeat for each")
	fs.Var(&expected, "units-expected", "how many translation units the run was meant to analyze")
	fs.Var(&analyzed, "units-analyzed", "how many it analyzed; for clang, the plist documents given where unset")
	fs.StringVar(&compileCommands, "compile-commands", "", "a compilation database whose entries are the units the run was meant to analyze")
	fs.Var(&exitStatus, "exit-status", "the analyzer's exit status")
	fs.BoolVar(&snippets, "snippets", false, "send the source lines of each location; off, no source leaves the pipeline")
	fs.StringVar(&saltFile, "salt-file", "", "a file holding the secret the content fingerprint is keyed with")
	fs.StringVar(&out, "output", "", "where write puts the document")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	files := fs.Args()
	if len(files) == 0 {
		return errors.New("name the analyzer's output files")
	}

	opts := analysisclient.Options{
		Series: series, Commit: commit, ToolVersion: toolVersion, Snippets: snippets,
		UnitsExpected: expected.n, UnitsAnalyzed: analyzed.n, ExitStatus: exitStatus.n,
		Client: "openpsirt-analysis " + version.Get().Version,
	}
	if built != "" {
		t, err := time.Parse(time.RFC3339, built)
		if err != nil {
			return fmt.Errorf("--built %q is not an RFC 3339 time", built)
		}
		opts.Built = t
	}
	work, err := os.Getwd()
	if err != nil {
		return err
	}
	opts.Work = work
	if root == "" {
		top, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
		if err != nil {
			return errors.New("the current directory is not in a git checkout; name the checkout with --source-root")
		}
		root = strings.TrimSpace(string(top))
	}
	if opts.Root, err = filepath.Abs(root); err != nil {
		return err
	}
	if compileCommands != "" && opts.UnitsExpected == nil {
		n, err := units(compileCommands)
		if err != nil {
			return err
		}
		opts.UnitsExpected = &n
	}
	if saltFile != "" {
		salt, err := os.ReadFile(saltFile) //nolint:gosec // G304: the path the pipeline named
		if err != nil {
			return err
		}
		if salt = []byte(strings.TrimSpace(string(salt))); len(salt) == 0 {
			return fmt.Errorf("%s holds no salt", saltFile)
		}
		opts.Salt = salt
	}
	if rulesFile != "" {
		listed, err := lines(rulesFile)
		if err != nil {
			return err
		}
		rules = append(rules, listed...)
	}

	inputs := make([]analysisclient.Input, 0, len(files))
	for _, f := range files {
		info, err := os.Stat(f) //nolint:gosec // G703: the path the pipeline named
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s is a directory: an analyzer writing a directory writes HTML reports, which carry source", f)
		}
		data, err := os.ReadFile(f) //nolint:gosec // G304: the path the pipeline named
		if err != nil {
			return err
		}
		inputs = append(inputs, analysisclient.Input{Name: f, Data: data})
	}
	doc, report, err := analysisclient.Build(ctx, opts, inputs)
	if err != nil {
		return err
	}
	summary := fmt.Sprintf("%s: %d results, %d fingerprinted, %d snippets", strings.Join(report.Tools, ", "),
		report.Results, report.Fingerprints, report.Snippets)
	for _, what := range slices.Sorted(maps.Keys(report.Removed)) {
		summary += fmt.Sprintf(", %d %s removed", report.Removed[what], what)
	}
	if _, err := fmt.Fprintln(stderr, summary); err != nil {
		return err
	}

	if command == "write" {
		if out == "" {
			return errors.New("write needs --output")
		}
		return os.WriteFile(out, doc, 0o644) //nolint:gosec // G306,G703: the document is for the pipeline to read, at the path it named
	}
	to.Key = os.Getenv("OPENPSIRT_KEY")
	if to.Key == "" {
		return errors.New("OPENPSIRT_KEY holds no key")
	}
	answer, err := analysisclient.Send(ctx, &http.Client{Timeout: 10 * time.Minute}, to, doc,
		analysisclient.Fields{Rules: rules, ThirdParty: thirdParty})
	if err != nil {
		return err
	}
	if answer.Status >= 300 {
		return fmt.Errorf("the deployment answered %d: %s", answer.Status, strings.TrimSpace(string(answer.Body)))
	}
	_, err = stdout.Write(answer.Body)
	return err
}

// units is how many entries a compilation database holds: each is a unit
// the build compiles.
func units(path string) (int, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path the pipeline named
	if err != nil {
		return 0, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return 0, fmt.Errorf("%s is not a compilation database: %w", path, err)
	}
	return len(entries), nil
}

// lines is a file's lines, each trimmed, with blank ones and those opening
// with # left out.
func lines(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path the pipeline named
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
