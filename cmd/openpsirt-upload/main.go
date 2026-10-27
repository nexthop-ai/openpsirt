// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command openpsirt-upload sends an analyzer's run from a build pipeline
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

	"github.com/nexthop-ai/openpsirt/internal/uploadclient"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

const usage = `openpsirt-upload sends an analyzer's run to OpenPSIRT.

  openpsirt-upload upload --product P --branch-or-tag B --variant V --series NAME [flags] OUTPUT...
  openpsirt-upload write  --series NAME [flags] --output FILE OUTPUT...
  openpsirt-upload version

Each OUTPUT is clang plist-multi-file, cppcheck XML version 2, or any tool's
SARIF 2.1.0, compressed with gzip or not. The address is --url, or
OPENPSIRT_URL where the flag is not given. The key is read from OPENPSIRT_KEY
alone, so it is never on a command line a process listing shows.

Output of several analyzers is sent as one upload per analyzer, each with its
own series, named --series TOOL=NAME once per analyzer. write puts each in a
file of its own, the analyzer's name before the extension.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "openpsirt-upload:", err)
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
		_, err := fmt.Fprintln(stdout, "openpsirt-upload", version.Get().Version)
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
		to                               uploadclient.Target
		commit, built, root, out         string
		toolVersion, saltFile, rulesFile string
		compileCommands                  string
		snippets                         bool
		rules, thirdParty, series        many
		expected, analyzed, exitStatus   count
	)
	fs.StringVar(&to.URL, "url", os.Getenv("OPENPSIRT_URL"), "the deployment's address")
	fs.StringVar(&to.Product, "product", "", "the declared product the build is of")
	fs.StringVar(&to.BranchOrTag, "branch-or-tag", "", "the declared branch or tag")
	fs.StringVar(&to.Variant, "variant", "", "the declared way the branch or tag is built")
	fs.Var(&series, "series", "which analysis this is, the same for every build: the tool and its configuration; "+
		"TOOL=NAME names one analyzer's where the output is of several")
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

	opts := uploadclient.Options{
		Commit: commit, ToolVersion: toolVersion, Snippets: snippets,
		UnitsExpected: expected.n, UnitsAnalyzed: analyzed.n, ExitStatus: exitStatus.n,
		Client: "openpsirt-upload " + version.Get().Version,
	}
	for _, named := range series {
		tool, name, each := strings.Cut(named, "=")
		switch {
		case !each && opts.Series != "":
			return errors.New("--series is named twice; name each analyzer's as --series TOOL=NAME")
		case !each:
			opts.Series = named
		default:
			if opts.SeriesOf == nil {
				opts.SeriesOf = map[string]string{}
			}
			key := strings.ToLower(strings.TrimSpace(tool))
			if _, dup := opts.SeriesOf[key]; dup {
				return fmt.Errorf("--series names %s twice", key)
			}
			opts.SeriesOf[key] = name
		}
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

	inputs := make([]uploadclient.Input, 0, len(files))
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
		inputs = append(inputs, uploadclient.Input{Name: f, Data: data})
	}
	runs, report, err := uploadclient.Build(ctx, opts, inputs)
	if err != nil {
		return err
	}
	if len(runs) > 1 && len(rules) > 0 {
		return errors.New("the output is of several analyzers, and --rule and --rules-file name one analyzer's rules")
	}
	summary := fmt.Sprintf("%s: %d results, %d fingerprinted, %d snippets", strings.Join(report.Tools, ", "),
		report.Results, report.Fingerprints, report.Snippets)
	for _, what := range slices.Sorted(maps.Keys(report.Removed)) {
		summary += fmt.Sprintf(", %d %s removed", report.Removed[what], what)
	}
	if _, err := fmt.Fprintln(stderr, summary); err != nil {
		return err
	}
	for _, tool := range report.Uncounted {
		if _, err := fmt.Fprintf(stderr, "%s states no count of the units it analyzed, so the units expected are not sent; "+
			"--units-analyzed gives that count for one analyzer's output\n", tool); err != nil {
			return err
		}
	}

	if command == "write" {
		if out == "" {
			return errors.New("write needs --output")
		}
		for _, r := range runs {
			if err := os.WriteFile(written(out, r.Tool, len(runs)), r.Doc, 0o644); err != nil { //nolint:gosec // G306,G703: the document is for the pipeline to read, at the path it named
				return err
			}
		}
		return nil
	}
	to.Key = os.Getenv("OPENPSIRT_KEY")
	if to.Key == "" {
		return errors.New("OPENPSIRT_KEY holds no key")
	}
	// Each analyzer's run is its own upload, and one refused does not keep
	// the others from being sent.
	var failed []string
	client := uploader()
	for _, r := range runs {
		answer, err := uploadclient.Send(ctx, client, to, r.Doc,
			uploadclient.Fields{Rules: rules, ThirdParty: thirdParty})
		switch {
		case err != nil:
			failed = append(failed, fmt.Sprintf("%s: %v", r.Series, err))
		case answer.Status >= 300 && answer.Status < 400:
			failed = append(failed, fmt.Sprintf("%s: the deployment answered %d, a redirect to %q, which is not followed: name that address with --url",
				r.Series, answer.Status, answer.Location))
		case answer.Status >= 300:
			failed = append(failed, fmt.Sprintf("%s: the deployment answered %d: %s", r.Series, answer.Status,
				strings.TrimSpace(string(answer.Body))))
		default:
			if _, err := stdout.Write(answer.Body); err != nil {
				return err
			}
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// uploader is the HTTP client the runs are sent with. It follows no
// redirect: the key is a bearer token, and a redirect would carry it wherever
// the answer points, over plain HTTP included.
func uploader() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// written is where write puts one analyzer's document: the path named, or,
// where the output is of several, that path with the analyzer's name before
// its extension.
func written(out, tool string, runs int) string {
	if runs == 1 {
		return out
	}
	ext := filepath.Ext(out)
	return strings.TrimSuffix(out, ext) + "." + tool + ext
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
