// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package analysisclient builds the SARIF a pipeline sends with an analyzer's
// run, from the analyzer's own output and the checkout it analyzed.
//
// It reads a tool's native output where that carries more than the tool's
// SARIF, and forwards any tool's SARIF. Either way it writes one run per tool,
// with what the deployment cannot learn from the output alone: the run's
// parameters, the repositories the checkout holds and their commits, paths
// placed in the checkout the same way on every operating system, and a
// content fingerprint for each result. Source text leaves the pipeline only
// when the pipeline asks for snippets.
package analysisclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// format is one kind of analyzer output this client reads.
type format interface {
	name() string
	// detects is whether data looks like this format.
	detects(data []byte) bool
	// read turns one output into runs, one per tool it holds.
	read(data []byte) ([]obj, error)
}

// formats is every format read, in the order they are tried.
var formats = []format{clangPlist{}, cppcheckXML{}, sarifDoc{}}

// Input is one output file of an analyzer.
type Input struct {
	Name string
	Data []byte
}

// Options is what a run is built from beside the analyzer's output.
type Options struct {
	// Root is the top of the checkout analyzed, and Work the directory the
	// tool's relative paths are relative to: absolute paths on this host.
	Root, Work string
	// Series is the analysis an output of one tool is. SeriesOf is each
	// tool's, by the name its output gives it in lower case, and is what an
	// output of several tools needs: a series named once for all of them
	// would change name whenever a tool was added or dropped.
	Series   string
	SeriesOf map[string]string
	// Commit is the checkout's commit; empty is the commit checked out.
	Commit string
	// Built is when the build was made; zero leaves the deployment to date
	// the run as it arrives.
	Built time.Time
	// ToolVersion fills the version where the output states none.
	ToolVersion string
	// UnitsExpected and UnitsAnalyzed are the translation units the run was
	// meant to analyze and did. A native format counts the units it read
	// where UnitsAnalyzed is unset.
	UnitsExpected, UnitsAnalyzed *int
	// ExitStatus is the analyzer's exit status, where the pipeline states it.
	ExitStatus *int
	// Snippets is whether the source text of each location is sent.
	Snippets bool
	// Salt keys the content fingerprint, where the product salts it.
	Salt []byte
	// Client is this client's own version.
	Client string
}

// Report is what building a run did, for the pipeline's log.
type Report struct {
	Tools        []string
	Results      int
	Fingerprints int
	Snippets     int
	// Uncounted is each tool whose run states no count of the units it
	// analyzed, so the units it was meant to analyze were not sent: the
	// deployment reads the two counts together.
	Uncounted []string
	// Removed counts what was taken out of forwarded output, by what it
	// was: whole files, fixes, attachments, snippets and markdown.
	Removed map[string]int
}

// Run is one tool's run, as a SARIF document of its own and the series it
// is sent as.
type Run struct {
	Tool   string
	Series string
	Doc    []byte
}

// Build writes a SARIF document per tool from the analyzer's outputs. Each is
// one upload: a series is one tool.
func Build(ctx context.Context, opts Options, inputs []Input) ([]Run, Report, error) {
	return build(ctx, runGit, opts, inputs)
}

func build(ctx context.Context, run git, opts Options, inputs []Input) ([]Run, Report, error) {
	report := Report{Removed: map[string]int{}}
	if opts.Series == "" && len(opts.SeriesOf) == 0 {
		return nil, report, errors.New("a run needs a series: the analysis it is, the same for every build")
	}
	root, work := filepath.ToSlash(opts.Root), filepath.ToSlash(opts.Work)
	paths, err := indexed(ctx, run, opts.Root)
	if err != nil {
		return nil, report, fmt.Errorf("read the checkout's index: %w", err)
	}
	repos, err := repositories(ctx, run, opts.Root, opts.Commit)
	if err != nil {
		return nil, report, fmt.Errorf("read the checkout's repositories: %w", err)
	}
	at := newPlacer(root, work, paths)

	byTool := map[string][]obj{}
	var order []string
	for _, in := range inputs {
		runs, err := readInput(in)
		if err != nil {
			return nil, report, fmt.Errorf("%s: %w", in.Name, err)
		}
		for _, r := range runs {
			s := settle(r, at)
			report.Removed["contents"] += s.contents
			report.Removed["fixes"] += s.fixes
			report.Removed["snippets"] += s.snippets
			report.Removed["markdown"] += s.markdown
			report.Removed["attachments"] += s.attachments
			tool := strings.ToLower(strings.TrimSpace(str(child(child(r, "tool"), "driver"), "name")))
			if _, ok := byTool[tool]; !ok {
				order = append(order, tool)
			}
			byTool[tool] = append(byTool[tool], r)
		}
	}
	if len(order) == 0 {
		return nil, report, errors.New("no analyzer output was given")
	}
	series := map[string]string{}
	for _, tool := range order {
		named := opts.SeriesOf[tool]
		if named == "" && len(order) == 1 {
			named = opts.Series
		}
		if named == "" {
			return nil, report, fmt.Errorf("the output is of %s; name each one's series, as %s",
				strings.Join(order, " and "), seriesFlags(order))
		}
		series[tool] = named
	}
	// Each describes one analyzer's process, so one value stamped on every
	// tool's run would be wrong for all but one.
	if len(order) > 1 && (opts.ToolVersion != "" || opts.ExitStatus != nil || opts.UnitsAnalyzed != nil) {
		return nil, report, fmt.Errorf("the output is of %s, and a tool version, an exit status and the units analyzed are each one analyzer's",
			strings.Join(order, " and "))
	}
	for k, n := range report.Removed {
		if n == 0 {
			delete(report.Removed, k)
		}
	}
	src := &source{root: opts.Root, files: map[string][]string{}, salt: opts.Salt}
	var out []Run
	for _, tool := range order {
		merged := merge(byTool[tool])
		describe(merged, opts, series[tool], repos, src, &report)
		report.Tools = append(report.Tools, str(child(child(merged, "tool"), "driver"), "name"))
		doc := obj{
			"version": sarifVersion,
			"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
			"runs":    list{merged},
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(doc); err != nil {
			return nil, report, err
		}
		out = append(out, Run{Tool: tool, Series: series[tool], Doc: buf.Bytes()})
	}
	return out, report, nil
}

// seriesFlags is the flags naming a series for each of these tools.
func seriesFlags(tools []string) string {
	flags := make([]string, len(tools))
	for i, tool := range tools {
		flags[i] = "--series " + tool + "=NAME"
	}
	return strings.Join(flags, " ")
}

// readInput reads one output, decompressed where it arrived compressed.
func readInput(in Input) ([]obj, error) {
	lower := strings.ToLower(in.Name)
	if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") {
		return nil, errors.New("an HTML report carries source; write plist-multi-file, XML or SARIF instead")
	}
	data := in.Data
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		z, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		if data, err = io.ReadAll(z); err != nil {
			return nil, err
		}
	}
	for _, f := range formats {
		if f.detects(data) {
			runs, err := f.read(data)
			if err != nil {
				return nil, fmt.Errorf("as %s: %w", f.name(), err)
			}
			return runs, nil
		}
	}
	return nil, errors.New("not clang plist, cppcheck XML or SARIF")
}

// The run properties the deployment reads, under its prefix.
const (
	propUnitsExpected = "openpsirt/unitsExpected"
	propUnitsAnalyzed = "openpsirt/unitsAnalyzed"
	propClient        = "openpsirt/client"
	propChanged       = "openpsirt/changed"
	propSeries        = "openpsirt/series"
	propCommit        = "openpsirt/commit"
	propSalt          = "openpsirt/salt"
)

// describe writes what the run says about itself, the repositories its
// checkout holds, and each result's fingerprint and snippets.
func describe(run obj, opts Options, series string, repos []repository, src *source, report *Report) {
	driver := ensure(ensure(run, "tool"), "driver")
	if str(driver, "version") == "" && opts.ToolVersion != "" {
		driver["version"] = opts.ToolVersion
	}
	props := ensure(run, "properties")
	read, counted := num(props, unitsKey)
	delete(props, unitsKey)
	analyzed := opts.UnitsAnalyzed
	if analyzed == nil && counted {
		analyzed = &read
	}
	if opts.UnitsExpected != nil && analyzed != nil {
		props[propUnitsExpected], props[propUnitsAnalyzed] = *opts.UnitsExpected, *analyzed
	} else if opts.UnitsExpected != nil {
		report.Uncounted = append(report.Uncounted, str(driver, "name"))
	}
	if opts.Client != "" {
		props[propClient] = opts.Client
	}
	if opts.Salt != nil {
		props[propSalt] = saltID(opts.Salt)
	}
	top := repos[0]
	props[propCommit] = top.Commit
	if opts.Built.IsZero() {
		props[propSeries] = series
	} else {
		run["automationDetails"] = obj{"id": series + "/" + opts.Built.UTC().Format(time.RFC3339)}
	}
	if opts.ExitStatus != nil {
		inv := obj{"exitCode": *opts.ExitStatus, "executionSuccessful": *opts.ExitStatus == 0}
		run["invocations"] = append(items(run, "invocations"), inv)
	}

	var provenance list
	changed := list{}
	for _, r := range repos {
		if r.Changed {
			changed = append(changed, r.Path)
		}
		if r.Remote == "" {
			continue
		}
		mapped := obj{"uriBaseId": rootBase}
		if r.Path != "" {
			mapped["uri"] = r.Path + "/"
		}
		provenance = append(provenance, obj{"repositoryUri": r.Remote, "revisionId": r.Commit, "mappedTo": mapped})
	}
	if len(provenance) > 0 {
		run["versionControlProvenance"] = provenance
	}
	if len(changed) > 0 {
		props[propChanged] = changed
	}
	if len(props) == 0 {
		delete(run, "properties")
	}

	for _, res := range objects(run, "results") {
		report.Results++
		if opts.Salt != nil {
			// A tool's own fingerprint cannot be salted, and a short line
			// is recovered from it by guessing.
			delete(res, "partialFingerprints")
			delete(res, "fingerprints")
		}
		if locs := objects(res, "locations"); len(locs) > 0 {
			if print := fingerprintOf(locs[0], src); print != "" {
				ensure(res, "partialFingerprints")[schemeContext] = print
				report.Fingerprints++
			}
		}
		if opts.Snippets {
			eachLocation(res, func(loc obj) {
				src.snippets(loc)
				if _, ok := child(child(loc, "physicalLocation"), "region")["snippet"]; ok {
					report.Snippets++
				}
			})
		}
	}
}

// fingerprintOf is the content fingerprint of a result's own location, where
// it is a line of the checkout.
func fingerprintOf(loc obj, src *source) string {
	physical := child(loc, "physicalLocation")
	art := child(physical, "artifactLocation")
	if str(art, "uriBaseId") != rootBase {
		return ""
	}
	rel, ok := relativePath(str(art, "uri"))
	if !ok {
		return ""
	}
	line, ok := num(child(physical, "region"), "startLine")
	if !ok {
		return ""
	}
	return src.contextPrint(rel, line)
}
