// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command advisories fails a change for a known vulnerability it introduces,
// and reports one already present on the branch it targets without failing.
//
// It reads a scanner's machine output: govulncheck's JSON stream for Go
// modules, npm's audit report for what the interface installs. An advisory is
// present when the base was already affected by it: the version the base's
// go.mod requires falls in the advisory's affected ranges, or npm's audit of
// the base's lockfile reports the same advisory against the same package.
// Everything else is introduced — including an advisory the base was not
// affected by at all, and one against a dependency the base does not have. A
// bump that fixes one advisory and not another therefore introduces nothing,
// and an advisory already present reaches a fix through the repository's
// dependency alerts.
//
// The base is where this branch left the reference named by AUDIT_BASE,
// origin/main unless set. On main itself that is the commit being checked, so
// nothing there is introduced and everything is reported.
//
// Usage:
//
//	advisories go  -- <govulncheck -format json ...>
//	advisories npm -- <npm audit --json>    run in web/, and in the base's copy
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// An advisory is one scanner finding about one version of one thing.
type advisory struct {
	ID       string // GO-… or GHSA-…
	Name     string // the module path, or the npm package's name
	Where    string // the module path, or the package's place in the lockfile
	Version  string
	Severity string // npm's word; empty for Go, which govulncheck does not rate
	Title    string
}

// gating reports whether an advisory of this severity fails a change. Every
// Go finding govulncheck calls reachable fails, as it does when run on its
// own; npm's are held to high and above, as npm audit's own level is.
func gating(a advisory) bool {
	switch a.Severity {
	case "", "high", "critical":
		return true
	}
	return false
}

// split divides advisories into those the change introduced and those the
// base was already affected by, each sorted for a stable report.
func split(found []advisory, affectedBefore func(advisory) bool) (introduced, present []advisory) {
	for _, a := range found {
		if affectedBefore(a) {
			present = append(present, a)
		} else {
			introduced = append(introduced, a)
		}
	}
	order := func(list []advisory) {
		sort.Slice(list, func(i, j int) bool {
			if list[i].ID != list[j].ID {
				return list[i].ID < list[j].ID
			}
			return list[i].Where < list[j].Where
		})
	}
	order(introduced)
	order(present)
	return introduced, present
}

// stdlib is the name govulncheck gives the standard library, whose version is
// the toolchain the module declares.
const stdlib = "stdlib"

// goVersions reads the versions a go.mod requires, and the toolchain it
// declares as the standard library's. Versions are written as semver reads
// them, with the leading v.
func goVersions(data []byte) (map[string]string, error) {
	file, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, err
	}
	held := map[string]string{}
	for _, req := range file.Require {
		held[req.Mod.Path] = req.Mod.Version
	}
	switch {
	case file.Toolchain != nil:
		held[stdlib] = "v" + strings.TrimPrefix(file.Toolchain.Name, "go")
	case file.Go != nil:
		held[stdlib] = "v" + file.Go.Version
	}
	return held, nil
}

// A span is one stretch of versions an advisory affects: from introduced, up
// to and not including fixed. An empty fixed is open-ended.
type span struct{ introduced, fixed string }

// affects reports whether a version falls in any span. Versions carry the
// leading v.
func affects(spans []span, version string) bool {
	if !semver.IsValid(version) {
		return false
	}
	for _, s := range spans {
		if s.introduced != "v0" && semver.Compare(version, s.introduced) < 0 {
			continue
		}
		if s.fixed != "" && semver.Compare(version, s.fixed) >= 0 {
			continue
		}
		return true
	}
	return false
}

// goScan is what govulncheck reported: each vulnerability a called function
// reaches, once per module, and the versions each advisory affects in each
// module.
type goScan struct {
	found    []advisory
	affected map[string]map[string][]span // advisory, module, spans
}

// goFindings reads govulncheck's JSON stream. A finding without a function in
// its trace is one in a module or package that nothing calls into, which
// govulncheck itself does not fail on.
func goFindings(r io.Reader) (goScan, error) {
	type frame struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Function string `json:"function"`
	}
	type event struct {
		Introduced string `json:"introduced"`
		Fixed      string `json:"fixed"`
	}
	type message struct {
		Config *struct {
			ScannerName string `json:"scanner_name"`
		} `json:"config"`
		OSV *struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Affected []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Ranges []struct {
					Type   string  `json:"type"`
					Events []event `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"osv"`
		Finding *struct {
			OSV   string  `json:"osv"`
			Trace []frame `json:"trace"`
		} `json:"finding"`
	}
	scan := goScan{affected: map[string]map[string][]span{}}
	ran := false
	titles := map[string]string{}
	seen := map[string]bool{}
	decoder := json.NewDecoder(r)
	for {
		var m message
		err := decoder.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return goScan{}, fmt.Errorf("reading govulncheck's output: %w", err)
		}
		switch {
		case m.Config != nil:
			ran = true
		case m.OSV != nil:
			titles[m.OSV.ID] = m.OSV.Summary
			modules := map[string][]span{}
			for _, aff := range m.OSV.Affected {
				for _, rng := range aff.Ranges {
					if rng.Type != "SEMVER" {
						continue
					}
					// Events alternate: an introduced opens a span, a fixed
					// closes the one open.
					var open *span
					for _, ev := range rng.Events {
						switch {
						case ev.Introduced != "":
							open = &span{introduced: "v" + ev.Introduced}
						case ev.Fixed != "" && open != nil:
							open.fixed = "v" + ev.Fixed
							modules[aff.Package.Name] = append(modules[aff.Package.Name], *open)
							open = nil
						}
					}
					if open != nil {
						modules[aff.Package.Name] = append(modules[aff.Package.Name], *open)
					}
				}
			}
			scan.affected[m.OSV.ID] = modules
		case m.Finding != nil && len(m.Finding.Trace) > 0 && m.Finding.Trace[0].Function != "":
			top := m.Finding.Trace[0]
			key := m.Finding.OSV + " " + top.Module
			if seen[key] {
				continue
			}
			seen[key] = true
			scan.found = append(scan.found, advisory{
				ID: m.Finding.OSV, Name: top.Module, Where: top.Module, Version: top.Version,
			})
		}
	}
	if !ran {
		return goScan{}, errors.New("govulncheck said nothing about its configuration, so it did not scan anything")
	}
	for i := range scan.found {
		scan.found[i].Title = titles[scan.found[i].ID]
	}
	return scan, nil
}

// goAffectedBefore reports whether the base's go.mod held a version of the
// advisory's module that the advisory affects.
func goAffectedBefore(scan goScan, base map[string]string) func(advisory) bool {
	return func(a advisory) bool {
		was, held := base[a.Name]
		return held && affects(scan.affected[a.ID][a.Name], was)
	}
}

// npmVersions reads the version locked at each place in a package-lock.json.
func npmVersions(data []byte) (map[string]string, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("reading the lockfile: %w", err)
	}
	held := map[string]string{}
	for place, pkg := range lock.Packages {
		if place != "" {
			held[place] = pkg.Version
		}
	}
	return held, nil
}

// npmFindings reads npm's audit report and returns each advisory at each
// place it is installed. A package listed only because something beneath it
// is vulnerable carries no advisory of its own, so it is not one.
func npmFindings(data []byte, locked map[string]string) ([]advisory, error) {
	var report struct {
		// What npm says instead of a report when it could not make one, such
		// as when the registry is out of reach.
		Message            string `json:"message"`
		AuditReportVersion int    `json:"auditReportVersion"`
		Vulnerabilities    map[string]struct {
			Via   []json.RawMessage `json:"via"`
			Nodes []string          `json:"nodes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("reading npm's audit report: %w", err)
	}
	if report.AuditReportVersion == 0 {
		if report.Message != "" {
			return nil, fmt.Errorf("npm made no audit report: %s", report.Message)
		}
		return nil, errors.New("npm's audit report has no version, so it is not a report this reads")
	}
	var found []advisory
	for name, vuln := range report.Vulnerabilities {
		for _, raw := range vuln.Via {
			var via struct {
				Name     string `json:"name"`
				Title    string `json:"title"`
				URL      string `json:"url"`
				Severity string `json:"severity"`
			}
			// A string names the package beneath that carries the advisory.
			if json.Unmarshal(raw, &via) != nil || via.Name != name {
				continue
			}
			id := via.URL[strings.LastIndex(via.URL, "/")+1:]
			for _, place := range vuln.Nodes {
				found = append(found, advisory{
					ID: id, Name: name, Where: place, Version: locked[place],
					Severity: via.Severity, Title: via.Title,
				})
			}
		}
	}
	return found, nil
}

// npmAffectedBefore reports whether the base's audit named the same advisory
// against the same package, at whatever place and version. A package npm
// moves to another place in the tree, or bumps to a version the advisory
// still affects, was affected before.
func npmAffectedBefore(base []advisory) func(advisory) bool {
	held := map[string]bool{}
	for _, a := range base {
		held[a.ID+" "+a.Name] = true
	}
	return func(a advisory) bool { return held[a.ID+" "+a.Name] }
}

// at reads one file as the base commit holds it. A file the base does not
// have reads as empty, so everything in it is introduced.
func at(commit, file string) ([]byte, error) {
	//nolint:gosec // G204: a commit git merge-base named, and a path this tool fixes
	out, err := exec.Command("git", "show", commit+":"+file).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && bytes.Contains(exit.Stderr, []byte("does not exist")) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s at %s: %w", file, commit, err)
	}
	return out, nil
}

// base finds the commit this branch left the reference at.
func base() (string, string, error) {
	ref := os.Getenv("AUDIT_BASE")
	if ref == "" {
		ref = "origin/main"
	}
	//nolint:gosec // G204: a reference the person running the gate names
	out, err := exec.Command("git", "merge-base", "HEAD", ref).Output()
	if err != nil {
		return "", ref, fmt.Errorf("no common commit with %s, so nothing says what this change introduced; "+
			"fetch it, or name the branch this targets in AUDIT_BASE", ref)
	}
	return strings.TrimSpace(string(out)), ref, nil
}

// scan runs the scanner in a directory and returns what it printed. npm exits
// non-zero whenever it finds anything, so for npm what decides is whether the
// output reads. govulncheck's JSON mode exits zero whatever it finds, so any
// other exit is the scan failing, whatever it printed before it did.
func scan(kind, dir string, command []string) ([]byte, error) {
	//nolint:gosec // G204: the scanner command the makefile passes
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && (kind == "go" || len(out) == 0) {
		return nil, fmt.Errorf("%s: %w\n%s", strings.Join(command, " "), err, stderr.String())
	}
	return out, nil
}

func describe(a advisory) string {
	line := fmt.Sprintf("  %s  %s %s", a.ID, a.Where, a.Version)
	if a.Severity != "" {
		line += " (" + a.Severity + ")"
	}
	if a.Title != "" {
		line += "  " + a.Title
	}
	return line
}

// report writes both lists and says whether the change passes.
func report(kind, ref string, introduced, present []advisory) (string, bool) {
	var out strings.Builder
	line := func(format string, args ...any) { out.WriteString(fmt.Sprintf(format, args...) + "\n") }
	failing := 0
	if len(introduced) > 0 {
		line("%s advisories this change introduces:", kind)
		for _, a := range introduced {
			line("%s", describe(a))
			if gating(a) {
				failing++
			}
		}
	}
	if len(present) > 0 {
		line("%s advisories already on %s, reported and not failed:", kind, ref)
		for _, a := range present {
			line("%s", describe(a))
		}
	}
	if len(introduced) == 0 && len(present) == 0 {
		line("no known %s advisories", kind)
	}
	if failing > 0 {
		line("%d %s advisories introduced here fail this change", failing, kind)
	}
	return out.String(), failing == 0
}

// errFailed is a change failing, which the report has already explained.
var errFailed = errors.New("introduced advisories")

// checkGo scans the working tree and asks the base's go.mod about each
// finding.
func checkGo(command []string, commit string) ([]advisory, func(advisory) bool, error) {
	out, err := scan("go", ".", command)
	if err != nil {
		return nil, nil, err
	}
	found, err := goFindings(bytes.NewReader(out))
	if err != nil {
		return nil, nil, err
	}
	was, err := at(commit, "go.mod")
	if err != nil {
		return nil, nil, err
	}
	held := map[string]string{}
	if len(was) > 0 {
		if held, err = goVersions(was); err != nil {
			return nil, nil, err
		}
	}
	return found.found, goAffectedBefore(found, held), nil
}

// checkNpm audits the working tree's lockfile and, where that finds anything,
// the base's.
func checkNpm(command []string, commit string) ([]advisory, func(advisory) bool, error) {
	lock, err := os.ReadFile("web/package-lock.json")
	if err != nil {
		return nil, nil, err
	}
	locked, err := npmVersions(lock)
	if err != nil {
		return nil, nil, err
	}
	if len(locked) == 0 {
		return nil, nil, errors.New("the lockfile holds no packages, so this checked nothing")
	}
	out, err := scan("npm", "web", command)
	if err != nil {
		return nil, nil, err
	}
	found, err := npmFindings(out, locked)
	if err != nil || len(found) == 0 {
		return found, nil, err
	}

	// The base's manifest and lockfile, audited as they stand. npm reads a
	// lockfile without installing it.
	manifest, err := at(commit, "web/package.json")
	if err != nil {
		return nil, nil, err
	}
	wasLock, err := at(commit, "web/package-lock.json")
	if err != nil {
		return nil, nil, err
	}
	if len(manifest) == 0 || len(wasLock) == 0 {
		return found, func(advisory) bool { return false }, nil
	}
	dir, err := os.MkdirTemp("", "advisories-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), manifest, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), wasLock, 0o600); err != nil {
		return nil, nil, err
	}
	wasLocked, err := npmVersions(wasLock)
	if err != nil {
		return nil, nil, err
	}
	wasOut, err := scan("npm", dir, append(command, "--package-lock-only"))
	if err != nil {
		return nil, nil, err
	}
	before, err := npmFindings(wasOut, wasLocked)
	if err != nil {
		return nil, nil, fmt.Errorf("auditing the base: %w", err)
	}
	return found, npmAffectedBefore(before), nil
}

func run(args []string) error {
	if len(args) < 3 || args[1] != "--" {
		return errors.New("usage: advisories go|npm -- <scanner command>")
	}
	kind, command := args[0], args[2:]
	commit, ref, err := base()
	if err != nil {
		return err
	}
	var found []advisory
	var affectedBefore func(advisory) bool
	switch kind {
	case "go":
		found, affectedBefore, err = checkGo(command, commit)
	case "npm":
		found, affectedBefore, err = checkNpm(command, commit)
	default:
		err = fmt.Errorf("no scanner called %q; go or npm", kind)
	}
	if err != nil {
		return err
	}
	introduced, present := split(found, affectedBefore)
	text, passed := report(kind, ref, introduced, present)
	fmt.Print(text)
	if !passed {
		return errFailed
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if !errors.Is(err, errFailed) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
