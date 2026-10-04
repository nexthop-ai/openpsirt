// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command advisories fails a change for a known vulnerability it introduces,
// and reports one already present on the branch it targets without failing.
//
// It reads a scanner's machine output: govulncheck's JSON stream for Go
// modules, npm's audit report for what the interface installs. An advisory is
// introduced when the version it sits in is one the base does not hold: a
// module whose required version moved, a toolchain that moved, a package
// whose locked version at that place in the tree moved, or anything the base
// does not have at all. An advisory against an unchanged version is one the
// change did not make, and the repository's dependency alerts are what carry
// it to a fix.
//
// The base is where this branch left the reference named by AUDIT_BASE,
// origin/main unless set. On main itself that is the commit being checked, so
// nothing there is introduced and everything is reported.
//
// Usage:
//
//	advisories go  -- <govulncheck -format json ...>
//	advisories npm -- <npm audit --json ...>
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

// An advisory is one scanner finding about one version of one thing.
type advisory struct {
	ID       string // GO-… or GHSA-…
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

// versions is what a tree holds: a version for each module path or lockfile
// place.
type versions map[string]string

// split divides advisories into those the change introduced and those the
// base already held, each sorted for a stable report.
func split(found []advisory, now, base versions) (introduced, present []advisory) {
	for _, a := range found {
		was, held := base[a.Where]
		is := now[a.Where]
		if held && was != "" && was == is {
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
// declares as the standard library's.
func goVersions(data []byte) (versions, error) {
	file, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, err
	}
	held := versions{}
	for _, req := range file.Require {
		held[req.Mod.Path] = req.Mod.Version
	}
	switch {
	case file.Toolchain != nil:
		held[stdlib] = strings.TrimPrefix(file.Toolchain.Name, "go")
	case file.Go != nil:
		held[stdlib] = file.Go.Version
	}
	return held, nil
}

// goFindings reads govulncheck's JSON stream and returns each vulnerability
// a called function reaches, once per module. A finding without a function in
// its trace is one in a module or package that nothing calls into, which
// govulncheck itself does not fail on.
func goFindings(r io.Reader) ([]advisory, error) {
	type frame struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Function string `json:"function"`
	}
	type message struct {
		Config *struct {
			ScannerName string `json:"scanner_name"`
		} `json:"config"`
		OSV *struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"osv"`
		Finding *struct {
			OSV   string  `json:"osv"`
			Trace []frame `json:"trace"`
		} `json:"finding"`
	}
	ran := false
	titles := map[string]string{}
	seen := map[string]bool{}
	var found []advisory
	decoder := json.NewDecoder(r)
	for {
		var m message
		err := decoder.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading govulncheck's output: %w", err)
		}
		switch {
		case m.Config != nil:
			ran = true
		case m.OSV != nil:
			titles[m.OSV.ID] = m.OSV.Summary
		case m.Finding != nil && len(m.Finding.Trace) > 0 && m.Finding.Trace[0].Function != "":
			top := m.Finding.Trace[0]
			key := m.Finding.OSV + " " + top.Module
			if seen[key] {
				continue
			}
			seen[key] = true
			found = append(found, advisory{
				ID: m.Finding.OSV, Where: top.Module, Version: top.Version,
			})
		}
	}
	if !ran {
		return nil, errors.New("govulncheck said nothing about its configuration, so it did not scan anything")
	}
	for i := range found {
		found[i].Title = titles[found[i].ID]
	}
	return found, nil
}

// npmVersions reads the version locked at each place in a package-lock.json.
func npmVersions(data []byte) (versions, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("reading the lockfile: %w", err)
	}
	held := versions{}
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
func npmFindings(data []byte, locked versions) ([]advisory, error) {
	var report struct {
		AuditReportVersion int `json:"auditReportVersion"`
		Vulnerabilities    map[string]struct {
			Via   []json.RawMessage `json:"via"`
			Nodes []string          `json:"nodes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("reading npm's audit report: %w", err)
	}
	if report.AuditReportVersion == 0 {
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
					ID: id, Where: place, Version: locked[place],
					Severity: via.Severity, Title: via.Title,
				})
			}
		}
	}
	return found, nil
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

// scan runs the scanner and returns what it printed. Both scanners exit
// non-zero for reasons that are not failures here — npm whenever it finds
// anything — so what decides is whether the output reads.
func scan(command []string) ([]byte, error) {
	//nolint:gosec // G204: the scanner command the makefile passes
	cmd := exec.Command(command[0], command[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if len(out) == 0 && err != nil {
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

func run(args []string) error {
	if len(args) < 3 || args[1] != "--" {
		return errors.New("usage: advisories go|npm -- <scanner command>")
	}
	kind, command := args[0], args[2:]
	commit, ref, err := base()
	if err != nil {
		return err
	}
	out, err := scan(command)
	if err != nil {
		return err
	}

	var found []advisory
	var now, then versions
	switch kind {
	case "go":
		if found, err = goFindings(bytes.NewReader(out)); err != nil {
			return err
		}
		mod, err := os.ReadFile("go.mod")
		if err != nil {
			return err
		}
		if now, err = goVersions(mod); err != nil {
			return err
		}
		was, err := at(commit, "go.mod")
		if err != nil {
			return err
		}
		if then, err = goVersions(was); err != nil {
			return err
		}
	case "npm":
		lock, err := os.ReadFile("web/package-lock.json")
		if err != nil {
			return err
		}
		if now, err = npmVersions(lock); err != nil {
			return err
		}
		if found, err = npmFindings(out, now); err != nil {
			return err
		}
		was, err := at(commit, "web/package-lock.json")
		if err != nil {
			return err
		}
		then = versions{}
		if len(was) > 0 {
			if then, err = npmVersions(was); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("no scanner called %q; go or npm", kind)
	}
	if len(now) == 0 {
		return fmt.Errorf("the %s tree holds nothing, so this checked nothing", kind)
	}

	introduced, present := split(found, now, then)
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
