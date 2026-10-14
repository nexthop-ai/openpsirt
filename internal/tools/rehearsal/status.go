// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// statusLine is a build in the release's own status report, with the state
// of its last scan and what is open.
var statusLine = regexp.MustCompile(`^\s+(\S+)/streams/(\S+)/variants/(\S+)\s+scan (.*?) · open (\d+) findings`)

// buildLine is any line of the status report that names a build and its scan,
// whether or not what follows is a count.
var buildLine = regexp.MustCompile(`^\s+(\S+)/streams/(\S+)/variants/(\S+)\s+scan `)

// parseStatus reads one status report: the open findings per build, whether
// any scan is still on its way, the builds whose scan failed, and the lines
// naming a build whose count could not be read. A build whose line does not
// read is not settled, because a total it is missing from is a build the
// upgrade never compares.
func parseStatus(out string) (totals Totals, busy bool, failed, unread []string) {
	totals = Totals{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		m := statusLine.FindStringSubmatch(line)
		if m == nil {
			if buildLine.MatchString(line) {
				unread = append(unread, strings.TrimSpace(line))
				busy = true
			}
			continue
		}
		build := m[1] + "/" + m[2] + "/" + m[3]
		// A scan reads its inventory, then scans it. Only the last two
		// states are an end; anything else, including a build nothing has
		// reached yet, is still on its way.
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
	return totals, busy, failed, unread
}

// shiftCast moves each entry of a release's cast, written "8081:name:…", from
// the demo's ports onto the rehearsal's, which start at port.
func shiftCast(text string, port int) ([]string, error) {
	var cast []string
	for _, entry := range strings.Fields(text) {
		p, rest, ok := strings.Cut(entry, ":")
		n, err := strconv.Atoi(p)
		if !ok || err != nil {
			return nil, fmt.Errorf("cast entry %q has no port", entry)
		}
		cast = append(cast, fmt.Sprintf("%d:%s", n-8080+port, rest))
	}
	return cast, nil
}

// firstBuild is the build that sorts first, as its product, stream and
// variant, so every run of the sweep asks the same one.
func firstBuild(builds Totals) (product, stream, variant string, ok bool) {
	for _, build := range slices.Sorted(maps.Keys(builds)) {
		parts := strings.SplitN(build, "/", 3)
		if len(parts) == 3 {
			return parts[0], parts[1], parts[2], true
		}
	}
	return "", "", "", false
}

var pathParameter = regexp.MustCompile(`\{(\w+)\}`)

// fillPath puts a name in for each of a path's parameters, and reports false
// when a parameter has no name to put in.
func fillPath(path string, names map[string]string) (string, bool) {
	complete := true
	filled := pathParameter.ReplaceAllStringFunc(path, func(p string) string {
		v, ok := names[strings.Trim(p, "{}")]
		if !ok {
			complete = false
		}
		return url.PathEscape(v)
	})
	return filled, complete
}

// started is the environment a container was started with beyond its image's
// own, without the database URL, which the rehearsal supplies. What the
// release's demo configured its server with is what this tree's server is
// served with, so the comparison runs on the configuration a deployment of
// the release had.
func started(container, image []string) []string {
	own := map[string]bool{}
	for _, entry := range image {
		own[entry] = true
	}
	var out []string
	for _, entry := range container {
		name, _, _ := strings.Cut(entry, "=")
		if own[entry] || name == "" || name == "OPENPSIRT_DATABASE_URL" {
			continue
		}
		out = append(out, entry)
	}
	slices.Sort(out)
	return out
}

// pause waits for d, or until ctx is done, and answers why it stopped early.
func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
