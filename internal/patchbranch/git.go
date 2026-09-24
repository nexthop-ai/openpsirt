// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// fetchBudget bounds one clone or fetch.
//
// Generous, because the first copy of a large tree from a host that sends
// whole history is several gigabytes. What stops a transfer that has stalled
// is the rate git is told to hold, below, rather than this.
const fetchBudget = 3 * time.Hour

// lookupBudget bounds one question put to a copy already on disk.
const lookupBudget = 10 * time.Minute

// slowest is the transfer rate below which git gives up, in bytes a second,
// and stalled is how long it may stay there.
const (
	slowest = 1024
	stalled = 2 * time.Minute
)

// git runs the version control program against copies on disk.
type git struct {
	// path is the program. Empty means whatever the environment resolves.
	path     string
	excluded outward.Excluded
	// transport is the protocol a fetch may use. https everywhere but the
	// tests, which fetch from a directory because a test has no host to
	// reach.
	transport string
	// locate turns a repository's address into what git is told to fetch.
	// Nil everywhere but the tests, where it names a directory.
	locate func(repository string) string
}

// source is what git is told to fetch for a repository.
func (g git) source(repository string) string {
	if g.locate != nil {
		return g.locate(repository)
	}
	return repository
}

// environment is everything git is given: nothing inherited but where to find
// programs.
//
// A credential helper, a proxy, a rewritten address or a hook configured for
// whoever runs this process would change where git goes or what it sends, so
// none of that is read. Git is told there is no system or personal
// configuration and no terminal to prompt on.
func (g git) environment(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
		// A copy that holds commits and no trees would otherwise go back to
		// the host for any object it lacks, outside the fetch that was
		// guarded and bounded.
		"GIT_NO_LAZY_FETCH=1",
		"LC_ALL=C",
	}
}

// settings is the configuration every invocation carries.
//
// One thread for packing and indexing, so a copy being built takes one core
// from the deployment rather than all of them. No automatic housekeeping,
// because the commit graph this relies on is written deliberately and nothing
// else is wanted.
//
// Small windows onto the pack files, because git otherwise maps as much of
// them as it likes and the process runs in the same memory limit as the
// server. Measured writing the commit graph for the kernel's stable tree,
// two million commits: 1.7 GB at git's defaults, 0.6 GB with these, 29
// seconds against 35.
func (g git) settings(proxy string) []string {
	out := []string{
		"-c", "protocol.allow=never",
		"-c", "protocol." + g.transport + ".allow=always",
		"-c", "http.followRedirects=false",
		"-c", "http.lowSpeedLimit=" + fmt.Sprint(slowest),
		"-c", "http.lowSpeedTime=" + fmt.Sprint(int(stalled.Seconds())),
		"-c", "credential.helper=",
		"-c", "core.askPass=",
		"-c", "pack.threads=1",
		"-c", "index.threads=1",
		"-c", "core.packedGitLimit=64m",
		"-c", "core.packedGitWindowSize=8m",
		"-c", "core.deltaBaseCacheLimit=16m",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
		"-c", "fetch.writeCommitGraph=false",
		"-c", "core.hooksPath=" + os.DevNull,
	}
	if proxy != "" {
		out = append(out, "-c", "http.proxy="+proxy)
	}
	return out
}

// run runs git with the settings above, writing what it prints to stdout.
func (g git) run(ctx context.Context, budget time.Duration, dir, proxy string, stdin []byte, stdout io.Writer, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	program := g.path
	if program == "" {
		program = "git"
	}
	command := exec.CommandContext(ctx, program, append(g.settings(proxy), args...)...) //nolint:gosec // G204: every argument is built here from a validated address, a hash or a constant
	command.Dir = dir
	command.Env = g.environment(dir)
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	if stdout == nil {
		stdout = io.Discard
	}
	var stderr bytes.Buffer
	command.Stdout = stdout
	command.Stderr = &limited{buffer: &stderr, most: 4096}
	// Where the program is killed at the deadline, the pipes it held are not
	// waited on for ever by anything it started.
	command.WaitDelay = time.Minute
	if err := command.Run(); err != nil {
		complaint := strings.TrimSpace(stderr.String())
		if ctx.Err() != nil {
			return fmt.Errorf("git %s did not finish within %s", args[0], budget)
		}
		if complaint == "" {
			return fmt.Errorf("git %s: %w", args[0], err)
		}
		return fmt.Errorf("git %s: %s", args[0], lastLine(complaint))
	}
	return nil
}

// reaching runs git with a guard for the repository's host in front of it.
func (g git) reaching(ctx context.Context, repository, dir string, args ...string) error {
	proxy := ""
	var door *guard
	if g.transport == "https" {
		parsed, err := url.Parse(repository)
		if err != nil {
			return fmt.Errorf("read the repository's address: %w", err)
		}
		door, err = openGuard(parsed.Hostname(), g.excluded)
		if err != nil {
			return err
		}
		defer door.close()
		proxy = door.address()
	}
	err := g.run(ctx, fetchBudget, dir, proxy, nil, nil, args...)
	if err != nil && door != nil {
		// The proxy's reason is the useful half. Git reports only that the
		// proxy said no.
		if refused := door.lastRefusal(); refused != nil {
			return refused
		}
	}
	return err
}

// clone makes a copy of a repository's branches at dir.
//
// Commits only where the host will send them without the files they
// describe, which for the kernel's stable tree is 1.1 GB rather than several
// times that. A host that cannot says so and sends everything; the warning it
// prints is not a failure.
func (g git) clone(ctx context.Context, repository, parent, dir string) error {
	return g.reaching(ctx, repository, parent,
		"clone", "--quiet", "--bare", "--no-tags", "--filter=tree:0", "--", g.source(repository), dir)
}

// fetch brings a copy's branches up to date, dropping branches the repository
// no longer has.
//
// From the remote the clone recorded rather than from the address. The clone
// recorded the filter beside the remote, and a fetch that names the address
// asks for whole trees on top of commits the copy holds without them: the host
// sends a pack that depends on trees the copy never had, and the fetch fails
// for want of them.
func (g git) fetch(ctx context.Context, repository, dir string) error {
	return g.reaching(ctx, repository, dir,
		"fetch", "--quiet", "--prune", "--no-tags", "origin", "+refs/heads/*:refs/heads/*")
}

// graph writes the index that makes asking which branches contain a commit
// cheap.
//
// Measured on the kernel's stable tree: 28 seconds a commit without it, 0.22
// with it, and 22 seconds and 116 MB to write.
func (g git) graph(ctx context.Context, dir string) error {
	return g.run(ctx, fetchBudget, dir, "", nil, nil, "commit-graph", "write", "--reachable")
}

// resolve answers the full name of each hash that names a commit in the copy.
//
// A hash absent from the answer is not a commit here: missing, or an
// abbreviation matching more than one object.
func (g git) resolve(ctx context.Context, dir string, hashes []string) (map[string]string, error) {
	var in bytes.Buffer
	for _, hash := range hashes {
		in.WriteString(hash + "^{commit}\n")
	}
	// One line per hash asked, so what comes back is bounded by the question.
	var out bytes.Buffer
	if err := g.run(ctx, lookupBudget, dir, "", in.Bytes(), &out,
		"cat-file", "--batch-check=%(objectname) %(objecttype)"); err != nil {
		return nil, err
	}
	found := map[string]string{}
	lines := bufio.NewScanner(&out)
	for _, hash := range hashes {
		if !lines.Scan() {
			return nil, errors.New("git cat-file answered fewer lines than it was asked")
		}
		// Answered one line per question, in order: the name and "commit",
		// or the question and "missing" or "ambiguous".
		fields := strings.Fields(lines.Text())
		if len(fields) == 2 && fields[1] == "commit" {
			found[hash] = fields[0]
		}
	}
	return found, nil
}

// branches answers the branches containing a commit that are kept, in
// version order, and how many contain it in all.
//
// Read as git prints it rather than held whole. A repository chooses its own
// branch names and how many there are, so what one lookup prints is bounded by
// nothing but that repository (REQ-69).
func (g git) branches(ctx context.Context, dir, commit string) ([]string, int, error) {
	var out branchLines
	if err := g.run(ctx, lookupBudget, dir, "", nil, &out,
		"for-each-ref", "--contains", commit, "--format=%(refname:strip=2)", "refs/heads/"); err != nil {
		return nil, 0, err
	}
	out.end()
	return out.kept(), out.count, nil
}

// longestLine is the most of one line kept while it arrives. A branch name
// wider than the column is counted and never kept, so nothing past this is
// needed to decide that.
const longestLine = 4 * database.NameWidth

// branchLines reads branch names one line at a time, counting every one and
// keeping the first MostBranches in version order.
type branchLines struct {
	line     []byte
	overlong bool
	names    []string
	count    int
}

func (b *branchLines) Write(p []byte) (int, error) {
	for _, c := range p {
		if c != '\n' {
			if len(b.line) < longestLine {
				b.line = append(b.line, c)
			} else {
				b.overlong = true
			}
			continue
		}
		b.take()
	}
	return len(p), nil
}

// end takes a last line that arrived without a newline.
func (b *branchLines) end() {
	if len(b.line) > 0 || b.overlong {
		b.take()
	}
}

// take ends one line.
func (b *branchLines) take() {
	name := strings.TrimSpace(string(b.line))
	overlong := b.overlong
	b.line, b.overlong = b.line[:0], false
	if name == "" && !overlong {
		return
	}
	b.count++
	// Kept only where the column can hold it and every engine will store
	// it. git allows any byte in a name, and text that is not valid UTF-8 is
	// refused by two of the four; a cut name is another branch.
	if overlong || !utf8.ValidString(name) || utf8.RuneCountInString(name) > database.NameWidth {
		return
	}
	b.names = append(b.names, name)
	if len(b.names) > 2*MostBranches {
		b.trim()
	}
}

// trim keeps the first MostBranches names in version order.
func (b *branchLines) trim() {
	sort.Slice(b.names, func(i, j int) bool { return versionLess(b.names[i], b.names[j]) })
	if len(b.names) > MostBranches {
		b.names = b.names[:MostBranches]
	}
}

func (b *branchLines) kept() []string {
	b.trim()
	return b.names
}

// limited keeps the last bytes written to it and drops the rest, so a
// program that prints without end does not grow this process with it. The
// last, because git says what went wrong at the end.
type limited struct {
	buffer *bytes.Buffer
	most   int
}

func (l *limited) Write(p []byte) (int, error) {
	l.buffer.Write(p)
	if over := l.buffer.Len() - l.most; over > 0 {
		l.buffer.Next(over)
	}
	return len(p), nil
}

// lastLine is the last line of what git complained, which is where it says
// what went wrong; the lines before it are progress and hints.
func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
