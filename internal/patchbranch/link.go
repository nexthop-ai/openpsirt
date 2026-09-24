// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package patchbranch labels a patch link with the branches that carry it.
//
// A fix is backported as a separate commit to each branch its maintainers
// still support, and a report lists those commits as bare links. Which link is
// the one for the branch a product ships is written nowhere in the report. It
// is written in the repository: the branches containing a commit are a
// question its history answers.
//
// So a copy of that history is kept here, and asked. Nothing in the report
// decides which branch a commit is on — the report supplies an address, and
// the answer comes from the repository the address names (REQ-78).
package patchbranch

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Commit is a commit a patch link names, in the repository that holds it.
type Commit struct {
	// Repository is the address the history is fetched from. Built here from
	// the parts of the link that were recognized, never copied from it, so
	// what reaches git is an address of a known shape rather than whatever a
	// report carried.
	Repository string
	// Hash is the commit's name, lowered. A link may abbreviate it, and an
	// abbreviation is kept as written: the copy resolves it, and an
	// abbreviation and the full name stay two rows, each looked up in its own
	// right.
	Hash string
}

// Host is the host the repository is fetched from.
func (c Commit) Host() string {
	parsed, err := url.Parse(c.Repository)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// hexName is a commit named in full or abbreviated.
//
// Seven characters is the shortest abbreviation git prints by default, and
// sixty-four is a name under the longer hash a repository may be converted to.
// Anything shorter is as likely to be a pull request number or a date as a
// commit.
var hexName = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// segment is one part of a repository path as it may reach git.
//
// Deliberately narrow: what is built from these is an argument to a program,
// and a path is the one part of an address a report chooses freely.
var segment = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)

// hostName is a host as it may reach git: a name or an address, and no port,
// credentials or anything else a URL can carry before the path.
var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// kernelShort is where the kernel's short links point.
//
// Two shapes git.kernel.org serves that name a commit and no repository: the
// stable tree's and the mainline tree's. The repository each stands for is the
// one the site redirects them to.
var kernelShort = map[string]string{
	"stable": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
	"linus":  "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
}

// cgitSite is where a cgit site serves the repositories its pages show.
type cgitSite struct {
	// Host is where the repositories are fetched from.
	Host string
	// Pages is the first path segment of a page, which names no repository.
	// Empty where every path on the site is a page.
	Pages string
	// Under is the path the repositories are served under.
	Under []string
}

// cgitSites is the cgit sites whose pages and repositories are at different
// addresses, keyed on the host the pages are on.
//
// Each repository address is the one git reaches without a redirect, because
// a fetch follows none: Savannah redirects its own clone address to the host
// named here.
var cgitSites = map[string]cgitSite{
	"git.kernel.org":               {Host: "git.kernel.org", Pages: "cgit", Under: []string{"pub", "scm"}},
	"git.savannah.gnu.org":         {Host: "https.git.savannah.gnu.org", Pages: "cgit", Under: []string{"git"}},
	"cgit.git.savannah.gnu.org":    {Host: "https.git.savannah.gnu.org", Pages: "cgit", Under: []string{"git"}},
	"git.savannah.nongnu.org":      {Host: "https.git.savannah.nongnu.org", Pages: "cgit", Under: []string{"git"}},
	"cgit.git.savannah.nongnu.org": {Host: "https.git.savannah.nongnu.org", Pages: "cgit", Under: []string{"git"}},
	"cgit.freebsd.org":             {Host: "git.freebsd.org"},
}

// Parse reads the commit a patch link names.
//
// Answers false for anything that does not name exactly one commit in a
// recognizable repository. A pull request, a merge request, a mailing-list
// post and a patch tracker all describe a fix without naming where it
// landed, and a guess at a repository is a request to somewhere the link never
// pointed.
//
// The shapes read:
//
//	/{owner}/{repo}/commit/{hash}            GitHub, Gitea, Forgejo, Gogs
//	/{owner}/{repo}/pull/{n}/commits/{hash}  GitHub, a commit inside a pull request
//	/{group…}/{repo}/-/commit/{hash}         GitLab
//	/{path…}/commit/?id={hash}               cgit
//	/stable/c/{hash}, /linus/{hash}          git.kernel.org's short links
//
// A cgit site that serves its pages and its repositories at different
// addresses has its links read as the repository address, from cgitSites.
func Parse(link string) (Commit, bool) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return Commit{}, false
	}
	if parsed.User != nil || parsed.Port() != "" {
		return Commit{}, false
	}
	host := strings.ToLower(parsed.Hostname())
	if !hostName.MatchString(host) {
		return Commit{}, false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")

	if host == "git.kernel.org" {
		if len(parts) == 3 && parts[1] == "c" {
			if repository, ok := kernelShort[parts[0]]; ok {
				return named(repository, parts[2])
			}
		}
		if len(parts) == 2 && parts[0] == "linus" {
			return named(kernelShort["linus"], parts[1])
		}
	}
	if site, ok := cgitSites[host]; ok {
		if site.Pages == "" {
			host, parts = site.Host, slices.Concat(site.Under, parts)
		} else if len(parts) > 0 && parts[0] == site.Pages {
			host, parts = site.Host, slices.Concat(site.Under, parts[1:])
		}
	}

	// cgit names the commit in the query rather than the path.
	if len(parts) >= 2 && parts[len(parts)-1] == "commit" {
		return at(host, parts[:len(parts)-1], parsed.Query().Get("id"))
	}
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] != "commit" || i+2 != len(parts) {
			continue
		}
		repository := parts[:i]
		// GitLab puts a marker between the repository and what is in it.
		if n := len(repository); n > 0 && repository[n-1] == "-" {
			repository = repository[:n-1]
		}
		return at(host, repository, strings.TrimSuffix(strings.TrimSuffix(parts[i+1], ".patch"), ".diff"))
	}
	// A commit inside a pull request is a commit in the repository the pull
	// request was opened against, which may not hold it on any branch yet.
	if n := len(parts); n == 6 && parts[2] == "pull" && parts[4] == "commits" {
		return at(host, parts[:2], parts[5])
	}
	return Commit{}, false
}

// at is the commit hash in the repository at host and path.
func at(host string, path []string, hash string) (Commit, bool) {
	if len(path) == 0 {
		return Commit{}, false
	}
	for _, part := range path {
		if !segment.MatchString(part) || part == "." || part == ".." {
			return Commit{}, false
		}
	}
	repository := "https://" + host + "/" + strings.Join(path, "/")
	if !strings.HasSuffix(repository, ".git") {
		repository += ".git"
	}
	return named(repository, hash)
}

// named is the commit hash in repository, where hash is a commit's name.
func named(repository, hash string) (Commit, bool) {
	hash = strings.ToLower(hash)
	if !hexName.MatchString(hash) {
		return Commit{}, false
	}
	return Commit{Repository: repository, Hash: hash}, true
}
