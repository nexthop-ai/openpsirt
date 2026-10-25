// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sourcelink builds the addresses a location in a product's source
// opens at, from what a product says about the repositories its builds are
// made from. The deployment builds an address and never requests it: the
// reader's browser does, and signs in where the repository is private.
//
// An address is built from uploaded data, so it is treated as a URL from a
// scan: it reaches only a host the product names, over https, with every
// part a document supplies checked or escaped for where it lands.
package sourcelink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Style is the kind of server a host is, which names the templates its
// addresses are written in.
type Style string

// The servers whose addresses are known, and one an administrator describes.
const (
	GitHub Style = "github"
	GitLab Style = "gitlab"
	Gitea  Style = "gitea"
	Custom Style = "custom"
)

// Styles is every style a host may be.
func Styles() []Style { return []Style{GitHub, GitLab, Gitea, Custom} }

// templates is each known server's addresses for a file's lines and for two
// commits compared. Forgejo writes Gitea's.
var templates = map[Style][2]string{
	GitHub: {"{repo}/blob/{commit}/{path}#L{start}-L{end}", "{repo}/compare/{from}...{to}"},
	GitLab: {"{repo}/-/blob/{commit}/{path}#L{start}-{end}", "{repo}/-/compare/{from}...{to}"},
	Gitea:  {"{repo}/src/commit/{commit}/{path}#L{start}-L{end}", "{repo}/compare/{from}...{to}"},
}

// Host is a repository host a product's links may point at.
type Host struct {
	bun.BaseModel `bun:"table:repository_host,alias:rh"`

	ID        int64 `bun:"id,pk,autoincrement"`
	ProductID int64 `bun:"product_id,notnull"`
	// Remote is the remotes the host covers, normalized: a host, or a host
	// and the path a mirror keeps its copies under.
	Remote         string `bun:"remote,notnull"`
	RemoteIdentity string `bun:"remote_identity,notnull"`
	// Web is the address the covered repositories are under.
	Web             string `bun:"web,notnull"`
	Style           Style  `bun:"style,notnull"`
	FileTemplate    string `bun:"file_template,nullzero"`
	CompareTemplate string `bun:"compare_template,nullzero"`
}

// Path is what a product says about the code under a path prefix of its
// checkouts. The empty prefix is the whole product.
type Path struct {
	bun.BaseModel `bun:"table:repository_path,alias:rp"`

	ID             int64  `bun:"id,pk,autoincrement"`
	ProductID      int64  `bun:"product_id,notnull"`
	Prefix         string `bun:"prefix,notnull"`
	PrefixIdentity string `bun:"prefix_identity,notnull"`
	// Remote and Branch are the repository links name where an upload
	// states none, and the branch they open on.
	Remote string `bun:"remote,nullzero"`
	Branch string `bun:"branch,nullzero"`
	// Snippets is whether source under the prefix is kept, or nil where the
	// nearest prefix stating it decides.
	Snippets *bool `bun:"snippets"`
}

// Config is what a product says about its repositories.
type Config struct {
	Hosts []Host
	Paths []Path
}

// The most a product may state. A host per service and a path per
// repository a checkout holds is the ordinary size; sonic-buildimage pins
// dozens of submodules.
const (
	MostHosts = 100
	MostPaths = 2000
)

// placeholders is what each template may name.
var (
	filePlaceholders    = []string{"{repo}", "{commit}", "{path}", "{start}", "{end}"}
	comparePlaceholders = []string{"{repo}", "{from}", "{to}"}
	placeholder         = regexp.MustCompile(`\{[^}]*\}`)
)

// Valid puts what an administrator sent in the form it is stored in, and
// refuses what cannot be used, in words that name the entry.
func (c *Config) Valid() error {
	if len(c.Hosts) > MostHosts {
		return refusal.Errorf("%d hosts is more than the %d a product may name", len(c.Hosts), MostHosts)
	}
	if len(c.Paths) > MostPaths {
		return refusal.Errorf("%d paths is more than the %d a product may name", len(c.Paths), MostPaths)
	}
	remotes := map[string]bool{}
	for i := range c.Hosts {
		h := &c.Hosts[i]
		h.Remote = prefixOf(h.Remote)
		if h.Remote == "" {
			return refusal.Errorf("host %d names no remote", i+1)
		}
		if remotes[h.Remote] {
			return refusal.Errorf("the remote %q is named twice", h.Remote)
		}
		remotes[h.Remote] = true
		web, err := webOf(h.Web)
		if err != nil {
			return refusal.Errorf("host %q: %s", h.Remote, err)
		}
		h.Web = web
		switch h.Style {
		case GitHub, GitLab, Gitea:
			h.FileTemplate, h.CompareTemplate = "", ""
		case Custom:
			if err := template(h.FileTemplate, filePlaceholders); err != nil {
				return refusal.Errorf("host %q, file template: %s", h.Remote, err)
			}
			if h.CompareTemplate != "" {
				if err := template(h.CompareTemplate, comparePlaceholders); err != nil {
					return refusal.Errorf("host %q, compare template: %s", h.Remote, err)
				}
			}
		default:
			return refusal.Errorf("host %q is of style %q; a host is github, gitlab, gitea or custom", h.Remote, h.Style)
		}
		h.RemoteIdentity = identity(h.Remote)
	}
	prefixes := map[string]bool{}
	for i := range c.Paths {
		p := &c.Paths[i]
		prefix, ok := cleanPath(p.Prefix)
		if !ok {
			return refusal.Errorf("path %d, %q, is not a path within a checkout", i+1, p.Prefix)
		}
		p.Prefix = prefix
		if prefixes[prefix] {
			return refusal.Errorf("the path %q is named twice", prefix)
		}
		prefixes[prefix] = true
		p.Remote, p.Branch = strings.TrimSpace(p.Remote), strings.TrimSpace(p.Branch)
		switch {
		case (p.Remote == "") != (p.Branch == ""):
			return refusal.Errorf("path %q: a repository and its branch are named together or not at all", prefix)
		case p.Remote != "" && Normalize(p.Remote) == "":
			return refusal.Errorf("path %q: %q names no repository", prefix, p.Remote)
		case p.Remote == "" && p.Snippets == nil:
			return refusal.Errorf("path %q says nothing: name a repository, or whether snippets are kept", prefix)
		case strings.ContainsAny(p.Branch, " \t\n?#\\"):
			return refusal.Errorf("path %q: %q is not a branch name", prefix, p.Branch)
		}
		p.PrefixIdentity = identity(prefix)
	}
	return nil
}

// prefixOf is a host's remote prefix normalized: a host, and the path under
// it, in lower case, with no scheme, credential or port.
func prefixOf(remote string) string {
	host, path := parse(remote)
	if host == "" {
		return ""
	}
	if path == "" {
		return host
	}
	return strings.ToLower(host + "/" + path)
}

// webOf is a host's web address checked: https, a host, and no credential,
// query or fragment.
func webOf(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	switch {
	case err != nil, u.Host == "":
		return "", fmt.Errorf("%q is not a web address", s)
	case u.Scheme != "https":
		return "", fmt.Errorf("%q is not https, and links open over https alone", s)
	case u.User != nil, u.RawQuery != "", u.Fragment != "", u.Opaque != "":
		return "", fmt.Errorf("%q carries a credential, a query or a fragment", s)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// template refuses a template that does not begin at the repository, or
// names a placeholder it may not.
func template(t string, allowed []string) error {
	if !strings.HasPrefix(t, "{repo}/") {
		return fmt.Errorf("%q does not begin with {repo}/, so it could open on another host", t)
	}
	for _, name := range placeholder.FindAllString(t, -1) {
		known := false
		for _, a := range allowed {
			known = known || a == name
		}
		if !known {
			return fmt.Errorf("%q names %s; a template names %s", t, name, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// cleanPath is a path within a checkout with no leading or trailing slash,
// refused where a segment is empty or climbs out.
func cleanPath(p string) (string, bool) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return "", true
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.Contains(segment, "\\") {
			return "", false
		}
	}
	return p, true
}

// identity is the hash a unique index holds in place of a value longer than
// an index key may be.
func identity(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Store reads and writes what products say about their repositories.
type Store struct{ db bun.IDB }

// NewStore returns a store over db, which may be a transaction.
func NewStore(db bun.IDB) *Store { return &Store{db: db} }

// Config is what one product says about its repositories, hosts by remote
// and paths by prefix.
func (s *Store) Config(ctx context.Context, productID int64) (Config, error) {
	var out Config
	if err := s.db.NewSelect().Model(&out.Hosts).
		Where(`"rh"."product_id" = ?`, productID).
		OrderExpr(`"rh"."remote" ASC`).Scan(ctx); err != nil {
		return Config{}, fmt.Errorf("read the repository hosts of product %d: %w", productID, err)
	}
	if err := s.db.NewSelect().Model(&out.Paths).
		Where(`"rp"."product_id" = ?`, productID).
		OrderExpr(`"rp"."prefix" ASC`).Scan(ctx); err != nil {
		return Config{}, fmt.Errorf("read the repository paths of product %d: %w", productID, err)
	}
	return out, nil
}

// Replace states what one product says about its repositories, in place of
// whatever it said before. The configuration is checked first.
func (s *Store) Replace(ctx context.Context, productID int64, c Config) error {
	if err := c.Valid(); err != nil {
		return err
	}
	if _, err := s.db.NewDelete().Model((*Host)(nil)).
		Where(`"product_id" = ?`, productID).Exec(ctx); err != nil {
		return fmt.Errorf("let go of the repository hosts of product %d: %w", productID, err)
	}
	if _, err := s.db.NewDelete().Model((*Path)(nil)).
		Where(`"product_id" = ?`, productID).Exec(ctx); err != nil {
		return fmt.Errorf("let go of the repository paths of product %d: %w", productID, err)
	}
	for i := range c.Hosts {
		c.Hosts[i].ID, c.Hosts[i].ProductID = 0, productID
	}
	for i := range c.Paths {
		c.Paths[i].ID, c.Paths[i].ProductID = 0, productID
	}
	if err := database.InBatchesUnkeyed(ctx, s.db, c.Hosts); err != nil {
		return fmt.Errorf("record the repository hosts of product %d: %w", productID, err)
	}
	if err := database.InBatchesUnkeyed(ctx, s.db, c.Paths); err != nil {
		return fmt.Errorf("record the repository paths of product %d: %w", productID, err)
	}
	return nil
}
