// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Mapping is one thing configuration says membership of a group grants.
//
// Configuration is the only source of these (REQ-41). They decide who holds
// every role in the deployment, so they change the way the deployment does,
// and nothing running can widen them.
type Mapping struct {
	// Group is the name the provider reports, matched exactly.
	Group string
	// Grants is a role held on products, or something held over the
	// deployment.
	Grants string
	// Product is the product a role is held on, folded the way a product's
	// name is. Empty is every product, including one declared later, and is
	// always empty for something held over the deployment.
	Product string
}

// Over reports what the mapping holds over the deployment, if that is what it
// grants.
func (m Mapping) Over() (Over, bool) {
	over := Over(m.Grants)
	return over, over.Valid()
}

// String is how the trail and the startup log name one mapping.
func (m Mapping) String() string {
	switch {
	case m.Product != "":
		return fmt.Sprintf("%s on %s", m.Group, m.Product)
	case Over(m.Grants).Valid():
		return m.Group + " over this deployment"
	}
	return m.Group + " on every product"
}

// GroupRoles is one entry as configuration writes it: a group, the roles its
// members hold, and the products those are held on.
type GroupRoles struct {
	Group    string
	Roles    []string
	Products []string
}

// escaped is what a name has percent-encoded inside one entry, because each
// separates the parts of the variable. The percent sign is first so that an
// encoding is never encoded twice.
var escaped = strings.NewReplacer(
	"%", "%25", ";", "%3B", "=", "%3D", "+", "%2B", "@", "%40", ",", "%2C")

// SpellGroupRoles writes entries as the variable carries them.
func SpellGroupRoles(entries []GroupRoles) string {
	spelled := make([]string, 0, len(entries))
	for _, entry := range entries {
		one := escaped.Replace(entry.Group) + "=" + strings.Join(entry.Roles, "+")
		if len(entry.Products) > 0 {
			products := make([]string, 0, len(entry.Products))
			for _, product := range entry.Products {
				products = append(products, escaped.Replace(product))
			}
			one += "@" + strings.Join(products, ",")
		}
		spelled = append(spelled, one)
	}
	return strings.Join(spelled, "; ")
}

// ParseGroupRoles reads the variable into the mappings it states.
//
// Entries are separated by semicolons. Each is a group, an equals sign, roles
// joined by plus signs, and optionally an at sign and products joined by
// commas: "security-team=private-triage+approver@router-os,switch-os". A name
// holding one of those characters, or a percent sign, writes it
// percent-encoded. The result is sorted and holds each mapping once.
func ParseGroupRoles(raw string) ([]Mapping, error) {
	var out []Mapping
	for n, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		mappings, err := parseEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", n+1, err)
		}
		out = append(out, mappings...)
	}
	slices.SortFunc(out, func(a, b Mapping) int {
		return strings.Compare(a.Group+"\x00"+a.Product+"\x00"+a.Grants,
			b.Group+"\x00"+b.Product+"\x00"+b.Grants)
	})
	return slices.Compact(out), nil
}

// parseEntry reads one group's entry.
func parseEntry(entry string) ([]Mapping, error) {
	rawGroup, rest, found := strings.Cut(entry, "=")
	if !found {
		return nil, refusal.Errorf("%q names no role: write it as group=role", entry)
	}
	group, err := unescape(rawGroup)
	if err != nil {
		return nil, err
	}
	switch {
	case group == "":
		return nil, refusal.Errorf("%q names no group", entry)
	case utf8.RuneCountInString(group) > database.NameWidth:
		return nil, refusal.Errorf("group %q is longer than %d characters", group, database.NameWidth)
	}

	rawRoles, rawProducts, scoped := strings.Cut(rest, "@")
	var roles []string
	for _, role := range strings.Split(rawRoles, "+") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if !Role(role).Valid() && !Over(role).Valid() {
			return nil, refusal.Errorf("%q is not a role: it is one of %s", role, strings.Join(grantable(), ", "))
		}
		roles = append(roles, role)
	}
	if len(roles) == 0 {
		return nil, refusal.Errorf("group %q is given no role", group)
	}

	var products []string
	if scoped {
		for _, rawProduct := range strings.Split(rawProducts, ",") {
			product, err := unescape(rawProduct)
			if err != nil {
				return nil, err
			}
			product = strings.ToLower(product)
			switch {
			case product == "":
				return nil, refusal.Errorf("group %q names an empty product", group)
			case utf8.RuneCountInString(product) > database.NameWidth:
				return nil, refusal.Errorf("product %q is longer than %d characters",
					product, database.NameWidth)
			}
			products = append(products, product)
		}
	}

	var out []Mapping
	for _, role := range roles {
		if Over(role).Valid() {
			if len(products) > 0 {
				return nil, refusal.Errorf("%s is held over the whole deployment, so group %q "+
					"names no product for it: give it an entry of its own", role, group)
			}
			out = append(out, Mapping{Group: group, Grants: role})
			continue
		}
		if len(products) == 0 {
			out = append(out, Mapping{Group: group, Grants: role})
		}
		for _, product := range products {
			out = append(out, Mapping{Group: group, Grants: role, Product: product})
		}
	}
	return out, nil
}

// unescape reads a name with its percent-encoding undone, refusing a percent
// sign that does not begin an encoding.
func unescape(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	name, err := url.PathUnescape(trimmed)
	if err != nil {
		return "", refusal.Errorf("%q holds a %% that does not begin an encoding such as %%40: "+
			"write a percent sign itself as %%25", trimmed)
	}
	return strings.TrimSpace(name), nil
}

// grantable is every word a mapping may grant, in the order the
// documentation lists them.
func grantable() []string {
	words := make([]string, 0, len(Roles())+2)
	for _, role := range Roles() {
		words = append(words, string(role))
	}
	for _, over := range OverTheDeployment() {
		words = append(words, string(over))
	}
	return words
}
