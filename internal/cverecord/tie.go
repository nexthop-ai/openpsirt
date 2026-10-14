// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"strings"
	"unicode"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// tied reports whether a record's entry describes the upstream project a
// component is a release of.
//
// Three ways, and only these. An entry carrying a CPE is tied to an upstream
// component whose CPE names the same vendor and product; an entry carrying a
// package identifier is tied to an upstream component with the same one. An
// entry that carries neither is tied through a name listed in names,
// which is the only way a distribution's package is tied at all.
//
// A distribution's package is never tied by its own CPE or identifier. Those
// describe the distribution's build, and an entry they match is the
// distribution's statement about that build, whose version lines are in the
// distribution's numbering rather than upstream's.
//
// The same holds from the entry's side. An entry a distribution or another
// vendor wrote about its own build may carry upstream's CPE, and its lines are
// still in that build's numbering, so a CPE ties only an entry that speaks as
// its publisher (see upstreams).
func tied(entry Entry, component graph.Described) bool {
	parts := graph.PartsOfPurl(component.Purl)
	if !Distribution(parts.Type) {
		if vendor, product, ok := cpeProduct(component.CPE); ok {
			for _, stated := range entry.CPEs {
				v, p, ok := cpeProduct(stated)
				if ok && v == vendor && p == product && upstreams(entry, v, p) {
					return true
				}
			}
		}
		if stated := graph.PartsOfPurl(entry.PackageURL); stated.Type != "" && parts.Type != "" &&
			stated.Type == parts.Type &&
			strings.EqualFold(stated.Namespace, parts.Namespace) &&
			strings.EqualFold(stated.Name, parts.Name) {
			return true
		}
	}
	for _, known := range names {
		if known.describes(entry) && known.covers(component, parts) {
			return true
		}
	}
	return false
}

// upstreams reports whether an entry speaks as the publisher a CPE it carries
// names, rather than as a distribution or vendor describing its own build.
//
// Two signs mark another's statement. The entry names neither the CPE's
// vendor nor its product, the way a distribution's entry names itself and its
// release; and the entry carries a platform CPE of another vendor, the way a
// distribution's entry names the release it was built for. An entry naming
// nobody at all, as a record assigned on a project's behalf often does, is
// read as the project's.
func upstreams(entry Entry, vendor, product string) bool {
	named, called := folded(entry.Vendor), folded(entry.Product)
	if named != "" || called != "" {
		if !strings.Contains(named, folded(vendor)) && !strings.Contains(called, folded(product)) {
			return false
		}
	}
	for _, stated := range entry.CPEs {
		part, v, _, ok := cpeParts(stated)
		if ok && part == "o" && v != vendor {
			return false
		}
	}
	return true
}

// folded is a name with everything but its letters and digits taken out, in
// lower case: "Red Hat" and "redhat" are one vendor. A name written "n/a" is
// no name.
func folded(name string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			out.WriteRune(r)
		}
	}
	if out.String() == "na" {
		return ""
	}
	return out.String()
}

// name ties entries that carry no CPE and no package identifier to the
// components they describe.
type name struct {
	// vendor and product are how the entry names the project, folded.
	vendor, product string
	// cpes are the vendor and product an upstream component's CPE names for
	// the same project.
	cpes [][2]string
	// sources are the distributions' packages that carry upstream's release
	// numbering unchanged, by package type, distribution and source package.
	sources []source
}

// source is one distribution's package of an upstream project.
type source struct {
	kind, namespace, name string
}

// names is every project an entry is tied to by name.
//
// The kernel's numbering authority writes its entries as vendor "Linux" and
// product "Linux", with the stable tree as the repository and no CPE. Debian's
// kernel package carries the stable release it was built from as its version,
// so its version with the revision taken off is that release. Ubuntu's and
// Red Hat's kernels keep one base version while taking in stable releases, so
// their versions say nothing about which stable release they carry and they
// are not listed.
var names = []name{{
	vendor: "linux", product: "linux",
	cpes:    [][2]string{{"linux", "linux_kernel"}},
	sources: []source{{kind: "deb", namespace: "debian", name: "linux"}},
}}

func (n name) describes(entry Entry) bool {
	return len(entry.CPEs) == 0 && strings.TrimSpace(entry.PackageURL) == "" &&
		strings.EqualFold(strings.TrimSpace(entry.Vendor), n.vendor) &&
		strings.EqualFold(strings.TrimSpace(entry.Product), n.product)
}

func (n name) covers(component graph.Described, parts graph.Parts) bool {
	if !Distribution(parts.Type) {
		vendor, product, ok := cpeProduct(component.CPE)
		if !ok {
			return false
		}
		for _, pair := range n.cpes {
			if pair[0] == vendor && pair[1] == product {
				return true
			}
		}
		return false
	}
	upstream := strings.TrimSpace(component.UpstreamName)
	if upstream == "" {
		upstream = parts.Name
	}
	for _, s := range n.sources {
		if parts.Type == s.kind && strings.EqualFold(parts.Namespace, s.namespace) &&
			strings.EqualFold(upstream, s.name) {
			return true
		}
	}
	return false
}

// cpeProduct is the vendor and product a CPE names, folded, in either of the
// two forms the format has: the formatted string and the older URI.
//
// A backslash escapes the character after it in the formatted form, so it is
// dropped before comparing: "linux\-image" and "linux-image" are one name.
func cpeProduct(cpe string) (vendor, product string, ok bool) {
	_, vendor, product, ok = cpeParts(cpe)
	return vendor, product, ok
}

// cpeParts is the part, the vendor and the product a CPE names, folded: "a"
// for an application, "o" for an operating system, "h" for hardware.
func cpeParts(cpe string) (part, vendor, product string, ok bool) {
	cpe = strings.TrimSpace(cpe)
	var fields []string
	switch {
	case strings.HasPrefix(cpe, "cpe:2.3:"):
		fields = splitFormatted(strings.TrimPrefix(cpe, "cpe:2.3:"))
	case strings.HasPrefix(cpe, "cpe:/"):
		fields = strings.Split(strings.TrimPrefix(cpe, "cpe:/"), ":")
	default:
		return "", "", "", false
	}
	if len(fields) < 3 {
		return "", "", "", false
	}
	part = strings.ToLower(fields[0])
	vendor, product = strings.ToLower(fields[1]), strings.ToLower(fields[2])
	if vendor == "" || product == "" || vendor == "*" || product == "*" {
		return "", "", "", false
	}
	return part, vendor, product, true
}

// splitFormatted splits a formatted CPE on the colons that are not escaped,
// and drops the escapes.
func splitFormatted(s string) []string {
	var fields []string
	var field strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			field.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			fields = append(fields, field.String())
			field.Reset()
		default:
			field.WriteRune(r)
		}
	}
	return append(fields, field.String())
}
