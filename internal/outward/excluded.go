// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package outward

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Excluded is where an administrator said nothing is ever fetched from.
//
// Two kinds of entry. A name covers itself and every host under it, so
// `corp.example.com` covers `git.corp.example.com`. A network covers every
// address in it, and is checked against the address a name resolved to rather
// than the name, so a public name pointing into it is refused too.
//
// On top of what is refused regardless: loopback, private, link-local and
// shared address space, which nothing this process fetches is reached inside
// (REQ-69).
type Excluded struct {
	names    []string
	networks []*net.IPNet
}

// hostName is a host as it may be named: a name or an address, and no port,
// credentials or anything else a URL can carry before the path.
var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// HostName reports whether a lowered host is a bare name or address.
func HostName(host string) bool { return hostName.MatchString(host) }

// ParseExcluded reads a comma-separated list of names and networks.
func ParseExcluded(list string) (Excluded, error) {
	var out Excluded
	for _, entry := range strings.Split(list, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return Excluded{}, fmt.Errorf("%q is not a network — write it as 10.0.0.0/8", entry)
			}
			out.networks = append(out.networks, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 8 * len(ip.To4())
			if bits == 0 {
				bits = 128
			}
			out.networks = append(out.networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		name := strings.TrimPrefix(entry, ".")
		if !hostName.MatchString(name) {
			return Excluded{}, fmt.Errorf("%q is neither a host name nor a network", entry)
		}
		out.names = append(out.names, name)
	}
	return out, nil
}

// Host reports whether a host is one an administrator excluded by name.
func (e Excluded) Host(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, name := range e.names {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return e.address(ip)
	}
	return false
}

// address reports whether an address is in a network an administrator
// excluded.
func (e Excluded) address(ip net.IP) bool {
	for _, network := range e.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Reachable refuses an address inside this network or in one an
// administrator excluded.
func (e Excluded) Reachable(address string) error {
	if err := Reachable(address); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil && e.address(ip) {
		return fmt.Errorf("refused a connection to %s: an administrator excluded it", ip)
	}
	return nil
}
