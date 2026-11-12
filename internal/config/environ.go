// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// incidental reports whether a variable, named without the prefix, is one that is
// set for something else: the test suite's, which every program the build
// runs inherits; the interface's development server's; the upload client's
// address and key, which a CI job running both programs sets; or a
// Kubernetes service link.
func incidental(key, value string) bool {
	return strings.HasPrefix(key, "TEST_") || strings.HasPrefix(key, "DEV_") ||
		key == "URL" || key == "KEY" || serviceLinked(key, value)
}

// serviceLinked reports whether a variable, named without the prefix, is a
// Kubernetes service link, which a pod is given for every Service in its
// namespace and so for one whose name begins with the prefix. A link is
// recognized by its value as well as its name, so a setting misspelled into
// the shape of one, such as a mail port given as `<prefix>MAIL_PORT=587`, is
// still refused.
func serviceLinked(key, value string) bool {
	// A Service's name may itself end in a link's suffix, as
	// `openpsirt-api-service` does, so every reading of the name is tried.
	for suffix := key; ; {
		if linkSuffix.MatchString(suffix) && linkValue(suffix, value) {
			return true
		}
		_, rest, found := strings.Cut(suffix, "_")
		if !found {
			return false
		}
		suffix = rest
	}
}

// linkValue reports whether a value has the shape a service link with the
// suffix given has.
func linkValue(suffix, value string) bool {
	// A named port's name may end in any of the other suffixes, so it is
	// read first.
	switch {
	case strings.HasPrefix(suffix, "SERVICE_PORT"), strings.HasSuffix(suffix, "_PORT") && suffix != "PORT":
		_, err := strconv.ParseUint(value, 10, 16)
		return err == nil
	case suffix == "SERVICE_HOST", strings.HasSuffix(suffix, "_ADDR"):
		return net.ParseIP(value) != nil
	case strings.HasSuffix(suffix, "_PROTO"):
		return value == "tcp" || value == "udp" || value == "sctp"
	default:
		return linkAddress.MatchString(value)
	}
}

// linkSuffix matches what follows a Service's name in the variables
// Kubernetes gives a pod for it: `<SERVICE>_SERVICE_HOST`,
// `<SERVICE>_SERVICE_PORT` and one per named port, `<SERVICE>_PORT`, and
// `<SERVICE>_PORT_<number>_<protocol>` with its three parts.
var linkSuffix = regexp.MustCompile(
	`^(SERVICE_HOST|SERVICE_PORT(_[A-Z0-9_]+)?|PORT(_[0-9]+_(TCP|UDP|SCTP)(_(PROTO|PORT|ADDR))?)?)$`)

// linkAddress is the value of a service link naming a whole address, such as
// `tcp://10.0.0.11:8080`.
var linkAddress = regexp.MustCompile(`^(tcp|udp|sctp)://[0-9A-Fa-f.:\[\]]+:[0-9]+$`)
