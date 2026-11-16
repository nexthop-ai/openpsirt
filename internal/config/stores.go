// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// apart refuses a published directory that is the attachment store, or holds
// it, or sits inside it.
//
// What the directory holds is served to anybody, and an attachment is fetched
// only after its finding's visibility is checked (REQ-70). Sharing one store
// serves every attachment unauthenticated. A bucket wins over a folder in each,
// so each is compared in the form it takes.
func apart(directory, attachments Store) error {
	if bucket := strings.TrimSpace(directory.Bucket); bucket != "" {
		other := strings.TrimSpace(attachments.Bucket)
		if !strings.EqualFold(bucket, other) {
			return nil
		}
		same, err := sameEndpoint(directory.Endpoint, attachments.Endpoint)
		if err != nil {
			return err
		}
		if same {
			return fmt.Errorf("OPENPSIRT_DIRECTORY_BUCKET: names the attachment store's " +
				"bucket, and everything in the directory is served to anybody: give the " +
				"directory a bucket of its own")
		}
		return nil
	}
	dir, other := strings.TrimSpace(directory.Dir), strings.TrimSpace(attachments.Dir)
	if dir == "" || other == "" || strings.TrimSpace(attachments.Bucket) != "" {
		return nil
	}
	dir, err := resolved(dir)
	if err != nil {
		return fmt.Errorf("OPENPSIRT_DIRECTORY_DIR: %w", err)
	}
	other, err = resolved(other)
	if err != nil {
		return fmt.Errorf("OPENPSIRT_ATTACHMENT_DIR: %w", err)
	}
	if within(dir, other) || within(other, dir) {
		return fmt.Errorf("OPENPSIRT_DIRECTORY_DIR: is, holds or sits inside " +
			"OPENPSIRT_ATTACHMENT_DIR, and everything in the directory is served to " +
			"anybody: give each a folder of its own")
	}
	return nil
}

// sameEndpoint reports whether two object store endpoints may name one
// service, and so one bucket where the names match.
//
// Each is compared as the service it reaches: a name and password
// in the address are handed over as credentials and taken out of it, a
// scheme's default port is no port, and capitals and slashes around the path
// mean nothing. Every Amazon S3 address of one partition is one service, because
// a bucket's name is unique across it. Two host names on one port and path
// are one service where they resolve to a shared address, since a short name
// and a cluster name, or a name and its address, reach one server.
//
// Doubt refuses: an empty endpoint is whatever the SDK resolves, from the
// environment, a profile or the region, so it is the same as any endpoint;
// so is an endpoint that does not parse. A lookup that keeps failing for any
// reason but the name not existing is a fault, returned as an error.
func sameEndpoint(a, b string) (bool, error) {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return true, nil
	}
	one, read := storeParts(a)
	two, readToo := storeParts(b)
	switch {
	case !read || !readToo:
		return true, nil
	case one.host == two.host && one.rest == two.rest:
		return true, nil
	case one.amazon || two.amazon || one.rest != two.rest:
		return false, nil
	}
	return sharedAddress(one.host, two.host)
}

// lookupHost resolves a host name to its addresses.
var lookupHost = net.DefaultResolver.LookupHost

// lookupWait is how long a failing lookup is asked again, and lookupPause how
// it waits between two asks.
var (
	lookupWait  = time.Minute
	lookupPause = time.Sleep
	lookupNow   = time.Now
)

// sharedAddress reports whether two hosts resolve to an address in common. A
// name that does not exist shares nothing, since a store nobody can reach
// serves nothing.
func sharedAddress(one, two string) (bool, error) {
	// One wait for both, so a resolver that is down holds startup for
	// lookupWait once.
	waited := time.Duration(0)
	mine, err := addresses(one, &waited)
	if err != nil {
		return false, err
	}
	theirs, err := addresses(two, &waited)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(mine, func(ip string) bool { return slices.Contains(theirs, ip) }), nil
}

// addresses is what a host resolves to, each address in one spelling. A name
// that does not exist has none. Any other failure is asked again, waiting
// twice as long each time, until the wait shared with the other host reaches
// lookupWait, and is then a fault in name resolution.
func addresses(host string, waited *time.Duration) ([]string, error) {
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	for pause := time.Second; ; pause *= 2 {
		// Each ask counts against the wait as well as each pause. An ask
		// with nothing left still takes a second, so a host asked after
		// the other spent the wait is asked once.
		ask := min(5*time.Second, max(lookupWait-*waited, time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), ask)
		began := lookupNow()
		found, err := lookupHost(ctx, host)
		*waited += lookupNow().Sub(began)
		cancel()
		var dns *net.DNSError
		switch {
		case err == nil:
			for i, each := range found {
				if ip := net.ParseIP(each); ip != nil {
					found[i] = ip.String()
				}
			}
			return found, nil
		case errors.As(err, &dns) && dns.IsNotFound:
			return nil, nil
		case *waited >= lookupWait:
			return nil, fmt.Errorf("looking up %q, to tell whether the directory and the attachment "+
				"store are one object store, failed for %v: a fault in name resolution, not in the "+
				"configuration: %w", host, *waited, err)
		}
		pause = min(pause, lookupWait-*waited)
		lookupPause(pause)
		*waited += pause
	}
}

// awsService is the service every Amazon S3 endpoint of the commercial
// partition reaches, and the domain of every partition's endpoints.
const awsService = "amazonaws.com"

// storeService is the service an object store endpoint reaches.
type storeService struct {
	// host is the host in lower case without a trailing dot, or the
	// partition for an Amazon address.
	host string
	// rest is a port where the port is not the scheme's default, and a
	// path where there is one.
	rest string
	// amazon says the host is an Amazon S3 endpoint, and host its partition.
	amazon bool
}

// s3Label is the position of the service label among the labels of an
// Amazon host before its domain, `s3` or one starting `s3-` as in
// `s3-external-1` and `s3-fips`, or -1 where there is none. A bucket's name
// may precede it, so the last such label is the service's.
func s3Label(parts []string) int {
	service := -1
	for i, part := range parts {
		if part == "s3" || strings.HasPrefix(part, "s3-") {
			service = i
		}
	}
	return service
}

// govCloud reports whether the labels of an Amazon S3 host after its service
// label name a GovCloud region, which shares the domain and is a partition of
// its own. The region follows the service label, dotted as
// `s3.us-gov-west-1` or dashed as `s3-us-gov-west-1`, and a bucket's name
// before it counts for nothing.
func govCloud(parts []string, service int) bool {
	dashed := strings.TrimPrefix(strings.TrimPrefix(parts[service], "s3-"), "fips-")
	if strings.HasPrefix(dashed, "us-gov-") {
		return true
	}
	return slices.ContainsFunc(parts[service+1:], func(part string) bool { return strings.HasPrefix(part, "us-gov-") })
}

// storeParts is the service an object store endpoint reaches, and whether the
// endpoint could be read. Every S3 endpoint of one AWS partition reaches one
// service, since a bucket name is unique across it: China, GovCloud, and the
// rest. Any other Amazon host, such as an EC2 instance's or a load balancer's
// name, is a server like any other, compared by its resolved address.
func storeParts(endpoint string) (storeService, bool) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" {
		return storeService{}, false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	// The China partition first, since its domain ends in the other's.
	for _, domain := range []string{awsService + ".cn", awsService} {
		labels, found := strings.CutSuffix(host, "."+domain)
		if !found {
			continue
		}
		parts := strings.Split(labels, ".")
		service := s3Label(parts)
		if service < 0 {
			break
		}
		if govCloud(parts, service) {
			domain = "us-gov." + domain
		}
		return storeService{host: domain, amazon: true}, true
	}
	service := storeService{host: host}
	switch port := parsed.Port(); {
	case port == "",
		port == "443" && strings.EqualFold(parsed.Scheme, "https"),
		port == "80" && strings.EqualFold(parsed.Scheme, "http"):
	default:
		service.rest = ":" + port
	}
	if path := strings.Trim(parsed.EscapedPath(), "/"); path != "" {
		service.rest += "/" + path
	}
	return service, true
}

// resolved is a folder as an absolute path with every symbolic link in it
// followed, so that two names for one folder compare as one. A folder not
// made yet is resolved through the nearest one above it that exists, and a
// link to a folder not made yet through what it points at, since the folder
// is made there.
func resolved(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	below := ""
	for hops := 0; ; {
		followed, err := filepath.EvalSymlinks(path)
		if err == nil {
			return filepath.Join(followed, below), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			// The bound the kernel puts on links followed in one lookup.
			if hops++; hops > 40 {
				return "", fmt.Errorf("%s: too many links", path)
			}
			target, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			// A relative target is read from the link's real folder, so a
			// ".." climbs from there.
			if !filepath.IsAbs(target) {
				folder, err := filepath.EvalSymlinks(filepath.Dir(path))
				if err != nil {
					return "", err
				}
				target = filepath.Join(folder, target)
			}
			path = filepath.Clean(target)
			continue
		}
		parent := filepath.Dir(path)
		if parent == path {
			return filepath.Join(path, below), nil
		}
		below = filepath.Join(filepath.Base(path), below)
		path = parent
	}
}

// within reports whether path is root or a folder below it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
