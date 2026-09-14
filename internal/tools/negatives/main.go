// Command negatives reports a 404 built from an error's own text.
//
// **A 404 asserts that a name reaches nothing.** Building its body from an
// error publishes whatever that error carried, and the two failures compound:
// thirty handlers wrote the 404 from the error, and the readers under them
// returned the driver's message unwrapped. A connection failure reached an
// authenticated caller as "that product does not exist", with the database
// host, port and driver in the detail — a false statement about the catalog
// and the address of the server in one answer.
//
// Only 404. The other refusals publish a store's own sentence deliberately,
// and which of the two an error is has already been decided for them by the
// helper that tells a refusal from a query that failed. Widening this to every
// status would flag fifteen deliberate lines and teach people to ignore it.
//
// What it does not cover: an error arm that answers the fixed 404 without
// asking which error it is. That has the same wrong status with nothing
// disclosed, and "did this arm test the sentinel" is a question about control
// flow that reading the text cannot answer. A gate that pretended to answer it
// would be worse than one that says where it stops.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/tools/walk"
)

// built matches a 404 whose message comes from an error value rather than from
// a sentence the code chose.
var built = regexp.MustCompile(
	`huma\.Error404NotFound\([^)]*\b(?:err|cause|failure)\.Error\(\)`)

// allowed is the one place a 404 may publish an error's text, and why.
//
// The catalog's own not-declared error is composed from the names the caller
// supplied and fixed words. Nothing a driver wrote can be in it, and a
// pipeline whose upload was refused has to be told which of the product, the
// branch and the variant was not declared. The arm is reached only once the
// sentinel has been tested — a property of one audited function rather than
// anything this gate can see, so the exemption is named rather than inferred.
var allowed = map[string]string{
	"internal/httpapi/absent.go": "undeclared, reached only for catalog.ErrNotFound",
}

func main() {
	var bad []string
	read, err := walk.Sources(".go", func(path string, body []byte) error {
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if _, ok := allowed[path]; ok {
			return nil
		}
		for i, line := range strings.Split(string(body), "\n") {
			// A comment quoting the shape is how this program and the
			// documents describe it.
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !built.MatchString(line) {
				continue
			}
			bad = append(bad, fmt.Sprintf(
				"%s:%d: a 404 built from an error's own text. It asserts that a name "+
					"reaches nothing, and publishes whatever the error carried — for a "+
					"store read, the driver's message. Split on the sentinel, choose "+
					"the sentence here, and send the error to the log:\n\t%s",
				path, i+1, strings.TrimSpace(line)))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(bad) == 0 {
		fmt.Printf("no 404 is built from an error's own text, beside the %d named "+
			"exception(s) (%d files)\n", len(allowed), read)
		return
	}
	for _, one := range bad {
		fmt.Fprintln(os.Stderr, one)
	}
	fmt.Fprintf(os.Stderr,
		"\n%d refusal(s) tell a caller a name reaches nothing, in words an error chose.\n",
		len(bad))
	os.Exit(1)
}
