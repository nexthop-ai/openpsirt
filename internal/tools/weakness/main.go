// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command weakness writes the weakness names a published advisory has to carry.
//
// The name is not optional and cannot be invented. CSAF states a weakness
// as an identifier and the name that goes with it, and a consumer's validator
// checks the pair against the published catalog. What is held here is the
// identifier alone — a scanner reports "CWE-787" and which source said so, and
// no name arrives with it — so a document naming a weakness has to get the name
// from the authority that assigns it.
//
// Fetched rather than typed, for the reason the reserved-word list is asked
// rather than typed. A thousand names nobody can check by eye is a file that
// goes wrong quietly: one transcription error is a document that fails
// validation at a customer, months later, over a weakness nobody was looking
// at. The catalog is published, so it is read.
//
// Weaknesses only. The catalog also carries categories and views, which
// have identifiers of the same shape and are not what a vulnerability is
// classified as. An identifier this does not know the name of produces no
// weakness in the document rather than a guess.
//
// The version read is recorded in the generated file. It is not gated against
// what the catalog says today: the engines a reserved-word list asks are pinned
// in CI and this authority is not, so a check against "latest" would fail the
// build on the day MITRE publishes, for a reason no change here caused. It is
// regenerated deliberately, by running this.
//
//	make weakness-names
package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"go/format"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/tools/provenance"
)

// catalogURL is the complete catalog, which is the one that carries every
// weakness rather than those reachable from one view.
const catalogURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

// written is where the names go, relative to the repository root.
const written = "internal/weakness/names.go"

// The bounds on what is read. The published archive is a few megabytes and
// the document inside it a few tens; each bound sits well above that and
// fails in words when outgrown, where an unbounded read of a hostile answer
// is the process running out of memory.
const (
	mostArchive  = 64 << 20
	mostDocument = 512 << 20
	mostHops     = 5
)

// catalog is the shape of the published file, read down to the two fields a
// document needs. Everything else it carries — the descriptions, the
// relationships, the mitigations — is a reference work rather than something a
// generated advisory states.
type catalog struct {
	Version    string `xml:"Version,attr"`
	Date       string `xml:"Date,attr"`
	Weaknesses struct {
		Weakness []struct {
			ID   string `xml:"ID,attr"`
			Name string `xml:"Name,attr"`
		} `xml:"Weakness"`
	} `xml:"Weaknesses"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: redirect}
	body, err := fetch(client, catalogURL, mostArchive)
	if err != nil {
		return err
	}
	read, err := catalogIn(body, mostDocument)
	if err != nil {
		return err
	}
	names := namesIn(read)
	// The whole point is that this is not a list somebody typed, so an empty
	// or near-empty answer is a fetch that went wrong rather than a catalog
	// that shrank. Refused rather than committed.
	if len(names) < 500 {
		return fmt.Errorf("the catalog answered with %d weaknesses, which is too few to be it",
			len(names))
	}
	source, err := render(read.Version, read.Date, names)
	if err != nil {
		return err
	}
	if err := os.WriteFile(written, source, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", written, err)
	}
	fmt.Printf("read CWE %s of %s: %d weakness names written to %s\n",
		read.Version, read.Date, len(names), written)
	return nil
}

// namesIn is the catalog's weakness names by identifier.
func namesIn(read *catalog) map[string]string {
	names := map[string]string{}
	for _, one := range read.Weaknesses.Weakness {
		id, name := strings.TrimSpace(one.ID), strings.TrimSpace(one.Name)
		// An entry missing either half is not usable and is not a reason to
		// refuse the rest of a published catalog.
		if id == "" || name == "" {
			continue
		}
		if _, err := strconv.Atoi(id); err != nil {
			continue
		}
		names["CWE-"+id] = name
	}
	return names
}

// redirect follows a redirect only to https, and only a few hops: the names
// read land in published advisories, so a hop to plain http is a hop to
// whoever is on the path.
func redirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refused a redirect to %s, which is not https", req.URL)
	}
	if len(via) >= mostHops {
		return fmt.Errorf("refused a redirect to %s after %d hops", req.URL, len(via))
	}
	return nil
}

// fetch reads the published archive, refusing one larger than most bytes.
func fetch(client *http.Client, url string, most int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ask %s for the catalog: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, most+1))
	if err != nil {
		return nil, fmt.Errorf("read the catalog from %s: %w", url, err)
	}
	if int64(len(body)) > most {
		return nil, fmt.Errorf("%s answered more than %d bytes, which is too large to be the catalog", url, most)
	}
	return body, nil
}

// catalogIn reads the one document inside the archive, refusing one that
// decompresses to more than most bytes.
func catalogIn(body []byte, most int64) (*catalog, error) {
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open the archive: %w", err)
	}
	for _, file := range archive.File {
		if !strings.HasSuffix(strings.ToLower(file.Name), ".xml") {
			continue
		}
		// The archive reader refuses a document that runs past the size it
		// declares, so bounding the declared size bounds what is decoded.
		if file.UncompressedSize64 > math.MaxInt64 || int64(file.UncompressedSize64) > most {
			return nil, fmt.Errorf("%s declares %d bytes, which is too large to be the catalog",
				file.Name, file.UncompressedSize64)
		}
		opened, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s inside the archive: %w", file.Name, err)
		}
		defer func() { _ = opened.Close() }()
		var read catalog
		if err := xml.NewDecoder(opened).Decode(&read); err != nil {
			return nil, fmt.Errorf("read %s: %w", file.Name, err)
		}
		return &read, nil
	}
	return nil, fmt.Errorf("the archive holds no catalog")
}

// render writes the file, sorted by number so that regenerating it produces the
// same bytes and a difference is a change in the catalog.
func render(version, date string, names map[string]string) ([]byte, error) {
	ids := make([]string, 0, len(names))
	for id := range names {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return number(ids[i]) < number(ids[j]) })

	var out strings.Builder
	out.WriteString(provenance.GoHeader(provenance.OwnLicense+" AND "+provenance.CWETerms) + "\n")
	out.WriteString("// Code generated by internal/tools/weakness. DO NOT EDIT.\n//\n")
	out.WriteString("// The names are the Common Weakness Enumeration's, published by The MITRE\n")
	out.WriteString("// Corporation. CWE is a trademark of The MITRE Corporation.\n")
	out.WriteString("// See https://cwe.mitre.org/about/termsofuse.html\n\n")
	out.WriteString("package weakness\n\n")
	fmt.Fprintf(&out, "// Version is the catalog these names were read from.\nconst Version = %q\n\n",
		version)
	fmt.Fprintf(&out, "// Published is the day that catalog was published.\nconst Published = %q\n\n",
		date)
	out.WriteString("// names is every weakness the catalog assigns, by identifier.\n")
	out.WriteString("var names = map[string]string{\n")
	for _, id := range ids {
		fmt.Fprintf(&out, "\t%q: %q,\n", id, names[id])
	}
	out.WriteString("}\n")

	source, err := format.Source([]byte(out.String()))
	if err != nil {
		return nil, fmt.Errorf("format the generated names: %w", err)
	}
	return source, nil
}

// number is the identifier's numeric part, for ordering.
func number(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "CWE-"))
	return n
}
