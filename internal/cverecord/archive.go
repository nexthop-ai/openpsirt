// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// Bounds on reading the CVE List's archive. The archive is fetched from
// outside, so what it holds is bounded before it is read.
const (
	// mostMembers is far above the 402,541 records the List held on
	// 2026-10-07.
	mostMembers = 4_000_000
	// largestRecord bounds one record's JSON. The largest on 2026-10-07 is a
	// few hundred kilobytes.
	largestRecord = 16 << 20
	// largestInner bounds the archive inside the published one, which is
	// written to disk before it is read: 688 MB on 2026-10-07.
	largestInner = 8 << 30
)

// FromArchive reads the CVE List's published archive and keeps what can narrow
// a match.
//
// The List publishes a daily archive of every record, as a zip holding one
// member, `cves.zip`, which holds a JSON file per record. A zip is read from
// its end, so the inner archive is written to scratch beside the outer one
// before it is read. An archive holding the records directly is read the same
// way without that step.
//
// The moment returned is the newest any record read was updated, withdrawn
// and rejected ones included, which is what the snapshot describes.
func FromArchive(archive, scratch string) ([]Record, time.Time, error) {
	outer, err := zip.OpenReader(archive)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("open the CVE List archive: %w", err)
	}
	defer func() { _ = outer.Close() }()

	for _, member := range outer.File {
		if path.Base(member.Name) != "cves.zip" {
			continue
		}
		inner, err := unpack(member, scratch)
		if err != nil {
			return nil, time.Time{}, err
		}
		defer func() { _ = os.Remove(inner) }()
		held, err := zip.OpenReader(inner)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("open the archive inside the CVE List archive: %w", err)
		}
		defer func() { _ = held.Close() }()
		return records(held.File)
	}
	return records(outer.File)
}

// unpack writes an archive member to scratch and names the file.
func unpack(member *zip.File, scratch string) (string, error) {
	if member.UncompressedSize64 > largestInner {
		return "", fmt.Errorf("the archive inside the CVE List archive is larger than %d bytes", int64(largestInner))
	}
	source, err := member.Open()
	if err != nil {
		return "", fmt.Errorf("open the archive inside the CVE List archive: %w", err)
	}
	defer source.Close()
	target, err := os.CreateTemp(scratch, ".cves-*.zip")
	if err != nil {
		return "", fmt.Errorf("make room for the archive inside the CVE List archive: %w", err)
	}
	written, err := io.Copy(target, io.LimitReader(source, largestInner+1))
	if closed := target.Close(); err == nil {
		err = closed
	}
	if err == nil && written > largestInner {
		err = fmt.Errorf("the archive inside the CVE List archive is larger than %d bytes", int64(largestInner))
	}
	if err != nil {
		_ = os.Remove(target.Name())
		return "", fmt.Errorf("unpack the archive inside the CVE List archive: %w", err)
	}
	return target.Name(), nil
}

// published is the part of a CVE record this reads.
//
// The affected entries of every container: the numbering authority's, and
// each one a third party added beside it. A third party's entry narrows as the
// authority's does, and an affected line in it stops a narrowing as one in the
// authority's would.
type published struct {
	Metadata struct {
		ID      string    `json:"cveId"`
		State   string    `json:"state"`
		Updated time.Time `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA container   `json:"cna"`
		ADP []container `json:"adp"`
	} `json:"containers"`
}

// container is one container of a record, as far as its affected entries.
type container struct {
	Affected []struct {
		Entry
		Versions []struct {
			Line
			Changes json.RawMessage `json:"changes"`
		} `json:"versions"`
	} `json:"affected"`
}

// records reads every record file among an archive's members and keeps those
// that can narrow a match, in identifier order.
func records(members []*zip.File) ([]Record, time.Time, error) {
	if len(members) > mostMembers {
		return nil, time.Time{}, fmt.Errorf("the CVE List archive holds more than %d files", mostMembers)
	}
	var kept []Record
	var taken time.Time
	read := 0
	for _, member := range members {
		name := path.Base(member.Name)
		if !strings.HasPrefix(name, "CVE-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		read++
		record, updated, keep, err := readRecord(member)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("read %s from the CVE List archive: %w", name, err)
		}
		// Every record read, kept or not and withdrawn or not: a record
		// withdrawn or changed so it no longer narrows changes what the
		// snapshot does, and the moment has to move with it.
		if updated.After(taken) {
			taken = updated
		}
		if keep {
			kept = append(kept, record)
		}
	}
	if read == 0 {
		return nil, time.Time{}, errors.New("the CVE List archive holds no records")
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].ID < kept[j].ID })
	return kept, taken, nil
}

// readRecord reads one record, and says whether it is one to keep.
func readRecord(member *zip.File) (Record, time.Time, bool, error) {
	if member.UncompressedSize64 > largestRecord {
		return Record{}, time.Time{}, false, fmt.Errorf("larger than %d bytes", largestRecord)
	}
	opened, err := member.Open()
	if err != nil {
		return Record{}, time.Time{}, false, err
	}
	defer opened.Close()
	var doc published
	if err := json.NewDecoder(io.LimitReader(opened, largestRecord)).Decode(&doc); err != nil {
		return Record{}, time.Time{}, false, err
	}
	if !strings.EqualFold(doc.Metadata.State, "PUBLISHED") {
		return Record{}, doc.Metadata.Updated, false, nil
	}
	record := Record{ID: strings.TrimSpace(doc.Metadata.ID)}
	keep := false
	containers := append([]container{doc.Containers.CNA}, doc.Containers.ADP...)
	for _, stated := range containers {
		for _, entry := range stated.Affected {
			if kept(&record, entry.Entry, entry.Versions) {
				keep = true
			}
		}
	}
	return record, doc.Metadata.Updated, keep && record.ID != "", nil
}

// kept adds one entry to a record, without the lines it never reads, and
// reports whether a line in it could narrow a match.
func kept(record *Record, stated Entry, versions []struct {
	Line
	Changes json.RawMessage `json:"changes"`
}) bool {
	entry := stated
	entry.Versions = nil
	narrows := false
	for _, version := range versions {
		line := version.Line
		line.Changes = len(version.Changes) > 0 && string(version.Changes) != "null" &&
			string(version.Changes) != "[]"
		// Commit ranges say what the release lines beside them say, in
		// terms this does not order, so they are not kept.
		if strings.EqualFold(line.VersionType, "git") ||
			strings.EqualFold(line.VersionType, "original_commit_for_fix") {
			continue
		}
		entry.Versions = append(entry.Versions, line)
		if canNarrow(line) {
			narrows = true
		}
	}
	record.Affected = append(record.Affected, entry)
	return narrows
}

// canNarrow reports whether a line is one that could ever narrow a match: an
// unaffected line in an ordered scheme whose first version can be read.
func canNarrow(line Line) bool {
	if !strings.EqualFold(line.Status, "unaffected") || !orderedType(line.VersionType) || line.Changes {
		return false
	}
	_, ok := vercmp.Order(vercmp.Semantic, line.Version, line.Version)
	return ok
}
