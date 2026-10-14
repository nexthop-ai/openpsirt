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

// What reading the CVE List's archive is bounded by. The archive is fetched from
// outside, so what it holds is bounded before it is read. What it keeps is
// bounded by what a snapshot holds, so a fetch fails before it replaces a
// snapshot with one no scan could read.
//
// Variables so a test can lower them.
var (
	// mostMembers is far above the 402,541 records the List held on
	// 2026-10-07. Counted from the archive's directory before the archive is
	// opened, because opening it holds an entry in memory for every member.
	mostMembers = 4_000_000
	// largestRecord bounds one record's JSON. The largest on 2026-10-07 is a
	// few hundred kilobytes.
	largestRecord uint64 = 16 << 20
	// largestInner bounds the archive inside the published one, which is
	// written to disk before it is read: 688 MB on 2026-10-07.
	largestInner int64 = 8 << 30
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
//
// A record that cannot be read is left out and named among what is returned
// as skipped. Left out, it narrows nothing, which is the conservative outcome;
// failing the whole archive on it keeps the last snapshot for as long as that
// record stands, and that snapshot goes on closing findings on what records
// said before they changed. The archive fails only where no record in it could
// be read.
func FromArchive(archive, scratch string) ([]Record, time.Time, []error, error) {
	if err := countMembers(archive); err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("open the CVE List archive: %w", err)
	}
	outer, err := zip.OpenReader(archive)
	if err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("open the CVE List archive: %w", err)
	}
	defer func() { _ = outer.Close() }()

	for _, member := range outer.File {
		if path.Base(member.Name) != "cves.zip" {
			continue
		}
		inner, err := unpack(member, scratch)
		if err != nil {
			return nil, time.Time{}, nil, err
		}
		defer func() { _ = os.Remove(inner) }()
		if err := countMembers(inner); err != nil {
			return nil, time.Time{}, nil, fmt.Errorf("open the archive inside the CVE List archive: %w", err)
		}
		held, err := zip.OpenReader(inner)
		if err != nil {
			return nil, time.Time{}, nil,
				fmt.Errorf("open the archive inside the CVE List archive: %w", err)
		}
		defer func() { _ = held.Close() }()
		return records(held.File)
	}
	return records(outer.File)
}

// unpack writes an archive member to scratch and names the file.
func unpack(member *zip.File, scratch string) (string, error) {
	if member.UncompressedSize64 > uint64(largestInner) { //nolint:gosec // G115: a positive bound
		return "", tooLarge(fmt.Sprintf("the archive inside the CVE List archive is larger than %d bytes", largestInner))
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
		err = tooLarge(fmt.Sprintf("the archive inside the CVE List archive is larger than %d bytes", largestInner))
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
		ID      string `json:"cveId"`
		State   string `json:"state"`
		Updated stamp  `json:"dateUpdated"`
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

// stamp is a record's moment of update.
//
// The record format allows a moment written without an offset and defines it
// as UTC. The standard library reads only a moment that carries one.
type stamp time.Time

func (s *stamp) UnmarshalJSON(raw []byte) error {
	var said string
	if err := json.Unmarshal(raw, &said); err != nil {
		return err
	}
	said = strings.TrimSpace(said)
	if said == "" {
		*s = stamp{}
		return nil
	}
	if at, err := time.Parse(time.RFC3339Nano, said); err == nil {
		*s = stamp(at)
		return nil
	}
	at, err := time.ParseInLocation("2006-01-02T15:04:05.999999999", said, time.UTC)
	if err != nil {
		return fmt.Errorf("a moment of update reading %q: %w", said, err)
	}
	*s = stamp(at)
	return nil
}

// records reads every record file among an archive's members and keeps those
// that can narrow a match, in identifier order, naming each record it could
// not read.
func records(members []*zip.File) ([]Record, time.Time, []error, error) {
	if len(members) > mostMembers {
		return nil, time.Time{}, nil,
			tooLarge(fmt.Sprintf("the CVE List archive holds more than %d files", mostMembers))
	}
	var kept []Record
	var count sized
	var taken time.Time
	var skipped []error
	read := 0
	for _, member := range members {
		name := path.Base(member.Name)
		if !strings.HasPrefix(name, "CVE-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		read++
		record, updated, keep, err := readRecord(member)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("read %s from the CVE List archive: %w", name, err))
			continue
		}
		// Every record read, kept or not and withdrawn or not: a record
		// withdrawn or changed so it no longer narrows changes what the
		// snapshot does, and the moment has to move with it.
		if updated.After(taken) {
			taken = updated
		}
		if keep {
			// Counted as the snapshot will write it, so what is kept in
			// memory is bounded by what a snapshot holds.
			line, err := json.Marshal(&record)
			if err != nil {
				return nil, time.Time{}, nil, fmt.Errorf("read %s from the CVE List archive: %w", name, err)
			}
			if err := count.add(record.ID, len(line)+1); err != nil {
				return nil, time.Time{}, nil, err
			}
			kept = append(kept, record)
		}
	}
	if read == 0 {
		return nil, time.Time{}, nil, errors.New("the CVE List archive holds no records")
	}
	if len(skipped) == read {
		return nil, time.Time{}, nil, fmt.Errorf("no record in the CVE List archive could be "+
			"read, the first: %w", skipped[0])
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].ID < kept[j].ID })
	return kept, taken, skipped, nil
}

// readRecord reads one record, and says whether it is one to keep.
func readRecord(member *zip.File) (Record, time.Time, bool, error) {
	if member.UncompressedSize64 > largestRecord {
		return Record{}, time.Time{}, false, tooLarge(fmt.Sprintf("larger than %d bytes", largestRecord))
	}
	opened, err := member.Open()
	if err != nil {
		return Record{}, time.Time{}, false, err
	}
	defer opened.Close()
	var doc published
	//nolint:gosec // G115: a positive bound far below the largest int64
	if err := json.NewDecoder(io.LimitReader(opened, int64(largestRecord))).Decode(&doc); err != nil {
		return Record{}, time.Time{}, false, err
	}
	updated := time.Time(doc.Metadata.Updated)
	if !strings.EqualFold(doc.Metadata.State, "PUBLISHED") {
		return Record{}, updated, false, nil
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
	return record, updated, keep && record.ID != "", nil
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
		if commitRange(line) {
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
	if !strings.EqualFold(line.Status, "unaffected") || !ordered(line) || line.Changes {
		return false
	}
	_, ok := vercmp.Order(vercmp.Semantic, line.Version, line.Version)
	return ok
}
