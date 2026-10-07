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
// The moment returned is the newest any kept record was updated, which is what
// the snapshot describes.
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
type published struct {
	Metadata struct {
		ID      string    `json:"cveId"`
		State   string    `json:"state"`
		Updated time.Time `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Affected []struct {
				Entry
				Versions []struct {
					Line
					Changes json.RawMessage `json:"changes"`
				} `json:"versions"`
			} `json:"affected"`
		} `json:"cna"`
	} `json:"containers"`
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
		if !keep {
			continue
		}
		kept = append(kept, record)
		if updated.After(taken) {
			taken = updated
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
		return Record{}, time.Time{}, false, nil
	}
	record := Record{ID: strings.TrimSpace(doc.Metadata.ID)}
	keep := false
	for _, stated := range doc.Containers.CNA.Affected {
		entry := stated.Entry
		entry.Versions = nil
		for _, version := range stated.Versions {
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
				keep = true
			}
		}
		record.Affected = append(record.Affected, entry)
	}
	return record, doc.Metadata.Updated, keep && record.ID != "", nil
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
