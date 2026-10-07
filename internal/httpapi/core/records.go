// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"
	"strings"
)

// RecordLineBody is one version line of a CVE record, beside the entry it
// belongs to.
type RecordLineBody struct {
	Entry           string `json:"entry" doc:"The product the record's line is about, as the record names it"`
	Status          string `json:"status" enum:"affected,unaffected" doc:"What the record says of the versions the line covers"`
	Version         string `json:"version" doc:"The first version the line covers, or the one version where it names no bound"`
	LessThan        string `json:"less_than,omitempty" doc:"The version the line stops before"`
	LessThanOrEqual string `json:"less_than_or_equal,omitempty" doc:"The last version the line covers. A trailing * covers every version beginning with what precedes it"`
}

// RecordLines reads the lines a finding was closed as unaffected by, as the
// store keeps them. Lines that cannot be read are none rather than a failure:
// the closure stands whether or not its evidence can be shown.
func RecordLines(stored string) []RecordLineBody {
	if strings.TrimSpace(stored) == "" {
		return nil
	}
	var lines []struct {
		Entry           string `json:"entry"`
		Status          string `json:"status"`
		Version         string `json:"version"`
		LessThan        string `json:"lessThan"`
		LessThanOrEqual string `json:"lessThanOrEqual"`
	}
	if err := json.Unmarshal([]byte(stored), &lines); err != nil {
		return nil
	}
	out := make([]RecordLineBody, 0, len(lines))
	for _, l := range lines {
		out = append(out, RecordLineBody{
			Entry: l.Entry, Status: strings.ToLower(l.Status), Version: l.Version,
			LessThan: l.LessThan, LessThanOrEqual: l.LessThanOrEqual,
		})
	}
	return out
}

// Said is a line as a sentence, for a file rather than a screen: "Linux Linux
// unaffected from 6.18.27 to 6.18.*".
func (l RecordLineBody) Said() string {
	var out strings.Builder
	out.WriteString(strings.TrimSpace(l.Entry + " " + l.Status))
	switch {
	case l.LessThan != "":
		out.WriteString(" from " + l.Version + " before " + l.LessThan)
	case l.LessThanOrEqual != "":
		out.WriteString(" from " + l.Version + " to " + l.LessThanOrEqual)
	default:
		out.WriteString(" at " + l.Version)
	}
	return out.String()
}
