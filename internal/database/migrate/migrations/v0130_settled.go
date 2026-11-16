// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// settledDigestV0130 is the settled digest of an advisory document as v0.13.0
// takes it: the document with every object's keys in alphabetical order, its
// current release date stated as no date, its generator left out, its
// version, status and revision history stated empty, and its references of
// category "self" left out. Numbers keep the text they were written as.
//
// The upgrade carries its own copy of the rule, so a later change to the
// application's leaves what the upgrade wrote as it was; a test holds the
// copy to the application's.
func settledDigestV0130(body []byte) (string, error) {
	reader := json.NewDecoder(bytes.NewReader(body))
	reader.UseNumber()
	var whole map[string]any
	if err := reader.Decode(&whole); err != nil {
		return "", fmt.Errorf("read the document to hash: %w", err)
	}
	meta, ok := whole["document"].(map[string]any)
	if !ok {
		return "", errors.New("the document to hash has no document part")
	}
	if references, ok := meta["references"].([]any); ok {
		kept := make([]any, 0, len(references))
		for _, each := range references {
			if one, ok := each.(map[string]any); ok && one["category"] == "self" {
				continue
			}
			kept = append(kept, each)
		}
		if len(kept) == 0 {
			delete(meta, "references")
		} else {
			meta["references"] = kept
		}
	}
	if tracking, ok := meta["tracking"].(map[string]any); ok {
		tracking["current_release_date"] = "0001-01-01T00:00:00Z"
		delete(tracking, "generator")
		tracking["version"] = ""
		tracking["status"] = ""
		tracking["revision_history"] = nil
	}
	settled, err := json.Marshal(whole)
	if err != nil {
		return "", fmt.Errorf("hash the document: %w", err)
	}
	sum := sha256.Sum256(settled)
	return hex.EncodeToString(sum[:]), nil
}
