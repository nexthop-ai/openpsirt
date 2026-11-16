// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// unreleased is a release date with no value, as a document states one.
const unreleased = "0001-01-01T00:00:00Z"

// SettledDigest is what an advisory document says, hashed: the document as
// written with every object's keys in alphabetical order, less what moves for
// a reason other than what it says.
//
// | Left out | Moves because |
// |---|---|
// | The current release date, stated as no date | Every generation dates the document |
// | The generator | Every generation dates it |
// | The version, the status and the revision history, stated empty | The document went out, or its agreement moved |
// | The references of category "self" | Where the document sits, not what it says; kept, a deployment starting a directory reads every past issuance as changed |
//
// The digest is taken from the bytes, so an issued document's stored text and
// the document generated now are hashed by one rule. Numbers keep the text
// they were written as.
func SettledDigest(body []byte) (string, error) {
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
		tracking["current_release_date"] = unreleased
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
