// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// mentionTarget is the subject of a piece of text, for deciding who may be
// told they were named in it.
//
// The four things that decide it, rather than the row one of the callers
// happens to hold. A mention in a claim's comment is about a place and a
// mention in an issue's note is about an issue in a product, and both resolve
// to one set: the names typed that may read the thing being written about, at
// its visibility.
type mentionTarget struct {
	ProductID       int64
	VulnerabilityID int64
	Visibility      access.Visibility
	// About is the notification's own name for the thing, in a few words: the
	// start of a place identity for a claim, the issue's name for a note.
	About string
}

// mentionCap bounds how many people one piece of text can call for.
//
// A justification naming forty people is not a question for any of them, and
// without a bound one comment is one write per person. Generous enough that
// nobody hits it while writing normally.
const mentionCap = 20

// MentionsBody says which names in a piece of text reached nobody.
//
// Reported rather than refused, and without saying why. The words are
// worth keeping either way, and a comment rejected because one name in it was
// wrong loses the paragraph to fix a word. A name nobody holds and a name held
// by somebody who may not read this are the same answer here, because telling
// them apart would answer "can this person see undisclosed work" one comment
// at a time.
type MentionsBody struct {
	NotNotified []string `json:"not_notified,omitempty" doc:"Names written after an @ that reached nobody. Either no such person is recorded, or they cannot read what the text is about — deliberately not said which"`
}

// tellMentioned tells whoever a decision's new text named.
//
// The decision is read back rather than carried out of the write, because the
// notification's own fields — the product, the issue, the disclosure — are what
// the reader is authorized against, and reading it through the same store the
// write went through gives one answer for the reader's reach.
//
// Failing to tell somebody never fails the write. The words are on record by
// the time this runs, and losing a comment because a notification could not be
// stored would be sacrificing the wrong half.
func tellMentioned(ctx context.Context, in Ingest, subject access.Subject,
	store *triage.Store, claimID int64, body string) []string {

	if len(markdown.Mentions(body)) == 0 {
		return nil
	}
	// Any row of the claim answers for what the text is about: a claim is one
	// action in one product, and who may be told is decided at the visibility
	// of what it is about. The first row is the one every other reader of the
	// claim is shown as its representative.
	_, rows, err := store.ReadClaim(ctx, subject, claimID)
	if err != nil || len(rows) == 0 {
		in.logger().WarnContext(ctx, "could not tell who was named", "error", err)
		return nil
	}
	dropped, err := mentioned(ctx, in, subject, mentionTarget{
		ProductID:       rows[0].ProductID,
		VulnerabilityID: rows[0].VulnerabilityID,
		Visibility:      rows[0].Visibility,
		About:           rows[0].PlaceIdentity[:min(8, len(rows[0].PlaceIdentity))],
	}, body, fmt.Sprintf("/claims/%d", claimID))
	if err != nil {
		in.logger().WarnContext(ctx, "could not tell who was named", "error", err)
	}
	return dropped
}

// mentioned tells whoever a piece of text named that it named them.
//
// Only people who could already read it. The set is exactly the set the
// editor offers, from the same query, so a mention cannot tell somebody that a
// finding exists when they may not see it — on an undisclosed one the
// notification itself would be the disclosure.
//
// Never the author. Somebody writing their own name is not asking
// themselves a question, and a tool that tells you what you just typed is one
// people stop reading.
//
// Failing to tell somebody is not failing to save the text. The words are on
// record by the time this runs, and losing a comment because a notification
// could not be written would be the wrong half to sacrifice — so this reports
// and the caller logs. It returns the names that reached nobody, so the caller
// can say so.
//
// Reached nobody, without saying why. A name nobody holds and a name held
// by somebody who may not read this stay indistinguishable, because telling
// them apart would answer "can this person see undisclosed work" one comment
// at a time. The author is told the mention did not land, which is what they
// can act on — and it discloses nothing they could not already
// learn by asking who may be mentioned here, which they may, because they can
// read the thing they are writing about.
//
// Reported rather than refused. The words are worth keeping either way, and a
// comment rejected because one name in it was wrong loses the paragraph to fix
// a word.
func mentioned(ctx context.Context, in Ingest, subject access.Subject,
	about mentionTarget, body, link string) ([]string, error) {

	names := markdown.Mentions(body)
	if len(names) == 0 {
		return nil, nil
	}
	// Reported rather than discarded, in both directions. A name past the cap
	// and a name written where there is no product to read them against are
	// both names that reached nobody, which is what this answer is for — and
	// without it the author is told every mention landed.
	if about.ProductID == 0 {
		return names, nil
	}
	var dropped []string
	if len(names) > mentionCap {
		dropped = append(dropped, names[mentionCap:]...)
		names = names[:mentionCap]
	}

	// The names typed that may read this, at the visibility of the thing the
	// text is about. Asked of the same rule the editor's list uses rather than
	// spelled again here, so the two cannot come to disagree about who may be
	// named — and asked about these names rather than by paging that list,
	// which answers from the alphabetically-first hundred readers and silently
	// reaches nobody sorting past them.
	readers, err := access.NewStore(in.DB.DB).ReadersNamed(ctx, subject,
		about.ProductID, about.Visibility, names)
	if err != nil {
		return nil, fmt.Errorf("read who may be told: %w", err)
	}
	byName := make(map[string]int64, len(readers))
	for _, reader := range readers {
		byName[strings.ToLower(reader.Identity)] = reader.ID
	}

	told := map[int64]bool{subject.ID: true}
	for _, name := range names {
		who, known := byName[strings.ToLower(name)]
		// A name nobody holds, and a name held by somebody who may not read
		// this, are both simply not told — and they are not told apart. A
		// refusal naming which it was would answer, one comment at a time,
		// whether a given person can see undisclosed work.
		if !known {
			dropped = append(dropped, name)
			continue
		}
		if told[who] {
			continue
		}
		told[who] = true
		if err := notify.NewStore(in.DB.DB).Tell(ctx, notify.Telling{
			PersonID: who, Kind: notify.Mentioned,
			Body: fmt.Sprintf("%s named you in a note on %s.",
				whoever(subject), about.About),
			Link:     link,
			Private:  about.Visibility == access.Private,
			Concerns: notify.Concerning(about.ProductID, about.VulnerabilityID, 0),
			// The same two as columns. Concerns is a string a digest
			// matches on; these are what a read narrows by, and a
			// narrowing cannot rest on a shape another pass invented.
			ProductID:       &about.ProductID,
			VulnerabilityID: &about.VulnerabilityID,
		}); err != nil {
			return dropped, fmt.Errorf("tell %d they were named: %w", who, err)
		}
	}
	return dropped, nil
}

// whoever is the name for the person who wrote the text.
func whoever(subject access.Subject) string {
	if name := strings.TrimSpace(subject.Identity); name != "" {
		return name
	}
	return "Somebody"
}
