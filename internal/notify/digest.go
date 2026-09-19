package notify

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Digest is what one person is told daily, assembled but not yet carried.
//
// Two lists and a count, which is the whole of the digest carrying what
// nothing else told you to counts for what is undisclosed: work that became
// theirs without a message, findings nobody owns where they asked for them,
// and — for anything nobody has announced — numbers rather than names.
type Digest struct {
	// Mine is work assigned to them that produced no message of its own.
	Mine []Item
	// Unowned is what arrived since the last digest and nobody has picked up.
	Unowned []Item
	// Withheld counts what is not named, and says how urgent it is.
	Withheld Withheld
	// HeldTotal and UnownedTotal are how many rows each half has in all,
	// which is not how many the digest took: the walk is bounded, and a
	// bounded list rendered as a flat statement of fact tells somebody
	// holding four hundred things that they hold fifty.
	HeldTotal    int
	UnownedTotal int
}

// Item is one piece of work, as a digest names it.
type Item struct {
	Issue     string
	Component string
	Version   string
	Severity  string
	Product   string
	Build     string
	Exploited bool
}

// Withheld is what an undisclosed finding contributes: how many, how bad, and
// how late — and nothing that says which one or where.
type Withheld struct {
	Count      int
	BySeverity map[string]int
	Exploited  int
	// Unowned counts those nobody has picked up, which is the one that says
	// somebody has to do something rather than merely know.
	Unowned int
}

// Empty reports whether there is anything worth sending.
//
// A digest with nothing in it is not sent. A daily message that says "nothing"
// is how somebody learns to stop opening the daily message, and then the ones
// that say something go unread with it.
func (d Digest) Empty() bool {
	return len(d.Mine) == 0 && len(d.Unowned) == 0 && d.Withheld.Count == 0
}

// Message renders the digest for a channel.
func (d Digest) Message(baseURL string) Message {
	var text strings.Builder
	if len(d.Mine) > 0 {
		fmt.Fprintf(&text, "%s assigned to you that you have not been told about:\n\n",
			count(len(d.Mine), "piece of work", "pieces of work"))
		writeItems(&text, d.Mine)
		text.WriteString(more(len(d.Mine)+d.Withheld.Count-d.Withheld.Unowned, d.HeldTotal))
	}
	if len(d.Unowned) > 0 {
		if text.Len() > 0 {
			text.WriteString("\n")
		}
		fmt.Fprintf(&text, "%s arrived since the last digest and nobody owns:\n\n",
			count(len(d.Unowned), "finding", "findings"))
		writeItems(&text, d.Unowned)
		text.WriteString(more(len(d.Unowned)+d.Withheld.Unowned, d.UnownedTotal))
	}
	if d.Withheld.Count > 0 {
		if text.Len() > 0 {
			text.WriteString("\n")
		}
		text.WriteString(d.Withheld.said())
	}
	if where := link(baseURL, "/"); where != "" {
		text.WriteString("\n" + where + "\n")
	}
	return Message{Subject: "Your daily digest", Text: text.String()}
}

// more says that a list is a part of something larger, where it is.
//
// A bounded walk rendered as a flat count is a message that says somebody
// holds fifty things when they hold four hundred — and they cannot tell the
// two apart from the message, which is the whole failure. Empty where nothing
// was cut, so an ordinary digest gains no line.
func more(shown, total int) string {
	if total <= shown {
		return ""
	}
	return fmt.Sprintf("\n%d of %d are listed. The rest are in the tool.\n", shown, total)
}

// said renders the part that names nothing.
//
// Severity and lateness rather than a bare number: "three undisclosed" does
// not say whether to open the tool now or after coffee, and a channel that
// cannot answer that is one people stop reading. Neither says which finding,
// which product or which build — a mail server has no business holding any of
// that .
func (w Withheld) said() string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s not named here, because %s not been disclosed",
		count(w.Count, "finding is", "findings are"),
		map[bool]string{true: "it has", false: "they have"}[w.Count == 1])
	out.WriteString(".\n")

	var parts []string
	for _, severity := range finding.Bands() {
		if n := w.BySeverity[severity]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, severity))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&out, "By severity: %s.\n", strings.Join(parts, ", "))
	}
	if w.Exploited > 0 {
		fmt.Fprintf(&out, "%d known to be exploited.\n", w.Exploited)
	}
	if w.Unowned > 0 {
		fmt.Fprintf(&out, "%d that nobody owns.\n", w.Unowned)
	}
	return out.String()
}

func writeItems(out *strings.Builder, items []Item) {
	for _, it := range items {
		fmt.Fprintf(out, "  %s in %s %s", it.Issue, it.Component, it.Version)
		if it.Severity != "" {
			fmt.Fprintf(out, " (%s", it.Severity)
			if it.Exploited {
				out.WriteString(", exploited")
			}
			out.WriteString(")")
		}
		fmt.Fprintf(out, " — %s %s\n", it.Product, it.Build)
	}
}

// count renders a number with the word that agrees with it.
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Assemble builds one person's digest.
//
// Read as that person rather than as whoever is sweeping: every query narrows
// by the subject it is handed, so a digest cannot contain something its reader
// could not open. The sweep holds no rights of its own and needs none.
func Assemble(ctx context.Context, db *bun.DB, person *access.Account, most int) (Digest, error) {
	var digest Digest
	if person == nil || person.ID == 0 {
		return digest, nil
	}
	subject, err := access.NewStore(db).Resolve(ctx, person.Identity)
	if err != nil {
		return digest, fmt.Errorf("read what %q may see: %w", person.Identity, err)
	}
	findings := finding.NewStore(db)

	// What became theirs without a message. Everything they hold, less the
	// things a notification already told them about — which is the whole
	// of "carries what nothing else told you".
	//
	// Theirs *and their teams'*: work routed to a team arrives without a
	// message by design — a rule is not a human action, so it is digest
	// content rather than an interruption — which makes this the only
	// place it is ever mentioned.
	told, err := ToldAbout(ctx, db, person.ID)
	if err != nil {
		return digest, err
	}
	// Paged until enough have survived the filter, rather than filtering one
	// page and stopping. What is being answered is "the things nothing else
	// told you about", and the things it told you about are exactly what the
	// filter removes — so a holder with a page's worth of already-told work
	// got an empty digest and was never told about anything behind it,
	// however much there was. Routed work is the case that matters: it is
	// deliberately silent, so the digest is the only place it is ever
	// mentioned.
	//
	// Bounded by pages rather than by rows so a holder of many thousands
	// cannot make one digest walk all of them.
	const mostPages = 20
	taken := 0
	for page := range mostPages {
		held, total, err := findings.AssignedTo(ctx, subject, subject.Mine(),
			finding.Scope{}, most, page*most)
		if err != nil {
			return digest, fmt.Errorf("read what %q holds: %w", person.Identity, err)
		}
		digest.HeldTotal = total
		for _, row := range held {
			if told[Concerning(row.ProductID, row.VulnerabilityID, row.ComponentID)] {
				continue
			}
			digest.take(row)
			taken++
			if taken >= most {
				break
			}
		}
		if taken >= most || len(held) < most {
			break
		}
	}

	// What arrived since the last one and nobody has picked up, for whoever
	// asked for it. A first digest has no "since", and reports nothing here
	// rather than everything ever opened: arriving to a list of eight
	// thousand is the same as arriving to no channel at all.
	if person.DigestUnassigned && person.DigestSentAt != nil {
		unowned, total, err := findings.UnassignedSince(ctx, subject, finding.Scope{},
			*person.DigestSentAt, most)
		if err != nil {
			return digest, fmt.Errorf("read what nobody owns: %w", err)
		}
		digest.UnownedTotal = total
		for _, row := range unowned {
			digest.takeUnowned(row)
		}
	}
	return digest, nil
}

// take adds a piece of the reader's own work, named or counted.
func (d *Digest) take(row finding.Owned) {
	if row.Undisclosed {
		d.Withheld.add(row, false)
		return
	}
	d.Mine = append(d.Mine, itemOf(row))
}

// takeUnowned adds a piece nobody holds, named or counted.
func (d *Digest) takeUnowned(row finding.Owned) {
	if row.Undisclosed {
		d.Withheld.add(row, true)
		return
	}
	d.Unowned = append(d.Unowned, itemOf(row))
}

func (w *Withheld) add(row finding.Owned, unowned bool) {
	if w.BySeverity == nil {
		w.BySeverity = map[string]int{}
	}
	w.Count++
	if row.Severity != "" {
		w.BySeverity[strings.ToLower(row.Severity)]++
	}
	if row.Exploited {
		w.Exploited++
	}
	if unowned {
		w.Unowned++
	}
}

func itemOf(row finding.Owned) Item {
	return Item{
		Issue: row.Vulnerability, Component: row.Component, Version: row.Version,
		Severity: row.Severity, Product: row.Product,
		Build: row.Stream + " " + row.Variant, Exploited: row.Exploited,
	}
}

// ToldAbout is what this person has already been told about individually.
//
// Read once for the whole digest rather than asked per row: a person holding
// two hundred things would otherwise be two hundred queries to answer one
// message.
// Bounded, on a table nothing prunes. Every other read in this package
// carries one, and this had neither a window nor a ceiling: it returned every
// notification a person had ever received, once per person per digest cycle.
func ToldAbout(ctx context.Context, db *bun.DB, personID int64) (map[string]bool, error) {
	var concerns []string
	if err := db.NewSelect().Model((*Notification)(nil)).
		Column("concerns").
		Where("person_id = ?", personID).
		Where("concerns IS NOT NULL AND concerns <> ?", "").
		// Newest first, because a ceiling that cuts the oldest is the right
		// way round: what a digest must not repeat is what somebody was told
		// recently, and a mention from two years ago that reappears once is
		// the lesser fault.
		OrderExpr("id DESC").
		Limit(database.AList.Of(0)).
		Scan(ctx, &concerns); err != nil {
		return nil, fmt.Errorf("read what person %d was told: %w", personID, err)
	}
	told := make(map[string]bool, len(concerns))
	for _, about := range concerns {
		told[about] = true
	}
	return told, nil
}
