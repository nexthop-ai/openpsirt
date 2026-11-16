// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// identifyingBatchV0130 is how many components one read of the identifying
// step takes.
const identifyingBatchV0130 = 5_000

// componentV0130 is v0.13.0's declaration of the component table.
//
// The baseline's, with the identifying name folded where the name holds the
// component's own version.
func componentV0130(t *columnTypes) []string {
	statements := append([]string(nil), componentBaseline(t)...)
	statements[0] = withColumn(statements[0], `"license"            `+t.free+` NULL,`,
		`-- The name with its own version taken out, folded, where the
			-- name holds that version: what a count across versions groups
			-- on. Null where the name holds no version, which reads the
			-- folded name.
			"identifying_folded" `+t.name+` NULL,`)
	return statements
}

// componentIdentifyingV0130 adds the column holding a component's identifying
// name folded. The identifying step fills it.
func componentIdentifyingV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("component", "identifying_folded")
	if err != nil || present {
		return err
	}
	return u.change(componentV0130(u.t), change{table: "component",
		add: []added{{column: "identifying_folded"}}})
}

// occurrenceIdentifyingV0130 keys every occurrence of a component whose name
// holds its own version as v0.13.0 keys it: by the name with that version
// taken out. A finding's occurrence is rewritten where it holds the key
// v0.12.0 made from the two names, and a decision occurrence follows the
// occurrence its findings moved to, so a decision made before the upgrade
// reaches the component at its next version.
//
// Two live decisions at one product, issue and occurrence that agree on their
// versions, or both stand at any version, become one key: the approved one
// stands over a proposed one, otherwise the newer, and the other lapses.
//
// A row whose stored key is not the one its names make is left alone: a code
// finding's occurrence is minted from its series. A key v0.12.0 made that
// v0.13.0 reads as two occurrences leaves the decision occurrences at it as
// they are: one name held at a version it carries and at one it does not,
// which a finding still holds once the findings are rewritten, or at two
// versions carrying different releases, which the findings left for two keys.
//
// Each such component stores its identifying name folded.
//
// The rewrite reads nothing it wrote, so a start after one that stopped finds
// every key it rewrote already v0.13.0's and rewrites nothing twice.
func occurrenceIdentifyingV0130(ctx context.Context, tx bun.Tx) error {
	named, renamed, err := identifyingComponentsV0130(ctx, tx)
	if err != nil || len(renamed) == 0 {
		return err
	}
	for _, id := range renamed {
		if _, err := tx.NewUpdate().TableExpr(`"component"`).
			Set(`"identifying_folded" = ?`, foldedV0130(named[id].identifying)).
			Where(`"id" = ?`, id).Exec(ctx); err != nil {
			return fmt.Errorf("store the identifying name of component %d: %w", id, err)
		}
	}
	sitting, err := occurrencesAtV0130(ctx, tx, renamed)
	if err != nil {
		return err
	}
	if err := namedComponentsV0130(ctx, tx, named, sitting); err != nil {
		return err
	}
	moved := map[string][]string{}
	for _, at := range sitting {
		component := named[at.Component]
		var consumer namedComponentV0130
		if at.Consumer != nil {
			consumer = named[*at.Consumer]
		}
		before := occurrenceIdentityV0130(component.name, consumer.name)
		if at.Occurrence != before {
			continue
		}
		after := occurrenceIdentityV0130(component.identifying, consumer.identifying)
		if after == before {
			continue
		}
		q := tx.NewUpdate().TableExpr(`"finding"`).
			Set(`"occurrence_identity" = ?`, after).
			Where(`"occurrence_identity" = ?`, before).
			Where(`"component_id" = ?`, at.Component)
		if at.Consumer == nil {
			q = q.Where(`"consumer_id" IS NULL`)
		} else {
			q = q.Where(`"consumer_id" = ?`, *at.Consumer)
		}
		if _, err := q.Exec(ctx); err != nil {
			return fmt.Errorf("key the findings of component %d by its identifying name: %w", at.Component, err)
		}
		if !slices.Contains(moved[before], after) {
			moved[before] = append(moved[before], after)
		}
	}
	return decisionsIdentifyingV0130(ctx, tx, moved)
}

// namedComponentV0130 is a component's name and the name it is identified by.
type namedComponentV0130 struct{ name, identifying string }

// identifyingComponentsV0130 reads every component, and returns those whose
// name holds their own version, by identifier, with their names.
func identifyingComponentsV0130(ctx context.Context, tx bun.Tx) (map[int64]namedComponentV0130, []int64, error) {
	named := map[int64]namedComponentV0130{}
	var renamed []int64
	for after := int64(0); ; {
		var rows []struct {
			ID      int64  `bun:"id"`
			Name    string `bun:"name"`
			Version string `bun:"version"`
			Purl    string `bun:"purl"`
		}
		if err := tx.NewSelect().TableExpr(`"component"`).
			ColumnExpr(`"id", "name", "version", COALESCE("purl", '') AS "purl"`).
			Where(`"id" > ?`, after).OrderExpr(`"id"`).Limit(identifyingBatchV0130).
			Scan(ctx, &rows); err != nil {
			return nil, nil, fmt.Errorf("read the components whose names hold their versions: %w", err)
		}
		for _, row := range rows {
			after = row.ID
			name := strings.TrimSpace(row.Name)
			identifying := identifyingNameV0130(name, row.Version, row.Purl)
			if identifying != name {
				named[row.ID] = namedComponentV0130{name, identifying}
				renamed = append(renamed, row.ID)
			}
		}
		if len(rows) < identifyingBatchV0130 {
			return named, renamed, nil
		}
	}
}

// sittingV0130 is one key findings hold for a component under a consumer.
type sittingV0130 struct {
	Component  int64  `bun:"component_id"`
	Consumer   *int64 `bun:"consumer_id"`
	Occurrence string `bun:"occurrence_identity"`
}

// occurrencesAtV0130 is every key a finding holds for these components, or
// for anything under them.
func occurrencesAtV0130(ctx context.Context, tx bun.Tx, components []int64) ([]sittingV0130, error) {
	type key struct {
		component, consumer int64
		occurrence          string
	}
	seen := map[key]bool{}
	var out []sittingV0130
	for _, column := range []string{"component_id", "consumer_id"} {
		for start := 0; start < len(components); start += database.BatchSize {
			batch := components[start:min(start+database.BatchSize, len(components))]
			var rows []sittingV0130
			if err := tx.NewSelect().TableExpr(`"finding"`).
				ColumnExpr(`"component_id", "consumer_id", "occurrence_identity"`).
				Where(`? IN (?)`, bun.Ident(column), bun.List(batch)).
				Distinct().
				Scan(ctx, &rows); err != nil {
				return nil, fmt.Errorf("read where the components whose names hold their versions sit: %w", err)
			}
			for _, row := range rows {
				// No component is numbered zero, so it stands for none.
				k := key{component: row.Component, occurrence: row.Occurrence}
				if row.Consumer != nil {
					k.consumer = *row.Consumer
				}
				if !seen[k] {
					seen[k] = true
					out = append(out, row)
				}
			}
		}
	}
	return out, nil
}

// namedComponentsV0130 adds to named every component the occurrences name that
// it does not hold, each identified by its name as it is.
func namedComponentsV0130(ctx context.Context, tx bun.Tx, named map[int64]namedComponentV0130,
	sitting []sittingV0130) error {
	var wanted []int64
	asked := map[int64]bool{}
	for _, at := range sitting {
		for _, id := range []*int64{&at.Component, at.Consumer} {
			if id == nil {
				continue
			}
			if _, held := named[*id]; !held && !asked[*id] {
				asked[*id] = true
				wanted = append(wanted, *id)
			}
		}
	}
	for start := 0; start < len(wanted); start += database.BatchSize {
		var rows []struct {
			ID   int64  `bun:"id"`
			Name string `bun:"name"`
		}
		if err := tx.NewSelect().TableExpr(`"component"`).ColumnExpr(`"id", "name"`).
			Where(`"id" IN (?)`, bun.List(wanted[start:min(start+database.BatchSize, len(wanted))])).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read what the components whose names hold their versions sit under: %w", err)
		}
		for _, row := range rows {
			name := strings.TrimSpace(row.Name)
			named[row.ID] = namedComponentV0130{name, name}
		}
	}
	return nil
}

// liveDecisionV0130 is a decision occurrence at an occurrence the step moves.
type liveDecisionV0130 struct {
	ID         int64     `bun:"id"`
	Product    int64     `bun:"product_id"`
	Issue      int64     `bun:"issue_id"`
	Occurrence string    `bun:"occurrence_identity"`
	Component  *string   `bun:"component_upstream_version"`
	Consumer   *string   `bun:"consumer_upstream_version"`
	State      string    `bun:"state"`
	ProposedAt time.Time `bun:"proposed_at"`
	LiveKey    *string   `bun:"live_key"`
	Outcome    string    `bun:"outcome"`
}

// outranks is whether one live decision stands over another: approved over
// proposed, and otherwise the newer.
func (d liveDecisionV0130) outranks(other liveDecisionV0130) bool {
	if (d.State == "approved") != (other.State == "approved") {
		return d.State == "approved"
	}
	if !d.ProposedAt.Equal(other.ProposedAt) {
		return d.ProposedAt.After(other.ProposedAt)
	}
	return d.ID > other.ID
}

// decisionsIdentifyingV0130 moves the decision occurrences at each key findings
// moved from to the one key they moved to, and keys the live ones anew.
func decisionsIdentifyingV0130(ctx context.Context, tx bun.Tx, moved map[string][]string) error {
	var from []string
	for before, after := range moved {
		if len(after) == 1 {
			from = append(from, before)
		}
	}
	slices.Sort(from)
	// A key a finding still holds once the findings are rewritten was made
	// from a name that does not carry its version there too, so it is split.
	from, err := unheldV0130(ctx, tx, from)
	if err != nil {
		return err
	}
	var decisions []liveDecisionV0130
	for start := 0; start < len(from); start += database.BatchSize {
		var rows []liveDecisionV0130
		if err := tx.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).
			Join(`JOIN "decision" AS "d" ON "d"."id" = "de"."decision_id"`).
			Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "de"."vulnerability_id"`).
			ColumnExpr(`"de"."id", "de"."product_id", "v"."issue_id", "de"."occurrence_identity"`).
			ColumnExpr(`"de"."component_upstream_version", "de"."consumer_upstream_version"`).
			ColumnExpr(`"de"."state", "de"."proposed_at", "de"."live_key", "d"."outcome"`).
			Where(`"de"."occurrence_identity" IN (?)`, bun.List(from[start:min(start+database.BatchSize, len(from))])).
			OrderExpr(`"de"."id"`).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read the decisions at occurrences keyed by a name holding its version: %w", err)
		}
		decisions = append(decisions, rows...)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	standing := map[string]liveDecisionV0130{}
	var lapsed []int64
	for _, d := range decisions {
		d.Occurrence = moved[d.Occurrence][0]
		if _, err := tx.NewUpdate().TableExpr(`"decision_occurrence"`).
			Set(`"occurrence_identity" = ?`, d.Occurrence).
			Where(`"id" = ?`, d.ID).Exec(ctx); err != nil {
			return fmt.Errorf("move decision occurrence %d to the identifying name: %w", d.ID, err)
		}
		if d.LiveKey == nil {
			continue
		}
		key := liveKeyV0130(d)
		other, taken := standing[key]
		switch {
		case !taken:
			standing[key] = d
		case d.outranks(other):
			standing[key] = d
			lapsed = append(lapsed, other.ID)
		default:
			lapsed = append(lapsed, d.ID)
		}
	}
	// Lapsed before any key is written, so no key is held twice in between.
	for _, id := range lapsed {
		if _, err := tx.NewUpdate().TableExpr(`"decision_occurrence"`).
			Set(`"state" = ?`, "lapsed").Set(`"ended_at" = ?`, now).Set(`"live_key" = NULL`).
			Where(`"id" = ?`, id).Exec(ctx); err != nil {
			return fmt.Errorf("lapse decision occurrence %d, which another stands over: %w", id, err)
		}
	}
	keys := make([]string, 0, len(standing))
	for key := range standing {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if _, err := tx.NewUpdate().TableExpr(`"decision_occurrence"`).
			Set(`"live_key" = ?`, key).
			Where(`"id" = ?`, standing[key].ID).Exec(ctx); err != nil {
			return fmt.Errorf("key decision occurrence %d by the identifying name: %w", standing[key].ID, err)
		}
	}
	return nil
}

// unheldV0130 is the keys of from that no finding holds.
func unheldV0130(ctx context.Context, tx bun.Tx, from []string) ([]string, error) {
	held := map[string]bool{}
	for start := 0; start < len(from); start += database.BatchSize {
		var rows []string
		if err := tx.NewSelect().TableExpr(`"finding"`).ColumnExpr(`"occurrence_identity"`).
			Where(`"occurrence_identity" IN (?)`, bun.List(from[start:min(start+database.BatchSize, len(from))])).
			Distinct().
			Scan(ctx, &rows); err != nil {
			return nil, fmt.Errorf("read which keys findings still hold under a name holding its version: %w", err)
		}
		for _, key := range rows {
			held[key] = true
		}
	}
	out := from[:0]
	for _, key := range from {
		if !held[key] {
			out = append(out, key)
		}
	}
	return out, nil
}

// liveKeyV0130 is the key a live decision occurrence holds: the product, the
// issue it is read as, the occurrence, and both upstream versions it was made
// against, or the occurrence alone where its outcome stands at any version.
func liveKeyV0130(d liveDecisionV0130) string {
	parts := []string{strconv.FormatInt(d.Product, 10), strconv.FormatInt(d.Issue, 10), d.Occurrence}
	switch d.Outcome {
	case "mismatched", "dismissed", "not-security", "confirmed":
	default:
		var component, consumer string
		if d.Component != nil {
			component = *d.Component
		}
		if d.Consumer != nil {
			consumer = *d.Consumer
		}
		parts = append(parts, strings.TrimSpace(component), strings.TrimSpace(consumer))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// occurrenceIdentityV0130 keys a component under the thing that pulled it in,
// or alone where nothing named did.
func occurrenceIdentityV0130(component, consumer string) string {
	basis := strings.TrimSpace(component)
	if c := strings.TrimSpace(consumer); c != "" {
		basis = c + "\x00" + basis
	}
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// identifyingNameV0130 is a name with every place it states its own release,
// as a whole token, replaced by a character no stored name holds. A name that
// is its release alone keeps it.
func identifyingNameV0130(name, version, purl string) string {
	name = strings.TrimSpace(name)
	release := releaseV0130(ecosystemV0130(purl), version)
	if release == "" || release == name || !strings.Contains(name, release) {
		return name
	}
	var out strings.Builder
	written, from := 0, 0
	for {
		at := strings.Index(name[from:], release)
		if at < 0 {
			break
		}
		at += from
		end := at + len(release)
		if !tokenV0130(name[:at], name[end:]) {
			_, width := utf8.DecodeRuneInString(name[at:])
			from = at + width
			continue
		}
		out.WriteString(name[written:at])
		out.WriteString("\x01")
		written, from = end, end
	}
	if written == 0 {
		return name
	}
	out.WriteString(name[written:])
	return out.String()
}

// tokenV0130 is whether no letter or digit runs into a match from either side.
func tokenV0130(before, after string) bool {
	alphanumeric := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
	if last, _ := utf8.DecodeLastRuneInString(before); before != "" && alphanumeric(last) {
		return false
	}
	if first, _ := utf8.DecodeRuneInString(after); after != "" && alphanumeric(first) {
		return false
	}
	if trimmed, dot := strings.CutSuffix(before, "."); dot {
		if last, _ := utf8.DecodeLastRuneInString(trimmed); trimmed != "" && unicode.IsDigit(last) {
			return false
		}
	}
	if trimmed, dot := strings.CutPrefix(after, "."); dot {
		if first, _ := utf8.DecodeRuneInString(trimmed); trimmed != "" && unicode.IsDigit(first) {
			return false
		}
	}
	return true
}

// ecosystemV0130 is the type a package identifier names, unescaped, without
// control characters or surrounding space, lowercased, or nothing where it
// names none.
func ecosystemV0130(purl string) string {
	body, _, _ := strings.Cut(strings.TrimSpace(purl), "#")
	body, _, _ = strings.Cut(body, "?")
	scheme, rest, found := strings.Cut(body, ":")
	if !found || !strings.EqualFold(scheme, "pkg") {
		return ""
	}
	kind, _, _ := strings.Cut(strings.Trim(rest, "/"), "/")
	if decoded, err := url.PathUnescape(kind); err == nil {
		kind = printableV0130(decoded)
	}
	return strings.ToLower(strings.TrimSpace(kind))
}

// foldedV0130 is a name folded as v0.13.0 folds it: trimmed, in lower case,
// and cut to the folded column's width in characters.
func foldedV0130(name string) string {
	folded := strings.ToLower(strings.TrimSpace(name))
	kept := 0
	for at := range folded {
		if kept == database.NameWidth {
			return folded[:at]
		}
		kept++
	}
	return folded
}

// printableV0130 is s without its control characters, every other byte kept,
// a malformed sequence included.
func printableV0130(s string) string {
	var b strings.Builder
	for rest := s; rest != ""; {
		r, size := utf8.DecodeRuneInString(rest)
		if (r == utf8.RuneError && size == 1) || !unicode.IsControl(r) {
			b.WriteString(rest[:size])
		}
		rest = rest[size:]
	}
	return b.String()
}

// releaseV0130 is a version without what its ecosystem's distribution adds:
// an epoch and the part after the last hyphen for Debian, RPM and an
// ecosystem with no version scheme, an Alpine revision, and a PEP 440 local
// label.
func releaseV0130(ecosystem, version string) string {
	v := strings.TrimSpace(version)
	switch ecosystem {
	case "golang", "npm", "cargo", "maven", "nuget":
		return v
	case "apk":
		if at := strings.LastIndex(v, "-r"); at > 0 && digitsV0130(v[at+2:]) {
			return v[:at]
		}
		return v
	case "pypi":
		if before, _, local := strings.Cut(v, "+"); local && before != "" {
			return before
		}
		return v
	}
	rest := v
	if at := strings.Index(rest, ":"); at >= 0 {
		if !digitsV0130(rest[:at]) {
			return v
		}
		rest = rest[at+1:]
	}
	if at := strings.LastIndex(rest, "-"); at >= 0 {
		rest = rest[:at]
	}
	if rest == "" || rest[0] < '0' || rest[0] > '9' {
		return v
	}
	return rest
}

// digitsV0130 is whether s is one or more ASCII digits.
func digitsV0130(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
