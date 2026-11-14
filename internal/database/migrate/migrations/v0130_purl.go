// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/uptrace/bun"
)

// purlColumnsV0130 is each table and column holding a package identifier as a
// build stated it.
var purlColumnsV0130 = [][2]string{
	{"component", "purl"}, {"graph_node", "purl"}, {"image_version", "purl"}, {"scan", "root_identifier"},
}

// purlBatchV0130 is how many rows one read of the credential step takes.
const purlBatchV0130 = 5_000

// publishedBatchV0130 is how many published documents one read takes. A
// document is a whole body, which can run to megabytes, and a page of them is
// held until it is written.
const publishedBatchV0130 = 50

// purlCredentialsV0130 rewrites the package identifiers v0.12.0 stored as
// v0.13.0 stores them: the slashes after the scheme dropped, and any
// credential and query taken out of the addresses its qualifiers hold. Every
// row holding a question mark, or starting "pkg:/" in any case, is read, and
// the cleaner decides: a filter naming the shapes a credential takes misses
// the next shape. Only a row that changes is written.
//
// The identifiers are read first and written last, with every document
// served to anybody rewritten in between. On MySQL and MariaDB the earlier
// steps' definitions commit on their own, so this step's writes can be cut
// off part way; a start after one stopped before the identifiers were written
// finds them as they were and rewrites the documents again, and one stopped
// after has nothing left in a document to rewrite. No identity is rewritten.
func purlCredentialsV0130(ctx context.Context, tx bun.Tx) error {
	var pass purlPassV0130
	for _, phase := range purlPhasesV0130 {
		if err := phase(ctx, tx, &pass); err != nil {
			return err
		}
	}
	return nil
}

// purlPassV0130 is what one start of the credential step carries from one
// phase to the next: each identifier the cleaning rewrites, beside what it
// becomes.
type purlPassV0130 struct{ cleaned map[string]string }

// purlPhasesV0130 is the credential step in the order it runs: the
// identifiers read, the served documents rewritten, the identifiers written,
// the remotes rewritten.
var purlPhasesV0130 = []func(context.Context, bun.Tx, *purlPassV0130) error{
	func(ctx context.Context, tx bun.Tx, pass *purlPassV0130) (err error) {
		pass.cleaned, err = purlCredentialsInBatchesV0130(ctx, tx, purlBatchV0130, false)
		return err
	},
	func(ctx context.Context, tx bun.Tx, pass *purlPassV0130) error {
		for _, at := range servedDocumentsV0130 {
			if err := servedPurlsV0130(ctx, tx, at[0], at[1], pass.cleaned, publishedBatchV0130); err != nil {
				return err
			}
		}
		return nil
	},
	func(ctx context.Context, tx bun.Tx, _ *purlPassV0130) error {
		_, err := purlCredentialsInBatchesV0130(ctx, tx, purlBatchV0130, true)
		return err
	},
	func(ctx context.Context, tx bun.Tx, _ *purlPassV0130) error {
		return remoteCredentialsV0130(ctx, tx, purlBatchV0130)
	},
}

// servedDocumentsV0130 is each table and column holding a document served to
// anybody: published VEX documents, and the advisories that went out, whose
// product tree names a build by its root.
var servedDocumentsV0130 = [][2]string{{"published_document", "document"}, {"advisory_issuance", "document"}}

// remoteColumnsV0130 is each table and column holding a repository remote an
// upload stated.
var remoteColumnsV0130 = [][2]string{{"graph_node", "repository"}, {"series_module", "remote"}}

// remoteCredentialsV0130 rewrites each remote holding an "@", a question mark
// or a fragment mark as v0.13.0 stores it, and one that cannot be read as no
// remote.
func remoteCredentialsV0130(ctx context.Context, tx bun.Tx, batch int) error {
	for _, at := range remoteColumnsV0130 {
		table, column := at[0], at[1]
		for after := int64(0); ; {
			type held struct {
				id     int64
				remote string
			}
			rows, err := tx.QueryContext(ctx, `SELECT "id", "`+column+`" FROM "`+table+`"
				WHERE "id" > ? AND ("`+column+`" LIKE ? OR "`+column+`" LIKE ? OR "`+column+`" LIKE ?)
				ORDER BY "id" LIMIT ?`, after, "%@%", "%?%", "%#%", batch)
			if err != nil {
				return fmt.Errorf("read the remotes of %s: %w", table, err)
			}
			var found []held
			read := 0
			for rows.Next() {
				var row held
				if err := rows.Scan(&row.id, &row.remote); err != nil {
					_ = rows.Close()
					return fmt.Errorf("read a remote of %s: %w", table, err)
				}
				read++
				after = row.id
				if clean := remoteWithoutCredentialV0130(row.remote); clean != row.remote {
					found = append(found, held{id: row.id, remote: clean})
				}
			}
			if err := rows.Close(); err != nil {
				return fmt.Errorf("read the remotes of %s: %w", table, err)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("read the remotes of %s: %w", table, err)
			}
			for _, row := range found {
				// No remote is stored as none, as an upload's is.
				value := sql.NullString{String: row.remote, Valid: row.remote != ""}
				if _, err := tx.ExecContext(ctx, `UPDATE "`+table+`" SET "`+column+`" = ? WHERE "id" = ?`,
					value, row.id); err != nil {
					return fmt.Errorf("clean the remote of %s %d: %w", table, row.id, err)
				}
			}
			if read < batch {
				break
			}
		}
	}
	return nil
}

// purlCredentialsInBatchesV0130 cleans as purlCredentialsV0130 does, reading
// batch rows at a time, and returns each identifier that cleaning rewrites
// beside what it becomes. Only where write is set are the rows rewritten.
func purlCredentialsInBatchesV0130(ctx context.Context, tx bun.Tx, batch int, write bool) (map[string]string, error) {
	cleaned := map[string]string{}
	for _, at := range purlColumnsV0130 {
		table, column := at[0], at[1]
		for after := int64(0); ; {
			type held struct {
				id   int64
				purl string
			}
			rows, err := tx.QueryContext(ctx, `SELECT "id", "`+column+`" FROM "`+table+`"
				WHERE "id" > ? AND ("`+column+`" LIKE ? OR LOWER("`+column+`") LIKE ?)
				ORDER BY "id" LIMIT ?`, after, "%?%", "pkg:/%", batch)
			if err != nil {
				return nil, fmt.Errorf("read the package identifiers of %s: %w", table, err)
			}
			var found []held
			read := 0
			for rows.Next() {
				var row held
				if err := rows.Scan(&row.id, &row.purl); err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("read a package identifier of %s: %w", table, err)
				}
				read++
				after = row.id
				if clean := purlWithoutCredentialV0130(row.purl); clean != row.purl {
					found = append(found, held{id: row.id, purl: clean})
					cleaned[row.purl] = clean
				}
			}
			if err := rows.Close(); err != nil {
				return nil, fmt.Errorf("read the package identifiers of %s: %w", table, err)
			}
			if err := rows.Err(); err != nil {
				return nil, fmt.Errorf("read the package identifiers of %s: %w", table, err)
			}
			if write {
				for _, row := range found {
					if _, err := tx.ExecContext(ctx, `UPDATE "`+table+`" SET "`+column+`" = ? WHERE "id" = ?`,
						row.purl, row.id); err != nil {
						return nil, fmt.Errorf("clean the package identifier of %s %d: %w", table, row.id, err)
					}
				}
			}
			if read < batch {
				break
			}
		}
	}
	return cleaned, nil
}

// servedPurlsV0130 rewrites each identifier the cleaning rewrites wherever a
// document in table's column states it. A document states one inside a JSON
// string: as the whole string, as a product's identifier does, or as a part
// of one split at "|" or " as part of ", as a CSAF relationship's identifier
// and name are. Each string is read decoded, so one identifier beginning
// another is never matched inside it, and only a string that changes is
// written again. A document left unchanged is not written.
func servedPurlsV0130(ctx context.Context, tx bun.Tx, table, column string, cleaned map[string]string,
	batch int) error {
	if len(cleaned) == 0 {
		return nil
	}
	for after := int64(0); ; {
		type held struct {
			id       int64
			document string
		}
		rows, err := tx.QueryContext(ctx, `SELECT "id", "`+column+`" FROM "`+table+`"
			WHERE "id" > ? AND "`+column+`" IS NOT NULL ORDER BY "id" LIMIT ?`, after, batch)
		if err != nil {
			return fmt.Errorf("read the documents of %s: %w", table, err)
		}
		var found []held
		read := 0
		for rows.Next() {
			var row held
			if err := rows.Scan(&row.id, &row.document); err != nil {
				_ = rows.Close()
				return fmt.Errorf("read a document of %s: %w", table, err)
			}
			read++
			after = row.id
			document := statedAnewV0130(row.document, cleaned)
			if document != row.document {
				found = append(found, held{id: row.id, document: document})
			}
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("read the documents of %s: %w", table, err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read the documents of %s: %w", table, err)
		}
		for _, row := range found {
			if _, err := tx.ExecContext(ctx, `UPDATE "`+table+`" SET "`+column+`" = ? WHERE "id" = ?`,
				row.document, row.id); err != nil {
				return fmt.Errorf("clean document %d of %s: %w", row.id, table, err)
			}
		}
		if read < batch {
			return nil
		}
	}
}

// statedAnewV0130 is a JSON document with every string stating a cleaned
// identifier written again, and every other byte as it was.
func statedAnewV0130(document string, cleaned map[string]string) string {
	var b strings.Builder
	last, changed := 0, false
	for i := 0; i < len(document); i++ {
		if document[i] != '"' {
			continue
		}
		end := i + 1
		for end < len(document) && document[end] != '"' {
			if document[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(document) {
			break
		}
		var text string
		if err := json.Unmarshal([]byte(document[i:end+1]), &text); err == nil {
			if now := identifiersAnewV0130(text, cleaned); now != text {
				b.WriteString(document[last:i])
				b.WriteString(jsonStringV0130(now))
				last, changed = end+1, true
			}
		}
		i = end
	}
	if !changed {
		return document
	}
	b.WriteString(document[last:])
	return b.String()
}

// identifiersAnewV0130 is a string with each cleaned identifier it states
// rewritten: the whole string, or a part of it between "|" and " as part of ".
func identifiersAnewV0130(text string, cleaned map[string]string) string {
	if now, ok := cleaned[text]; ok {
		return now
	}
	halves := strings.Split(text, withinV0130)
	for i, half := range halves {
		parts := strings.Split(half, "|")
		for j, part := range parts {
			if now, ok := cleaned[part]; ok {
				parts[j] = now
			}
		}
		halves[i] = strings.Join(parts, "|")
	}
	return strings.Join(halves, withinV0130)
}

// withinV0130 joins a CSAF relationship's two product names.
const withinV0130 = " as part of "

// jsonStringV0130 is a string as encoding/json writes it, quotes included.
func jsonStringV0130(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// purlWithoutCredentialV0130 is a package identifier as v0.13.0 stores one:
// the slashes after its scheme dropped, and any credential and query taken
// out of each qualifier holding an address, with or without a scheme, an
// address escaped twice read as decoded twice. A qualifier holding an address
// that does not parse is dropped, since where its credential ends cannot be
// told, and so are a pair whose escapes do not decode, a pair whose key the
// specification does not allow with the pair before it, since it is the rest
// of that value, the pairs after an address whose query is written unescaped,
// since they are that query, and a subpath after a walk that stopped or
// holding a value, a user or a query, since it is an address's fragment.
func purlWithoutCredentialV0130(purl string) string {
	purl = strings.TrimSpace(purl)
	if scheme, rest, found := strings.Cut(purl, ":"); found && strings.EqualFold(scheme, "pkg") {
		purl = scheme + ":" + strings.TrimLeft(rest, "/")
	}
	body, qualifiers, found := strings.Cut(purl, "?")
	if !found {
		return purl
	}
	qualifiers, subpath, hasSubpath := strings.Cut(qualifiers, "#")
	if hasSubpath && strings.Contains(subpath, "@") {
		qualifiers, subpath, hasSubpath = qualifiers+"#"+subpath, "", false
	}
	pairs := strings.Split(qualifiers, "&")
	kept := make([]string, 0, len(pairs))
	walked := 0
	for _, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		if !found || !qualifierKeyV0130(key) {
			// No qualifier the specification allows: the rest of a value
			// holding a raw "&", such as a password or a path, so that value
			// and every pair after it go.
			if len(kept) > 0 {
				kept = kept[:len(kept)-1]
			}
			break
		}
		decoded, err := url.PathUnescape(value)
		if err != nil {
			break
		}
		if again, err := url.PathUnescape(decoded); err == nil {
			decoded = again
		}
		if !schemedV0130(decoded) {
			bare, readable := withoutPasswordV0130(decoded)
			if !readable {
				break
			}
			if at := strings.IndexAny(bare, "?#"); at >= 0 {
				bare = bare[:at]
			}
			if bare != decoded {
				pair = key + "=" + qualifierEscapedV0130(bare)
			}
			kept = append(kept, pair)
			if queryUnescapedV0130(value) {
				break
			}
			walked++
			continue
		}
		parsed, err := url.Parse(decoded)
		if err != nil {
			break
		}
		_, password := parsed.User.Password()
		user := parsed.User != nil && (password || !strings.Contains(strings.ToLower(parsed.Scheme), "ssh"))
		queried := parsed.RawQuery != "" || parsed.ForceQuery
		if !user && !queried && parsed.Fragment == "" {
			kept = append(kept, pair)
		} else {
			if user {
				parsed.User = nil
			}
			parsed.RawQuery, parsed.ForceQuery = "", false
			parsed.Fragment, parsed.RawFragment = "", ""
			kept = append(kept, key+"="+qualifierEscapedV0130(parsed.String()))
		}
		if queryUnescapedV0130(value) {
			break
		}
		walked++
	}
	purl = body
	if len(kept) > 0 {
		purl += "?" + strings.Join(kept, "&")
	}
	if hasSubpath && walked == len(pairs) {
		if decoded, err := url.PathUnescape(subpath); err == nil && !strings.ContainsAny(decoded, "=@?") {
			purl += "#" + subpath
		}
	}
	return purl
}

// qualifierKeyV0130 is whether a qualifier's key is one the purl
// specification allows: ASCII letters, digits, ".", "-" and "_", not starting
// with a digit.
func qualifierKeyV0130(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', c == '.', c == '-', c == '_':
		case '0' <= c && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// queryUnescapedV0130 says whether a qualifier's value holds an address whose
// query is written in part unescaped: a question mark written as it is, or an
// escaped one followed by an equals sign written as it is.
func queryUnescapedV0130(value string) bool {
	if strings.Contains(value, "?") {
		return true
	}
	at := strings.Index(strings.ToLower(value), "%3f")
	return at >= 0 && strings.Contains(value[at:], "=")
}

// schemedV0130 is whether an address opens on a scheme and "://", or on "//".
func schemedV0130(address string) bool {
	if strings.HasPrefix(address, "//") {
		return true
	}
	end := strings.Index(address, "://")
	if end <= 0 {
		return false
	}
	for i, c := range address[:end] {
		letter := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
		later := ('0' <= c && c <= '9') || c == '+' || c == '-' || c == '.'
		if !letter && (i == 0 || !later) {
			return false
		}
	}
	return true
}

// withoutPasswordV0130 is an address written without a scheme with a user
// and password written before its host taken out, and whether it can be read
// at all. A user with no password is kept, as an scp-style address names one.
// A colon before the first slash with no "@" there, and an "@" after it,
// cannot be read.
func withoutPasswordV0130(address string) (string, bool) {
	// Read to the first slash and no shorter: a password may hold a question
	// mark or a fragment mark, and cutting there first hides the "@" that
	// ends it.
	host := address
	if end := strings.IndexByte(host, '/'); end >= 0 {
		host = host[:end]
	}
	if at := strings.LastIndex(host, "@"); at >= 0 {
		if at > 0 && strings.Contains(host[:at], ":") {
			return address[at+1:], true
		}
		return address, true
	}
	if strings.Contains(host, ":") && strings.Contains(address[len(host):], "@") {
		return "", false
	}
	return address, true
}

// remoteWithoutCredentialV0130 is a remote as v0.13.0 stores one: without a
// user, password, query or fragment, and none where its credential ends
// cannot be told.
func remoteWithoutCredentialV0130(remote string) string {
	if schemedV0130(remote) {
		u, err := url.Parse(remote)
		if err != nil {
			return ""
		}
		u.User, u.RawQuery, u.ForceQuery = nil, "", false
		u.Fragment, u.RawFragment = "", ""
		return u.String()
	}
	bare, readable := withoutPasswordV0130(remote)
	if !readable {
		return ""
	}
	if at := strings.IndexAny(bare, "?#"); at >= 0 {
		bare = bare[:at]
	}
	return bare
}

// qualifierEscapedV0130 percent-encodes a qualifier's value, leaving the
// characters an address is read by.
func qualifierEscapedV0130(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
			strings.IndexByte("-._~:/@", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
