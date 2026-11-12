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
// credential and query taken out of the addresses its qualifiers hold. Only a
// row starting "pkg:/" in any case, or holding a colon, a question mark or a
// fragment mark after its qualifiers start, plain or escaped, is read: an
// address with a credential or a query has one, and a distribution's arch and
// distro qualifiers do not. Only a row that changes is written, so
// a start after one that stopped part way writes what the first missed.
// No identity is rewritten. Each document served to anybody then states every
// identifier it holds as it now stands.
func purlCredentialsV0130(ctx context.Context, tx bun.Tx) error {
	cleaned, err := purlCredentialsInBatchesV0130(ctx, tx, purlBatchV0130)
	if err != nil {
		return err
	}
	if err := publishedPurlsV0130(ctx, tx, cleaned, publishedBatchV0130); err != nil {
		return err
	}
	return remoteCredentialsV0130(ctx, tx, purlBatchV0130)
}

// remoteColumnsV0130 is each table and column holding a repository remote an
// upload stated.
var remoteColumnsV0130 = [][2]string{{"graph_node", "repository"}, {"series_module", "remote"}}

// remoteCredentialsV0130 rewrites each remote holding an "@" or a question
// mark as v0.13.0 stores it, and one that cannot be read as no remote.
func remoteCredentialsV0130(ctx context.Context, tx bun.Tx, batch int) error {
	for _, at := range remoteColumnsV0130 {
		table, column := at[0], at[1]
		for after := int64(0); ; {
			type held struct {
				id     int64
				remote string
			}
			rows, err := tx.QueryContext(ctx, `SELECT "id", "`+column+`" FROM "`+table+`"
				WHERE "id" > ? AND ("`+column+`" LIKE ? OR "`+column+`" LIKE ?)
				ORDER BY "id" LIMIT ?`, after, "%@%", "%?%", batch)
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
// batch rows at a time, and returns each identifier it rewrote beside what it
// became.
func purlCredentialsInBatchesV0130(ctx context.Context, tx bun.Tx, batch int) (map[string]string, error) {
	cleaned := map[string]string{}
	for _, at := range purlColumnsV0130 {
		table, column := at[0], at[1]
		for after := int64(0); ; {
			type held struct {
				id   int64
				purl string
			}
			rows, err := tx.QueryContext(ctx, `SELECT "id", "`+column+`" FROM "`+table+`"
				WHERE "id" > ? AND ("`+column+`" LIKE ? OR "`+column+`" LIKE ? OR "`+column+`" LIKE ?
				  OR LOWER("`+column+`") LIKE ? OR LOWER("`+column+`") LIKE ? OR LOWER("`+column+`") LIKE ?
				  OR LOWER("`+column+`") LIKE ?)
				ORDER BY "id" LIMIT ?`, after, "%?%:%", "%?%?%", "%?%#%", "%?%3a%", "%?%3f%", "%?%23%", "pkg:/%", batch)
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
			for _, row := range found {
				if _, err := tx.ExecContext(ctx, `UPDATE "`+table+`" SET "`+column+`" = ? WHERE "id" = ?`,
					row.purl, row.id); err != nil {
					return nil, fmt.Errorf("clean the package identifier of %s %d: %w", table, row.id, err)
				}
			}
			if read < batch {
				break
			}
		}
	}
	return cleaned, nil
}

// publishedPurlsV0130 rewrites each identifier the cleaning rewrote wherever a
// document served to anybody states it. A document states one as a whole JSON
// string, so the quoted encoding is matched, and one identifier beginning
// another is never matched inside it. A document left unchanged is not
// written.
func publishedPurlsV0130(ctx context.Context, tx bun.Tx, cleaned map[string]string, batch int) error {
	if len(cleaned) == 0 {
		return nil
	}
	// No quoted string begins another, so the order the pairs are tried in
	// changes nothing.
	swaps := make([]string, 0, 2*len(cleaned))
	for from, to := range cleaned {
		swaps = append(swaps, jsonStringV0130(from), jsonStringV0130(to))
	}
	replacer := strings.NewReplacer(swaps...)
	for after := int64(0); ; {
		type held struct {
			id       int64
			document string
		}
		rows, err := tx.QueryContext(ctx, `SELECT "id", "document" FROM "published_document"
			WHERE "id" > ? ORDER BY "id" LIMIT ?`, after, batch)
		if err != nil {
			return fmt.Errorf("read the published documents: %w", err)
		}
		var found []held
		read := 0
		for rows.Next() {
			var row held
			if err := rows.Scan(&row.id, &row.document); err != nil {
				_ = rows.Close()
				return fmt.Errorf("read a published document: %w", err)
			}
			read++
			after = row.id
			document := replacer.Replace(row.document)
			if document != row.document {
				found = append(found, held{id: row.id, document: document})
			}
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("read the published documents: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read the published documents: %w", err)
		}
		for _, row := range found {
			if _, err := tx.ExecContext(ctx, `UPDATE "published_document" SET "document" = ? WHERE "id" = ?`,
				row.document, row.id); err != nil {
				return fmt.Errorf("clean published document %d: %w", row.id, err)
			}
		}
		if read < batch {
			return nil
		}
	}
}

// jsonStringV0130 is a string as encoding/json writes it, quotes included.
func jsonStringV0130(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// purlWithoutCredentialV0130 is a package identifier as v0.13.0 stores one:
// the slashes after its scheme dropped, and any credential and query taken
// out of each qualifier holding an address, with or without a scheme. A qualifier holding an address
// that does not parse is dropped, since where its credential ends cannot be
// told, and so are a pair whose escapes do not decode, the pairs after an
// address whose query is written unescaped, since they are that query, and a
// subpath holding a value after an address, since it is that address's
// fragment.
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
	pairs := strings.Split(qualifiers, "&")
	kept := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			kept = append(kept, pair)
			continue
		}
		address, err := url.PathUnescape(value)
		if err != nil {
			if queryUnescapedV0130(value) {
				break
			}
			continue
		}
		if !schemedV0130(address) {
			bare, readable := withoutPasswordV0130(address)
			if readable {
				if at := strings.IndexAny(bare, "?#"); at >= 0 {
					bare = bare[:at]
				}
				if bare != address {
					pair = key + "=" + qualifierEscapedV0130(bare)
				}
				kept = append(kept, pair)
			}
			if queryUnescapedV0130(value) {
				break
			}
			continue
		}
		parsed, err := url.Parse(address)
		if err != nil {
			if queryUnescapedV0130(value) {
				break
			}
			continue
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
	}
	purl = body
	if len(kept) > 0 {
		purl += "?" + strings.Join(kept, "&")
	}
	if hasSubpath && !strings.Contains(subpath, "=") {
		purl += "#" + subpath
	}
	return purl
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
// user, password or query, and none where its credential ends cannot be
// told.
func remoteWithoutCredentialV0130(remote string) string {
	if schemedV0130(remote) {
		u, err := url.Parse(remote)
		if err != nil {
			return ""
		}
		u.User, u.RawQuery, u.ForceQuery = nil, "", false
		return u.String()
	}
	bare, readable := withoutPasswordV0130(remote)
	if !readable {
		return ""
	}
	bare, _, _ = strings.Cut(bare, "?")
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
