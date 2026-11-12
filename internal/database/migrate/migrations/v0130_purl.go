// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
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

// purlCredentialsV0130 rewrites the package identifiers v0.12.0 stored as
// v0.13.0 stores them: the slashes after the scheme dropped, and any
// credential and query taken out of the addresses its qualifiers hold. Only a
// row starting "pkg:/" in any case, or holding a colon after its qualifiers
// start, plain or escaped, is read: an address has one, and a distribution's
// arch and distro qualifiers do not. Only a row that changes is written, so
// a start after one that stopped part way writes what the first missed.
// No identity is rewritten.
func purlCredentialsV0130(ctx context.Context, tx bun.Tx) error {
	return purlCredentialsInBatchesV0130(ctx, tx, purlBatchV0130)
}

// purlCredentialsInBatchesV0130 cleans as purlCredentialsV0130 does, reading
// batch rows at a time.
func purlCredentialsInBatchesV0130(ctx context.Context, tx bun.Tx, batch int) error {
	for _, at := range purlColumnsV0130 {
		table, column := at[0], at[1]
		for after := int64(0); ; {
			type held struct {
				id   int64
				purl string
			}
			rows, err := tx.QueryContext(ctx, `SELECT "id", "`+column+`" FROM "`+table+`"
				WHERE "id" > ? AND ("`+column+`" LIKE ? OR LOWER("`+column+`") LIKE ? OR LOWER("`+column+`") LIKE ?)
				ORDER BY "id" LIMIT ?`, after, "%?%:%", "%?%3a%", "pkg:/%", batch)
			if err != nil {
				return fmt.Errorf("read the package identifiers of %s: %w", table, err)
			}
			var found []held
			read := 0
			for rows.Next() {
				var row held
				if err := rows.Scan(&row.id, &row.purl); err != nil {
					_ = rows.Close()
					return fmt.Errorf("read a package identifier of %s: %w", table, err)
				}
				read++
				after = row.id
				if cleaned := purlWithoutCredentialV0130(row.purl); cleaned != row.purl {
					found = append(found, held{id: row.id, purl: cleaned})
				}
			}
			if err := rows.Close(); err != nil {
				return fmt.Errorf("read the package identifiers of %s: %w", table, err)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("read the package identifiers of %s: %w", table, err)
			}
			for _, row := range found {
				if _, err := tx.ExecContext(ctx, `UPDATE "`+table+`" SET "`+column+`" = ? WHERE "id" = ?`,
					row.purl, row.id); err != nil {
					return fmt.Errorf("clean the package identifier of %s %d: %w", table, row.id, err)
				}
			}
			if read < batch {
				break
			}
		}
	}
	return nil
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
	addressLast := false
	for _, pair := range pairs {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			addressLast = false
			kept = append(kept, pair)
			continue
		}
		address, err := url.PathUnescape(value)
		if err != nil {
			addressLast = false
			continue
		}
		addressLast = strings.Contains(address, "://")
		if !addressLast {
			if host, held := withoutPasswordV0130(address); held {
				pair = key + "=" + qualifierEscapedV0130(host)
			}
			kept = append(kept, pair)
			continue
		}
		parsed, err := url.Parse(address)
		if err != nil {
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
		if strings.Contains(value, "?") || (queried && strings.Contains(value, "=")) {
			break
		}
	}
	purl = body
	if len(kept) > 0 {
		purl += "?" + strings.Join(kept, "&")
	}
	if hasSubpath && (!addressLast || !strings.Contains(subpath, "=")) {
		purl += "#" + subpath
	}
	return purl
}

// withoutPasswordV0130 is an address written without a scheme with the user
// and password written before its host taken out, and whether it held one. A
// user with no password is kept, as an scp-style address names one.
func withoutPasswordV0130(address string) (string, bool) {
	end := strings.IndexAny(address, "/?#")
	if end < 0 {
		end = len(address)
	}
	at := strings.LastIndex(address[:end], "@")
	if at <= 0 || at == end-1 || !strings.Contains(address[:at], ":") {
		return "", false
	}
	return address[at+1:], true
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
