// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A URL a third party supplied, judged before it becomes somewhere to click.
//
// A scanner's advisory references and the records an enrichment feed carries
// are strings from outside this deployment, and a string in an `href` is not
// encoded output — it is a scheme the browser acts on. What stands between a
// feed record carrying `javascript:` and a triager's click is otherwise a
// framework's own rewriting and a response header, neither of which is a check
// in this codebase, and neither of which the rule about third-party text
// anywhere says is enough.
//
// The same two schemes the text policy permits for a link, asked the same way:
// an address that is not one of them is not linked, and the text is shown as
// it stands so nothing disappears from the page.
const LINKABLE = /^https?:\/\//i;

export function linkable(url: string | undefined | null): string | null {
  const written = String(url ?? "").trim();
  return LINKABLE.test(written) ? written : null;
}
