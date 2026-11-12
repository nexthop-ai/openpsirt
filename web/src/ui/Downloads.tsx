// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The two links a report offers its rows through as a file. A link somebody
// follows rather than a request the page makes, so the browser fetches it
// with the session it already has. Inline, the pair sits in a sentence of
// prose; otherwise each is a quiet button in a toolbar.
export function Downloads({
  href,
  inline = false,
}: {
  href: (format: "csv" | "json") => string;
  inline?: boolean;
}) {
  if (inline) {
    return (
      <>
        <a href={href("csv")}>CSV</a> · <a href={href("json")}>JSON</a>
      </>
    );
  }
  return (
    <>
      <a className="btn quiet" href={href("csv")}>
        CSV
      </a>{" "}
      <a className="btn quiet" href={href("json")}>
        JSON
      </a>
    </>
  );
}
