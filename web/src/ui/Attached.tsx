// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";

// One attached file as a list shows it: a link to fetch it, its type and size;
// or, where it was removed, its name and why. The fetch address is the one
// route that authorizes a download before anything is handed over, so every
// list reaches a file through here.
//
// What follows the link — a control to remove it — is the caller's, and is
// drawn only for a file that is still there.
export function Attached({
  file,
  children,
}: {
  file: {
    token?: string;
    filename?: string;
    content_type?: string;
    size?: number;
    redacted?: boolean;
    redacted_reason?: string;
  };
  children?: ReactNode;
}) {
  if (file.redacted) {
    return (
      <span className="hint">
        <b>{file.filename}</b> was removed
        {file.redacted_reason ? <> — {file.redacted_reason}</> : null}
      </span>
    );
  }
  return (
    <>
      <a href={`/v1/attachments/${file.token}`} rel="noreferrer">
        {file.filename}
      </a>
      <span className="hint">
        {" "}
        · {file.content_type} · {Math.max(1, Math.round((file.size ?? 0) / 1024))} KB
      </span>
      {children}
    </>
  );
}
