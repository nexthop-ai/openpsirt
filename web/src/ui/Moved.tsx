// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Whether what a document says now is what last went out.
//
// The server compares what would be generated now with what was kept when it
// last went out, so an answer here is never a guess; where it has none the
// caller draws nothing.
export function Moved({ changed }: { changed: boolean }) {
  return changed ? (
    <div className="alert" style={{ marginBottom: 10 }}>
      <strong>Changed since it went out</strong>
      <span>What it says now differs from the last revision published.</span>
    </div>
  ) : (
    <p className="hint">What it says now is what last went out.</p>
  );
}
