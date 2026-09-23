// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from "react";
import { render } from "./markdown";

// Text somebody typed into this tool, rendered. Anything a scan file supplied
// is shown escaped and never rendered — that is a different component and
// deliberately not this one.
export function Markdown({ source, className }: { source: string; className?: string }) {
  const markup = useMemo(() => render(source), [source]);
  return (
    <div
      className={`prose-openpsirt ${className ?? ""}`}
      // Sanitized immediately above, by the one renderer this application has.
      dangerouslySetInnerHTML={{ __html: markup }}
    />
  );
}
