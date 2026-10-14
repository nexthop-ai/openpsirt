// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
// @ts-expect-error - a gate script, which is plain ESM with no types of its own
import { excepts, licenseVerdict, packageAt, satisfies, shippedImports } from "./licenses.mjs";

// The interface ships inside the binary, so a copyleft dependency there is the
// installer's problem.
//
// An SPDX expression is not a license name: "MIT AND ISC" is satisfied only if
// both are allowed, "(MPL-2.0 OR Apache-2.0)" by either. Treating the whole
// string as a name refuses both, and adding both strings to the allowlist
// accepts every other expression spelled the same way. The gate's only
// consumer is an exit code.

const permissive = new Set(["MIT", "ISC", "Apache-2.0", "BSD-3-Clause", "0BSD"]);
const ok = (expression: string) => satisfies(expression, permissive) as boolean;

describe("what an allowlist admits", () => {
  it("takes a plain name that is on it", () => {
    expect(ok("MIT")).toBe(true);
  });

  it("refuses a plain name that is not", () => {
    expect(ok("GPL-3.0")).toBe(false);
  });
});

describe("an expression is read, not matched", () => {
  it("requires both sides of an AND", () => {
    expect(ok("MIT AND ISC")).toBe(true);
    expect(ok("MIT AND GPL-3.0")).toBe(false);
  });

  it("takes either side of an OR", () => {
    expect(ok("MPL-2.0 OR Apache-2.0")).toBe(true);
    expect(ok("GPL-3.0 OR AGPL-3.0")).toBe(false);
  });

  it("reads parentheses as grouping", () => {
    expect(ok("(MIT OR GPL-3.0) AND ISC")).toBe(true);
    expect(ok("(GPL-3.0 OR AGPL-3.0) AND MIT")).toBe(false);
  });

  it("takes a trailing plus as this version or later", () => {
    expect(ok("Apache-2.0+")).toBe(true);
    expect(ok("GPL-3.0+")).toBe(false);
  });
});

describe("what it will not guess at", () => {
  it("refuses an expression it cannot read to the end", () => {
    // Accepting whatever the first token happened to be is how an expression
    // nobody has read gets admitted on the strength of its opening word.
    expect(ok("MIT WITH Classpath-exception-2.0")).toBe(false);
    expect(ok("MIT ISC")).toBe(false);
  });

  it("refuses nothing at all", () => {
    expect(ok("")).toBe(false);
  });

  it("refuses a truncated expression rather than throwing on it", () => {
    // The gate's only output is an exit code, so a parser that throws exits
    // with a stack trace and never names the package whose license field was
    // the problem — which is the one thing somebody reading the failure needs.
    expect(() => ok("(MIT")).not.toThrow();
    expect(ok("(MIT")).toBe(false);
    expect(ok("MIT AND")).toBe(false);
    expect(ok("MIT OR")).toBe(false);
    expect(ok("(((")).toBe(false);
    expect(ok(")")).toBe(false);
  });

  it("refuses a group that never closes, rather than reading the next name as its bracket", () => {
    expect(ok("(MIT GPL-3.0")).toBe(false);
    expect(ok("(MIT AGPL-3.0 AND ISC")).toBe(false);
    expect(ok("(MIT OR ISC)")).toBe(true);
  });
});

describe("which package an exception names", () => {
  it("reads the package installed at a location, scope included", () => {
    expect(packageAt("argparse")).toBe("argparse");
    expect(packageAt("@fontsource/inter")).toBe("@fontsource/inter");
    expect(packageAt("js-yaml/argparse")).toBe("argparse");
    expect(packageAt("@a/b/@c/d")).toBe("@c/d");
  });

  it("admits the named package wherever it is installed", () => {
    expect(excepts("argparse", "argparse")).toBe(true);
    expect(excepts("argparse", "js-yaml/argparse")).toBe(true);
  });

  it("admits no other package that shares the name's last part", () => {
    expect(excepts("argparse", "@someone/argparse")).toBe(false);
    expect(excepts("argparse", "argparse-lite")).toBe(false);
    expect(excepts("argparse", "argparse/other")).toBe(false);
  });

  it("admits every package in a scope named with a trailing slash, and none outside it", () => {
    expect(excepts("@fontsource/", "@fontsource/inter")).toBe(true);
    expect(excepts("@fontsource/", "x/@fontsource/inter")).toBe(true);
    expect(excepts("@fontsource/", "@fontsourcery/inter")).toBe(false);
    expect(excepts("@fontsource/", "fontsource")).toBe(false);
  });
});

describe("the verdict over a lockfile", () => {
  const packages = {
    "": { name: "web" },
    "node_modules/kept": { license: "MIT" },
    "node_modules/copyleft": { license: "GPL-3.0-only" },
    "node_modules/tool": { license: "GPL-3.0-only", dev: true },
    "node_modules/@fonts/serif": { license: "OFL-1.1" },
  };
  const verdict = () =>
    licenseVerdict(packages, permissive, [{ prefix: "@fonts/", license: "OFL-1.1" }]) as {
      refused: string[];
      excepted: string[];
      checked: number;
    };

  it("refuses a shipped package outside the allowlist", () => {
    expect(verdict().refused).toEqual(["copyleft is GPL-3.0-only"]);
  });

  it("admits a package by exception and leaves a development one alone", () => {
    expect(verdict().excepted).toEqual(["@fonts/serif (OFL-1.1)"]);
    expect(verdict().checked).toBe(3);
  });
});

describe("a development dependency in the bundle", () => {
  const packages = {
    "node_modules/shipped": { license: "MIT" },
    "node_modules/@build/tool": { license: "GPL-3.0-only", dev: true },
    "node_modules/styles": { license: "MIT", devOptional: true },
  };
  const found = (files: Record<string, string>) =>
    (shippedImports(files, packages) as { found: string[] }).found;

  it("is reported where the source imports it", () => {
    expect(
      found({
        "ui/a.tsx": `import { x } from "@build/tool/inner";`,
        "index.css": `@import "styles";`,
      }),
    ).toEqual([
      "@build/tool is imported by src/ui/a.tsx but is a development dependency",
      "styles is imported by src/index.css but is a development dependency",
    ]);
  });

  it("is not reported where only a test, the harness or a type import names it", () => {
    expect(
      found({
        "ui/a.test.tsx": `import { x } from "@build/tool";`,
        "test/mount.tsx": `import { x } from "@build/tool";`,
        "ui/b.ts": `import type { X } from "@build/tool"; import { y } from "shipped"; import "./c";`,
      }),
    ).toEqual([]);
  });

  it("counts every specifier it read, and none from a test", () => {
    const read = (files: Record<string, string>) =>
      (shippedImports(files, packages) as { read: number }).read;
    expect(read({ "ui/a.tsx": `import { y } from "shipped"; import "./c";` })).toBe(2);
    expect(read({ "ui/a.test.tsx": `import { y } from "shipped";` })).toBe(0);
  });
});
