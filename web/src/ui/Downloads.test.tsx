// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { mounted } from "../test/mount";
import { Downloads } from "./Downloads";

const mount = mounted();
const at = (format: "csv" | "json") => `/v1/trend.${format}?weeks=12`;
const links = () =>
  Array.from(mount.host().querySelectorAll("a")).map((a) => [
    a.getAttribute("href"),
    a.textContent,
    a.className,
  ]);

describe("a report's file links", () => {
  it("offers each format as a quiet button", () => {
    mount.render(<Downloads href={at} />);
    expect(links()).toEqual([
      ["/v1/trend.csv?weeks=12", "CSV", "btn quiet"],
      ["/v1/trend.json?weeks=12", "JSON", "btn quiet"],
    ]);
  });

  it("offers each format as a plain link inside a sentence", () => {
    mount.render(<Downloads inline href={at} />);
    expect(links()).toEqual([
      ["/v1/trend.csv?weeks=12", "CSV", ""],
      ["/v1/trend.json?weeks=12", "JSON", ""],
    ]);
    expect(mount.host().textContent).toBe("CSV · JSON");
  });
});
