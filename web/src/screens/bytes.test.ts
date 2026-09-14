import { describe, expect, it } from "vitest";
import { humaneBytes, readBytes, writeBytes } from "./bytes";

// The server takes a plain count of bytes, because that is what it compares an
// upload against. Nobody reads 26214400 as twenty-five megabytes, and a field
// that shows it is a field where a mistake is a factor of a thousand.
//
// Which is why this is tested rather than left to read correctly: a wrong
// multiplier here is an upload bound off by 1024, and it looks right on the
// screen either way. Its twin, the duration composer, has ten tests; this had
// none.
describe("a size between what the server stores and what somebody reads", () => {
  it("round trips each unit", () => {
    for (const [count, unit, stored] of [
      [900, "bytes", "900"],
      [25, "KB", "25600"],
      [25, "MB", "26214400"],
      [2, "GB", "2147483648"],
    ] as const) {
      expect(writeBytes(count, unit)).toBe(stored);
      expect(readBytes(stored)).toEqual({ count, unit });
    }
  });

  it("reads a size as the largest unit that divides it whole", () => {
    // 1048576 is a megabyte, not 1024 kilobytes. Offering the smaller unit
    // would put four digits in a field somebody has to check.
    expect(readBytes("1048576")).toEqual({ count: 1, unit: "MB" });
    expect(readBytes("1024")).toEqual({ count: 1, unit: "KB" });
    // And a size that divides into nothing whole stays bytes.
    expect(readBytes("1500")).toEqual({ count: 1500, unit: "bytes" });
  });

  it("refuses what a unit control cannot express, rather than rounding it", () => {
    // A value somebody set deliberately is never quietly changed by a control
    // that cannot hold it.
    for (const refused of ["", "   ", "25 MB", "-1", "0", "1.5", "9007199254740993"]) {
      expect(readBytes(refused), `${refused} was read as a size`).toBeNull();
    }
  });

  it("never writes a size of nothing", () => {
    // Zero or negative reads as unset everywhere in this tool, so a control
    // that could produce it would turn a bound into no bound at all.
    expect(writeBytes(0, "MB")).toBe("1048576");
    expect(writeBytes(-3, "KB")).toBe("1024");
  });

  it("says a size somebody set from a script in words", () => {
    expect(humaneBytes("1536")).toBe("1.5 KB");
    expect(humaneBytes("26214400")).toBe("25 MB");
    expect(humaneBytes("900")).toBe("900 bytes");
    // Nothing to say about something that is not a size.
    expect(humaneBytes("")).toBe("");
    expect(humaneBytes("0")).toBe("");
    expect(humaneBytes("later")).toBe("");
  });
});
