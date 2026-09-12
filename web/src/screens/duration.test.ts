import { describe, expect, it } from "vitest";
import { composable, humane, read, write } from "./duration";

describe("a length of time somebody has to set", () => {
  it("reads a stored value as the largest whole unit", () => {
    // A year is 365 days and not a whole number of weeks, so days is the
    // largest unit that says it exactly.
    expect(read("8760h")).toEqual({ count: 365, unit: "days" });
    expect(read("336h")).toEqual({ count: 2, unit: "weeks" });
    expect(read("72h")).toEqual({ count: 3, unit: "days" });
    expect(read("5h")).toEqual({ count: 5, unit: "hours" });
    // The form the server hands back, which is not the form it was set in.
    expect(read("12h0m0s")).toEqual({ count: 12, unit: "hours" });
  });

  it("gives up rather than rounding something it cannot say", () => {
    // Real values, set by somebody who meant them. A control that can only
    // say whole hours must not offer to edit one of these.
    expect(read("90m")).toBeNull();
    expect(read("30s")).toBeNull();
    expect(read("")).toBeNull();
    expect(read("forever")).toBeNull();
    // Nothing is not a length of time; the server refuses it either way.
    expect(read("0h")).toBeNull();
  });

  it("writes back the form the server takes", () => {
    expect(write(52, "weeks")).toBe("8736h");
    expect(write(3, "days")).toBe("72h");
    expect(write(5, "hours")).toBe("5h");
    // A year is 52 weeks and a bit, so what comes back out of the composer is
    // what was composed rather than what was stored before it — which is the
    // honest behavior: the person chose 52 weeks.
    expect(read(write(52, "weeks"))).toEqual({ count: 52, unit: "weeks" });
  });

  it("refuses to compose nothing", () => {
    expect(write(0, "days")).toBe("24h");
    expect(write(-3, "days")).toBe("24h");
  });

  it("offers the composer for a setting nobody has set", () => {
    // An unset value has no unit to read, which is not the same as a unit
    // this cannot say. The embargo periods arrive empty, and a plain text box
    // cannot ask whether a typed 90 means hours, days or weeks.
    expect(composable("")).toBe(true);
    expect(composable("  ")).toBe(true);
    expect(composable("168h0m0s")).toBe(true);
    expect(composable("90m")).toBe(false);
  });

  it("says a length of time the way somebody would", () => {
    expect(humane("8760h")).toBe("1 year");
    expect(humane("72h")).toBe("3 days");
    expect(humane("24h")).toBe("1 day");
    expect(humane("5h")).toBe("5 hours");
    expect(humane("90m")).toBe("");
  });
});
