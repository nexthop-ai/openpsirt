import { afterEach, describe, expect, it } from "vitest";
import { returningHere } from "./SignIn";

function at(path: string, search = "") {
  window.history.replaceState({}, "", path + search);
}

afterEach(() => at("/"));

describe("where a sign-in comes back to", () => {
  it("carries the screen somebody was on", () => {
    at("/products/sonic/streams/master/variants/broadcom/findings");
    expect(returningHere()).toBe(
      "?return=%2Fproducts%2Fsonic%2Fstreams%2Fmaster%2Fvariants%2Fbroadcom%2Ffindings",
    );
  });

  it("carries the filters that were set with it", () => {
    // A findings list is its filters. Coming back to the same path with none
    // of them is coming back to a different screen.
    at(
      "/products/sonic/streams/master/variants/broadcom/findings",
      "?state=undecided&severity=high",
    );
    expect(returningHere()).toContain("%3Fstate%3Dundecided%26severity%3Dhigh");
  });

  it("carries nothing from the home page, which is where a sign-in lands anyway", () => {
    at("/");
    expect(returningHere()).toBe("");
  });

  it("escapes what it carries, so the address cannot end the parameter early", () => {
    at("/products/a&b=c/streams");
    const carried = returningHere();
    expect(carried).not.toContain("&b=");
    expect(carried).toBe("?return=%2Fproducts%2Fa%26b%3Dc%2Fstreams");
  });
});
