import { describe, expect, it } from "vitest";
import { Refused, notYours, statusOf, unwrap } from "./queries";

const answered = (status: number, statusText: string, error?: unknown) => ({
  error,
  response: { ok: status < 400, status, statusText } as Response,
});

// Every failure arm in the interface routes through this one predicate to
// decide whether a refusal is shown to somebody or swallowed. Widened to
// "any refusal", it swallows the 500s the whole change exists to surface —
// and the rest of the suite stays green while it does.
describe("whether a refusal is somebody's to see", () => {
  it("swallows what the server says is not theirs", () => {
    expect(notYours(new Refused(403, "not authorized"))).toBe(true);
    expect(notYours(new Refused(404, "no such thing"))).toBe(true);
  });

  it("does not swallow a read that failed", () => {
    expect(notYours(new Refused(500, "boom"))).toBe(false);
    expect(notYours(new Refused(503, "unavailable"))).toBe(false);
    expect(notYours(new Refused(401, "session ended"))).toBe(false);
  });

  it("does not swallow something that is not a refusal at all", () => {
    // A network failure never reaches the server, so it carries no status and
    // is nobody's answer about anything.
    expect(notYours(new Error("network"))).toBe(false);
    expect(notYours(undefined)).toBe(false);
    expect(notYours(null)).toBe(false);
  });
});

// For the call sites where one of the two statuses above means something of
// its own — the reporter read answers 404 for "nobody recorded a reporter".
describe("the status a refusal carried", () => {
  it("is the server's own", () => {
    expect(statusOf(new Refused(404, "none"))).toBe(404);
    expect(statusOf(new Refused(403, "no"))).toBe(403);
  });

  it("is nothing where there was no refusal", () => {
    expect(statusOf(new Error("network"))).toBeUndefined();
    expect(statusOf(undefined)).toBeUndefined();
  });
});

describe("what a refusal says", () => {
  it("prefers the sentence the server wrote", () => {
    const said = () => unwrap(answered(422, "Unprocessable", { detail: "version is required" }));
    expect(said).toThrow("version is required");
  });

  it("falls back to the reason phrase", () => {
    expect(() => unwrap(answered(404, "Not Found"))).toThrow("Not Found");
  });

  it("falls back to the status where there is no reason phrase", () => {
    // Every HTTP/2 response: the protocol carries the code and dropped the
    // phrase, so `statusText` is the empty string and a screen showing it
    // showed nothing at all.
    expect(() => unwrap(answered(500, ""))).toThrow("HTTP 500");
  });

  it("carries the status, so an ended session can be told from a failure", () => {
    try {
      unwrap(answered(401, ""));
      expect.unreachable("a refusal was not thrown");
    } catch (error) {
      expect(statusOf(error)).toBe(401);
    }
  });

  it("gives back the value where nothing was refused", () => {
    expect(
      unwrap({ data: { items: [] }, response: { ok: true, status: 200 } as Response }),
    ).toEqual({ items: [] });
  });
});
