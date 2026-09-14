import { beforeEach, describe, expect, it } from "vitest";
import { belongTo, forget, forgetAll, keep, restore } from "./drafts";

beforeEach(() => {
  window.localStorage.clear();
  belongTo(undefined);
});

describe("drafts", () => {
  it("gives back what was left behind", () => {
    belongTo("oidc:ana");
    keep("revise:7", "half a justification");
    expect(restore("revise:7")).toBe("half a justification");
  });

  it("keeps nothing until somebody is recognized", () => {
    // Text typed before the session is known has nowhere safe to go: stored
    // under nobody's name, it would be handed to whoever signs in next.
    keep("revise:7", "half a justification");
    expect(window.localStorage.length).toBe(0);
    belongTo("oidc:ana");
    expect(restore("revise:7")).toBe("");
  });

  it("takes away what belongs to somebody else", () => {
    // The control that covers a session which quietly expired rather than
    // being signed out of. Same browser, same screen, different person.
    //
    // The identity in the key stopped Ana's text being read back into Ben's
    // form; it did not stop the text being in the storage, which outlives
    // every session and needs no credential to read. So somebody signing in
    // takes away what is not theirs, and Ana's draft does not come back when
    // she does.
    belongTo("oidc:ana");
    keep("revise:7", "what Ana was writing");
    belongTo("oidc:ben");
    expect(restore("revise:7")).toBe("");
    belongTo("oidc:ana");
    expect(restore("revise:7")).toBe("");
  });

  it("forgets a draft nobody came back to", () => {
    // Browser storage outlives every session, so text about an undisclosed
    // finding written on a shared machine sat there for whoever opened the
    // tools next. A draft has an age now.
    belongTo("oidc:ana");
    keep("revise:7", "started before the meeting");
    const key = "openpsirt.draft.oidc:ana:revise:7";
    const held = JSON.parse(window.localStorage.getItem(key)!) as {
      text: string;
      at: number;
    };
    // Two days ago, which is past the window.
    window.localStorage.setItem(
      key,
      JSON.stringify({ text: held.text, at: held.at - 48 * 60 * 60 * 1000 }),
    );
    expect(restore("revise:7")).toBe("");
    expect(window.localStorage.getItem(key)).toBeNull();
  });

  it("clears one draft when its text has been accepted", () => {
    belongTo("oidc:ana");
    keep("revise:7", "sent");
    keep("comment:7", "not sent");
    forget("revise:7");
    expect(restore("revise:7")).toBe("");
    expect(restore("comment:7")).toBe("not sent");
  });

  it("removes a draft rather than storing an empty one", () => {
    belongTo("oidc:ana");
    keep("revise:7", "typed");
    keep("revise:7", "");
    expect(window.localStorage.length).toBe(0);
  });

  it("clears every draft on the browser, whoever wrote them", () => {
    // What signing out rests on. Drafts hold triage text, private findings
    // included, so text surviving a sign-out would be exposed in a way the
    // application itself is not — and a draft left by an earlier session is
    // exactly the one nobody would think to clear.
    belongTo("oidc:ana");
    keep("revise:7", "Ana's");
    belongTo("oidc:ben");
    keep("revise:7", "Ben's");
    keep("comment:9", "Ben's other");

    forgetAll();

    expect(restore("revise:7")).toBe("");
    expect(restore("comment:9")).toBe("");
    belongTo("oidc:ana");
    expect(restore("revise:7")).toBe("");
  });

  it("takes away a draft of your own that has lapsed, on the next sign-in", () => {
    // The sweep's other branch. Restoring a draft checks its age too, so a
    // lapsed one is never handed back either way — but only the sweep takes
    // it out of storage, and how long private triage text sits in a browser
    // for somebody who never reopens the form is what the window is for.
    belongTo("oidc:ana");
    keep("revise:9", "written before a meeting");
    const key = "openpsirt.draft.oidc:ana:revise:9";
    const held = JSON.parse(window.localStorage.getItem(key)!) as { text: string; at: number };
    expect(held.text).toBe("written before a meeting");
    // Older than the window, which nothing else in these tests reaches.
    window.localStorage.setItem(
      key,
      JSON.stringify({ text: held.text, at: held.at - 48 * 3600 * 1000 }),
    );

    // Being recognized again is what runs the sweep.
    belongTo("oidc:ana");

    expect(window.localStorage.getItem(key)).toBeNull();
  });

  it("keeps a draft of your own that is inside the window", () => {
    // The other direction, so the test above cannot pass by sweeping
    // everything.
    belongTo("oidc:ana");
    keep("revise:10", "still being written");
    belongTo("oidc:ana");
    expect(restore("revise:10")).toBe("still being written");
  });

  it("leaves what is not a draft alone", () => {
    // This store holds the chosen theme and which rail groups are folded,
    // under their own names. Signing out is not a reason to forget which
    // colors somebody likes, and a prefix that swept them up would do exactly
    // that.
    //
    // Both are keys production actually writes here, which is what makes the
    // assertion mean anything: forgetAll walks localStorage alone, so a key
    // kept anywhere else survives it whether or not the prefix is right, and
    // asserting on one would pin nothing.
    window.localStorage.setItem("openpsirt.look", "dusk");
    window.localStorage.setItem("openpsirt.rail", '["manage"]');
    belongTo("oidc:ana");
    keep("revise:7", "typed");

    forgetAll();

    expect(restore("revise:7")).toBe("");
    expect(window.localStorage.getItem("openpsirt.look")).toBe("dusk");
    expect(window.localStorage.getItem("openpsirt.rail")).toBe('["manage"]');
  });

  it("does not reach the scope, which is kept for the session rather than the person", () => {
    // Where the scope actually lives, asserted against the store it is in.
    // Nothing clears it on sign-out, which this says plainly rather than
    // leaving somebody to infer it from a localStorage key that is never set.
    window.sessionStorage.setItem("openpsirt.scope", '{"product":"sonic"}');
    belongTo("oidc:ana");

    forgetAll();

    expect(window.sessionStorage.getItem("openpsirt.scope")).toBe('{"product":"sonic"}');
  });
});
