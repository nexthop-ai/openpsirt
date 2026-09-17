import { beforeEach, describe, expect, it } from "vitest";
import {
  belongTo,
  forget,
  forgetAll,
  forgetSession,
  keep,
  keepAnswer,
  restore,
  restoreAnswer,
} from "./drafts";

beforeEach(() => {
  window.localStorage.clear();
  belongTo(undefined);
});

// Where the one draft in the store is, found rather than restated. The key's
// shape is the module's business — its identity segment is encoded, so a
// colon in an identity cannot be read as the separator — and a test that
// retyped it would break on a change that is not a defect and would say
// nothing about the property it is actually pinning.
function theOnlyKey(): string {
  for (let i = 0; i < window.localStorage.length; i++) {
    const key = window.localStorage.key(i);
    if (key?.startsWith("openpsirt.draft.")) return key;
  }
  throw new Error("no draft is stored");
}

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
    const key = theOnlyKey();
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
    const key = theOnlyKey();
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

  it("does not reach the session's own state, which has its own clear", () => {
    // Where the scope actually lives, asserted against the store it is in.
    // forgetAll walks the local store alone; what the tab holds is taken away
    // by forgetSession, and sign-out calls both.
    window.sessionStorage.setItem("openpsirt.scope", '{"product":"sonic"}');
    belongTo("oidc:ana");

    forgetAll();

    expect(window.sessionStorage.getItem("openpsirt.scope")).toBe('{"product":"sonic"}');
  });
});

describe("what signing out takes away", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    belongTo(undefined);
  });

  it("takes the scope and the last judgment, and leaves the preferences", () => {
    // Seeded in the stores production actually writes them to: a key put in
    // the wrong store survives whatever the clear does, so an assertion over
    // one pins nothing.
    //
    // Sign-out is a same-tab navigation, so nothing here goes on its own.
    window.sessionStorage.setItem("openpsirt.scope", '{"product":"sonic"}');
    window.sessionStorage.setItem("openpsirt.decide.last", '{"outcome":"wont-fix"}');
    window.localStorage.setItem("openpsirt.look", "dusk");
    window.localStorage.setItem("openpsirt.rail", '["manage"]');

    forgetSession();

    expect(window.sessionStorage.getItem("openpsirt.scope")).toBeNull();
    expect(window.sessionStorage.getItem("openpsirt.decide.last")).toBeNull();
    // Preferences, not session state. Signing out is not a reason to forget
    // which colors somebody likes.
    expect(window.localStorage.getItem("openpsirt.look")).toBe("dusk");
    expect(window.localStorage.getItem("openpsirt.rail")).toBe('["manage"]');
  });

  it("survives a browser that refuses storage", () => {
    const kept = window.sessionStorage.removeItem;
    window.sessionStorage.removeItem = () => {
      throw new Error("storage is off");
    };
    expect(() => forgetSession()).not.toThrow();
    window.sessionStorage.removeItem = kept;
  });
});

// The sweep is the whole of the control that stops one person being handed
// another's text, and it is a prefix test over a key built by joining two
// fields with a colon. Neither field excludes one.
describe("whose draft is whose", () => {
  beforeEach(() => {
    window.localStorage.clear();
    belongTo(undefined);
  });

  it("does not read one identity as a prefix of another", () => {
    // `alice` and `alice:b` are both admissible identities — nothing refuses a
    // colon — and what a draft is about is colon-rich by construction. Joined
    // unencoded, alice's prefix matched alice:b's key, so the sweep classed
    // one person's text as the other's and left it in the browser.
    belongTo("alice:b");
    keep("decide:P:S:V:CVE-2026-1:pkg", "theirs");
    expect(restore("decide:P:S:V:CVE-2026-1:pkg")).toBe("theirs");

    belongTo("alice");

    expect(restore("decide:P:S:V:CVE-2026-1:pkg")).toBe("");
    expect(window.localStorage.length).toBe(0);
  });

  it("keeps a person's own drafts across a sign-in", () => {
    // The other direction, so the test above cannot pass by sweeping
    // everything an encoded key produces.
    belongTo("alice:b");
    keep("decide:P:S:V:CVE-2026-1:pkg", "mine");
    belongTo("alice:b");
    expect(restore("decide:P:S:V:CVE-2026-1:pkg")).toBe("mine");
  });
});

describe("what was chosen, beside what was typed", () => {
  it("gives back the answer as well as the prose", () => {
    belongTo("oidc:ana");
    keep("decide:mine:master:broadcom:CVE-1:curl:8.0", "the argument");
    keepAnswer("decide:mine:master:broadcom:CVE-1:curl:8.0", {
      outcome: "not-applicable",
      justification: "vulnerable_code_not_present",
    });
    expect(restore("decide:mine:master:broadcom:CVE-1:curl:8.0")).toBe("the argument");
    expect(restoreAnswer("decide:mine:master:broadcom:CVE-1:curl:8.0")).toEqual({
      outcome: "not-applicable",
      justification: "vulnerable_code_not_present",
    });
  });

  it("keeps the answer per finding, like the prose", () => {
    belongTo("oidc:ana");
    keepAnswer("decide:a", { outcome: "deferred", until: "2026-12-01" });
    expect(restoreAnswer("decide:b")).toEqual({});
  });

  it("is nobody else's", () => {
    belongTo("oidc:ana");
    keepAnswer("decide:a", { outcome: "wont-fix" });
    // Somebody else arriving on this browser clears what is not theirs, which
    // is the whole reason a draft is safe to keep at all — and the answer is
    // the same draft.
    belongTo("oidc:ben");
    expect(restoreAnswer("decide:a")).toEqual({});
  });

  it("goes when the decision it belonged to is accepted", () => {
    belongTo("oidc:ana");
    keep("decide:a", "the argument");
    keepAnswer("decide:a", { outcome: "wont-fix" });
    forget("decide:a");
    expect(restore("decide:a")).toBe("");
    // Both halves. Cleared apart, an accepted decision left its outcome behind
    // to be offered against the next thing decided at the same place.
    expect(restoreAnswer("decide:a")).toEqual({});
  });

  it("keeps nothing where nothing was chosen", () => {
    belongTo("oidc:ana");
    keepAnswer("decide:a", { outcome: "wont-fix" });
    keepAnswer("decide:a", {});
    expect(restoreAnswer("decide:a")).toEqual({});
  });

  it("reads an unreadable answer as none", () => {
    belongTo("oidc:ana");
    keep("decide:a:answer", "not an object");
    expect(restoreAnswer("decide:a")).toEqual({});
  });
});
