import { describe, expect, it } from "vitest";
import { render } from "./markdown";
import shared from "../../../testdata/xss-corpus.json";

// The live markup a rendering produced. Checked instead of the whole string
// because escaped text is the correct outcome and contains the same words:
// `&lt;svg/onload=…&gt;` is a safe rendering of a dangerous input, and a check
// that could not tell the two apart would fail on the thing working.
function tagsIn(rendered: string): string[] {
  return rendered.match(/<[^>]*>/g) ?? [];
}

// The things that must not survive rendering, whatever route they take in.
// Deliberately crude and deliberately broad: nothing executable, nothing that
// fetches, and no attribute a browser will run. A subtle check here would be a
// second place to get the rules wrong.
//
// Checked against the output rather than against the configuration — asking
// the allowlist whether it allows something proves only that it agrees with
// itself.
const forbidden = [
  "<script",
  "javascript:",
  "onerror",
  "onload",
  "onclick",
  "onmouseover",
  "onfocus",
  "<iframe",
  "<object",
  "<embed",
  "<svg",
  "<img",
  "data:text/html",
  "vbscript:",
  "<style",
  "<link",
  "<meta",
  "<base",
  "srcdoc",
  "formaction",
];

// The corpus, read from the one file the server's submission check reads.
//
// One file, because it was two. The Go list called itself "the same
// corpus" as this one and was 27 payloads shorter — two copies of a security
// corpus diverge in the direction of the one nobody is adding to, and the
// comment saying they were the same is what stopped anybody checking.
//
// Every payload must render inert, whether or not the server refuses it: a
// fenced block holds whatever it holds and escaped text is text, and both
// still reach a browser.
const corpus: string[] = (() => {
  if (shared.payloads.length < 40) {
    throw new Error(
      `the corpus holds ${shared.payloads.length} payloads, so this checks almost nothing`,
    );
  }
  return shared.payloads.map((one) => one.text);
})();

describe("the renderer", () => {
  it("lets nothing in the corpus through", () => {
    for (const payload of corpus) {
      const rendered = render(payload);
      for (const tag of tagsIn(rendered)) {
        const lowered = tag.toLowerCase();
        for (const bad of forbidden) {
          expect(
            lowered,
            `${payload} survived as ${rendered} (live markup ${tag} carries ${bad})`,
          ).not.toContain(bad);
        }
      }
    }
  });

  it("fetches nothing from anywhere", () => {
    // An image fires from the browser of every person who reads the text,
    // from inside the network. On an undisclosed finding that is a disclosure
    // channel, so the element is not permitted at all.
    const out = render("![a](https://example.com/p.gif)\n\n<img src='https://example.com/q.gif'>");
    expect(out).not.toContain("<img");
    expect(out).not.toContain("example.com/p.gif");
  });

  it("keeps the links people actually write", () => {
    // The point of the allowlist is that it lets ordinary writing through.
    // A sanitizer that refuses real links is one people work around.
    const out = render(
      "See [the advisory](https://example.com/a) or [mail us](mailto:x@example.com).",
    );
    expect(out).toContain('href="https://example.com/a"');
    expect(out).toContain('href="mailto:x@example.com"');
    expect(out).toContain('rel="noreferrer noopener nofollow"');
  });

  it("keeps a link to somewhere in this deployment", () => {
    // DESIGN-text.md: one finding referring to another is ordinary, and the
    // submission check accepts it. The sanitizer went on deleting the anchor
    // and leaving the text — a link accepted when it was written stopped
    // being a link when anybody read it, and nothing reported it.
    const out = render("See [the other one](/findings/CVE-2026-1000).");
    expect(out).toContain('href="/findings/CVE-2026-1000"');
    // Ours, so it opens here rather than being sent away with a policy meant
    // for somebody else's site.
    expect(out).not.toContain('target="_blank"');
  });

  it("does not mistake a protocol-relative address for one of ours", () => {
    // `//somewhere.else/x` has no scheme and is not relative to this
    // deployment: a browser resolves it against the page's protocol and
    // fetches it from another origin. Matched by pattern it reads as a path;
    // resolved, it lands where it really goes.
    for (const link of ["//evil.example/x", "\\\\evil.example\\x"]) {
      for (const tag of tagsIn(render(`[x](${link})`))) {
        expect(tag, `${link} survived as ${tag}`).not.toContain('href="//');
      }
    }
  });

  it("drops a scheme that is merely harmless rather than permitted", () => {
    // restricted link schemes narrows further than a sanitizer's own default
    // does: only http, https and mailto survive. A file or ftp link is not
    // executable and would pass a check that only looks for danger — this is
    // the one that asserts the allowlist is an allowlist rather than a
    // denylist. Asserted on the live markup, not the whole string: a
    // destination the parser declined to make a link of stays in the text,
    // which is a safe outcome that contains the same characters.
    for (const link of ["ftp://example.com/x", "file:///etc/passwd", "tel:+15551234"]) {
      for (const tag of tagsIn(render(`[x](${link})`))) {
        expect(tag, `${link} survived as ${tag}`).not.toContain("href=");
      }
    }
  });

  it("labels a language it knows and drops one it does not", () => {
    // An unknown language keeps its block and loses the label rather than
    // failing — refusing text over a language nobody listed would make the
    // tool argue with people about syntax highlighting.
    expect(render("```go\nx := 1\n```")).toContain('class="language-go"');
    const unknown = render("```nosuchlang\nx := 1\n```");
    expect(unknown).toContain("<code>");
    expect(unknown).not.toContain("nosuchlang");
    expect(unknown).toContain("x := 1");
  });

  it("renders ordinary markdown", () => {
    const out = render("# Title\n\nSome **bold** and `code`.\n\n- one\n- two");
    expect(out).toContain("<h1>");
    expect(out).toContain("<strong>");
    expect(out).toContain("<code>");
    expect(out).toContain("<li>");
  });
});

describe("files attached here", () => {
  const token = "0f9a1b2c3d4e5f60718293a4b5c6d7e8";

  it("renders an image of one from this origin", () => {
    // The content security policy permits images from this origin and no
    // other, so the reference becomes a path here rather than an address at
    // whoever's store the operator runs.
    const html = render(`![a screenshot](attachment:${token})`);
    expect(html).toContain(`src="/v1/attachments/${token}"`);
    expect(html).toContain('referrerpolicy="no-referrer"');
  });

  it("links to one without sending the reader away", () => {
    const html = render(`[the log](attachment:${token})`);
    expect(html).toContain(`href="/v1/attachments/${token}"`);
    // Ours, so not opened in another tab with a policy meant for somebody
    // else's site.
    expect(html).not.toContain('target="_blank"');
  });

  it("takes the whole element away from an image pointing anywhere else", () => {
    // Refused at submission, so this is text written before that rule — and a
    // source that is merely stripped leaves a broken-image icon in the middle
    // of somebody's reasoning.
    for (const source of [
      "![shot](https://example.org/s.png)",
      "![shot](data:image/png;base64,AAAA)",
      "![shot](/static/s.png)",
      "![shot](attachment:not-a-token)",
    ]) {
      const html = render(source);
      expect(html).not.toContain("<img");
      expect(html).not.toContain("example.org");
    }
  });

  it("does not resolve a reference shaped differently", () => {
    const html = render(`[x](attachment:${token.toUpperCase()})`);
    expect(html).not.toContain("/v1/attachments/");
  });
});

describe("identifiers people paste", () => {
  it("links a CVE to the record that defines it", () => {
    // The record rather than the enrichment most people mean by "look up a
    // CVE": they are different documents from different organizations, and
    // linking the summary as the source hides that they disagree.
    const html = render("Fixed by the maintainer, see CVE-2026-31431.");
    expect(html).toContain('href="https://www.cve.org/CVERecord?id=CVE-2026-31431"');
    expect(html).toContain(">CVE-2026-31431</a>");
    expect(html).toContain('rel="noreferrer noopener nofollow"');
  });

  it("links a GitHub advisory identifier", () => {
    const html = render("See GHSA-cfh5-3ghh-wfjx for the write-up.");
    expect(html).toContain("https://github.com/advisories/GHSA-cfh5-3ghh-wfjx");
  });

  it("leaves alone anything that only looks like one", () => {
    // A link that lands on a record for the wrong thing costs more than no
    // link, because it is followed before it is disbelieved.
    for (const source of ["CVE-26-1", "CVE-2026-1", "NOTACVE-2026-31431", "GHSA-zzzz-zzzz-zzzz"]) {
      expect(render(source)).not.toContain("cve.org");
      expect(render(source)).not.toContain("github.com/advisories");
    }
  });

  it("does not link one inside code, or inside a link somebody wrote", () => {
    expect(render("Write `CVE-2026-31431` like that")).not.toContain("cve.org");
    expect(render("```\nCVE-2026-31431\n```\n")).not.toContain("cve.org");
    // A link inside a link is not something a browser renders sensibly.
    const nested = render("[CVE-2026-31431](https://example.org/x)");
    expect(nested).toContain("https://example.org/x");
    expect(nested).not.toContain("cve.org");
  });

  it("keeps the rest of the sentence around it", () => {
    const html = render("Before CVE-2026-31431 after.");
    expect(html).toContain("Before ");
    expect(html).toContain(" after.");
  });

  it("still lets nothing dangerous through", () => {
    // The autolinking runs after the sanitizer, so this checks that it did not
    // put back what the sanitizer had taken out. Asserted on the live markup
    // rather than on the string: escaped text is the correct outcome here and
    // contains the same words, which is what tagsIn exists to tell apart.
    const html = render("<img src=x onerror=alert(1)> CVE-2026-31431");
    for (const tag of tagsIn(html)) {
      expect(tag).not.toMatch(/onerror/i);
      expect(tag).not.toMatch(/^<img/i);
    }
    expect(html).toContain("cve.org");
  });
});

describe("an issue reference", () => {
  // REQ-65's internal half. Text could link out to anywhere and to a file held
  // here, and could not say "the same root cause as this issue, wherever we
  // have it" — which is the thing somebody writes on a claim.
  it("becomes this deployment's address for that issue", () => {
    const html = render("[the same root cause](issue:CVE-2026-1234)");
    expect(html).toContain('href="/issues/CVE-2026-1234"');
    expect(html).not.toContain("issue:");
  });

  it("keeps its href, because it is one of ours", () => {
    const html = render("[x](issue:SONIC-2026-245447)");
    expect(html).toContain('href="/issues/SONIC-2026-245447"');
    // Not sent out to another tab with a referrer policy meant for somebody
    // else's site: it is a page of this deployment.
    expect(html).not.toContain('target="_blank"');
  });

  it("drops a destination that is not an identifier", () => {
    for (const bad of [
      "[x](issue:../../secret)",
      "[x](issue:)",
      "[x](issue:CV)",
      "[x](issue:1234-not-a-letter-first)",
    ]) {
      const html = render(bad);
      expect(html).not.toContain("issue:");
      expect(html).not.toContain('href="/issues/');
    }
  });

  // A bare identifier and a written reference are two different citations and
  // both are right. Bare goes to the record that defines the identifier — the
  // world's answer — and is unchanged by any of this; `issue:` goes to what we
  // hold about it. Turning bare into ours would silently retarget every
  // identifier anybody has ever typed.
  it("does not take over what a bare identifier already means", () => {
    const html = render("This is the same as CVE-2026-1234.");
    expect(html).toContain("https://www.cve.org/CVERecord?id=CVE-2026-1234");
    expect(html).not.toContain('href="/issues/');
  });
});
