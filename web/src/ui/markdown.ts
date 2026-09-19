import MarkdownIt from "markdown-it";
import DOMPurify from "dompurify";

// Rendering moved here when the API stopped returning markup, so this carries
// the half of the policy that travels with rendering (DESIGN-text.md). The
// other half — what may be submitted at all, which links survive, what a
// reference resolves to — still runs on the server before anything is stored,
// because it needs data and authorization checks no browser holds.
//
// The assertions are about the *output*, not the configuration. Asking
// the allowlist whether it allows something proves only that it agrees with
// itself.

// The fenced-block tags that may reach a class attribute. This list is this
// renderer's own — the server emits no markup and holds no such list — because
// a language tag is somebody's input, and three backticks followed by chosen
// text landing in markup is small and real.
//
// An unknown language keeps its block and loses the label rather than failing.
// Refusing to render over a language nobody listed would make the tool argue
// with people about syntax highlighting.
const LANGUAGES = new Set([
  "bash",
  "c",
  "cpp",
  "diff",
  "dockerfile",
  "go",
  "hcl",
  "ini",
  "java",
  "javascript",
  "json",
  "makefile",
  "markdown",
  "nginx",
  "none",
  "patch",
  "perl",
  "php",
  "python",
  "ruby",
  "rust",
  "shell",
  "sql",
  "text",
  "toml",
  "typescript",
  "xml",
  "yaml",
]);

const md = new MarkdownIt({
  // Raw markup is disabled at the parser rather than stripped afterwards.
  // Something never turned into a tag cannot be a tag that was missed.
  html: false,
  linkify: true,
  breaks: false,
  // The language becomes a class and nothing else. Coloring is applied
  // afterwards, over already-sanitized markup.
  highlight: () => "",
});

// The language tag, allowlisted, as a class the highlighter can find.
md.renderer.rules.fence = (tokens, index) => {
  const token = tokens[index];
  if (!token) return "";
  const stated = (token.info || "").trim().split(/\s+/)[0]?.toLowerCase() ?? "";
  const language = LANGUAGES.has(stated) ? stated : "";
  const body = md.utils.escapeHtml(token.content);
  const attr = language ? ` class="language-${language}"` : "";
  return `<pre><code${attr}>${body}</code></pre>\n`;
};

// Nothing is fetched from anywhere else, ever. An image fires from the browser
// of every person who reads the text, from inside the network, telling whoever
// wrote it who is looking at which finding and when — on an undisclosed
// finding that is a disclosure channel.
//
// An image of a file attached here is not that: it is fetched from this origin
// through a path that asks who is looking. The content security policy permits
// images from this origin and from `data:`, so the policy is not what stops an
// image pointing elsewhere — the rewrite below is. So the element is permitted
// and its source is rewritten to that path before anything sees it; an image
// pointing anywhere else loses the whole element rather than the attribute,
// because an img with no src is a broken-image icon in the middle of somebody
// reasoning.
const ALLOWED_TAGS = [
  "p",
  "br",
  "hr",
  "strong",
  "em",
  "del",
  "code",
  "pre",
  "blockquote",
  "ul",
  "ol",
  "li",
  "a",
  "img",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "table",
  "thead",
  "tbody",
  "tr",
  "th",
  "td",
];

const ALLOWED_ATTR = ["href", "title", "class", "src", "alt"];

// The identifiers this tool's whole subject is. People paste them constantly,
// and a tool about vulnerabilities that leaves them as plain words makes the
// most repeated action there is into a copy and a paste.
//
// The patterns are the strict ones, not "anything starting with CVE": a link
// that lands on a record for the wrong thing costs more than no link, because
// it is followed before it is disbelieved.
const IDENTIFIERS: { pattern: RegExp; where: (id: string) => string }[] = [
  {
    pattern: /\bCVE-[0-9]{4}-[0-9]{4,}\b/g,
    // The record that defines the identifier, rather than the enrichment most
    // people mean when they say "look up a CVE". They are different documents
    // from different organizations, and linking the summary as though it were
    // the source is how a disagreement between them goes unnoticed.
    where: (id) => `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`,
  },
  {
    pattern:
      /\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b/g,
    where: (id) => `https://github.com/advisories/${encodeURIComponent(id)}`,
  },
];

// A file held here, as the text refers to it: an opaque identifier and never
// an address. The identifier is what this deployment mints — 32 hexadecimal
// characters — and anything else shaped differently is a broken reference
// rather than something to resolve.
const ATTACHMENT = /^attachment:([0-9a-f]{32})$/;

// One vulnerability, wherever this deployment has it, as the text refers to
// it: an identifier and never an address. A finding is an issue at a place in
// a build, and "the same root cause as CVE-2026-1234" does not mean a place —
// it means the issue, and the issue has an address of its own.
//
// The shape matches what the submission check accepts, so a reference accepted
// when it was written is still a link when somebody reads it. Anything else is
// a broken reference rather than something to resolve.
const ISSUE = /^issue:([A-Za-z][A-Za-z0-9._-]{2,63})$/;

// The page an issue is read on. A page of this deployment, so it keeps its
// href and the router follows it without a reload.
function issuePath(identifier: string): string {
  return `/issues/${encodeURIComponent(identifier)}`;
}

// The address one is actually fetched from. Same origin, so the content security
// policy permits it and the request carries who is asking.
function fetchPath(token: string): string {
  return `/v1/attachments/${token}`;
}

// Only the schemes a link may use once attachment references have been
// rewritten into paths. Everything else is dropped, autolinked text included.
const SCHEMES = /^(?:https?:|mailto:)/i;

// sameDeployment reports whether a destination lands on the page's own origin.
function sameDeployment(href: string): boolean {
  if (href === "") return false;
  try {
    return new URL(href, window.location.href).origin === window.location.origin;
  } catch {
    return false;
  }
}

// Anything that leaves this is what a reader sees, so the class attribute is
// held to the one prefix the highlighter needs rather than left open — a class
// is a small thing to permit and a large thing to permit freely.
function tidy(node: Element) {
  anchor(node);
  const className = node.getAttribute("class");
  if (className !== null && !/^language-[a-z0-9+#-]+$/.test(className)) {
    node.removeAttribute("class");
  }
}

// anchor is the half of that about where a link goes.
//
// Separated so the class check above runs on every element that leaves here.
// Written as early returns inside one function, the two anchors that keep
// their href — a file held here, and a link into this deployment — left
// without it, so the stated invariant was true of some of what the sanitizer
// emits rather than of all of it.
function anchor(node: Element) {
  if (node.tagName !== "A") {
    return;
  }
  const href = node.getAttribute("href") ?? "";
  if (!SCHEMES.test(href)) {
    // A link to somewhere in this deployment keeps its href — a rewritten
    // attachment reference among them, which is why an early return above
    // this answers nothing of its own: `/v1/attachments/x` has
    // no scheme, so it arrives here and resolves against this page.
    //
    // One finding referring to another is ordinary, the submission check
    // accepts it, and deleting the anchor while leaving the text is the
    // disagreement DESIGN-text.md records as the one nothing reports:
    // accepted when it was written, no longer a link when anybody read it.
    //
    // Resolved against this page rather than matched against a pattern,
    // because `//somewhere.else/x` is relative-looking and is not ours, and
    // a scheme the browser refuses resolves to no origin at all.
    if (sameDeployment(href)) {
      return;
    }
    node.removeAttribute("href");
  } else {
    // Nothing linked from here is ours. No referrer, and no handle back to
    // this window from whatever opens.
    node.setAttribute("rel", "noreferrer noopener nofollow");
    node.setAttribute("target", "_blank");
  }
}

// Rewrites a reference to a file held here into the path it is fetched from,
// and removes an image pointing anywhere else.
//
// Before the sanitizer rather than after. `attachment:` is a scheme
// nothing recognizes, so an attribute still carrying it when the sanitizer
// runs is dropped as an unknown scheme — and then the rewrite would have
// nothing to rewrite. By the time anything is judged, what is there is a
// relative path to this origin.
function resolve(node: Element) {
  if (node.tagName === "IMG") {
    const found = ATTACHMENT.exec(node.getAttribute("src") ?? "");
    if (!found?.[1]) {
      // Refused at submission, so this is text written before that rule. An
      // image with its source taken away is a broken-image icon; the whole
      // element goes.
      node.remove();
      return;
    }
    node.setAttribute("src", fetchPath(found[1]));
    // Never a channel back to whoever wrote the text, whatever the file is.
    node.setAttribute("loading", "lazy");
    node.setAttribute("referrerpolicy", "no-referrer");
    return;
  }
  if (node.tagName === "A") {
    // An issue reference becomes this deployment's own address for that
    // issue. Before the sanitizer for the reason an attachment is: `issue:`
    // is a scheme nothing recognizes, so an href still carrying it when the
    // sanitizer runs is dropped as unknown, and the rewrite would then have
    // nothing to rewrite.
    const issue = ISSUE.exec(node.getAttribute("href") ?? "");
    if (issue?.[1]) {
      node.setAttribute("href", issuePath(issue[1]));
      return;
    }
    const found = ATTACHMENT.exec(node.getAttribute("href") ?? "");
    if (found?.[1]) {
      node.setAttribute("href", fetchPath(found[1]));
    }
  }
}

// Turns bare identifiers in prose into links.
//
// Text nodes only, and never inside a link or a code block. An identifier
// inside somebody's own link would produce a link inside a link, which no
// browser renders as anything sensible; inside a code span it is being shown
// rather than referred to.
//
// Run over the sanitized document rather than over the markdown, so what is
// linked is text that survived, and the elements this creates are made here
// rather than parsed from a string — there is no markup round trip for
// anything to be smuggled through.
function autolink(root: Element | DocumentFragment) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const found: Text[] = [];
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const parent = (node as Text).parentElement;
    if (!parent || parent.closest("a, code, pre")) continue;
    found.push(node as Text);
  }

  for (const node of found) {
    const text = node.nodeValue ?? "";
    const hits: { at: number; end: number; id: string; href: string }[] = [];
    for (const { pattern, where } of IDENTIFIERS) {
      pattern.lastIndex = 0;
      for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
        hits.push({ at: m.index, end: m.index + m[0].length, id: m[0], href: where(m[0]) });
      }
    }
    if (hits.length === 0) continue;
    hits.sort((a, b) => a.at - b.at);

    const pieces = document.createDocumentFragment();
    let cursor = 0;
    for (const hit of hits) {
      // Two patterns cannot both claim the same run of text, but a sort does
      // not prove that — so anything starting inside what was already taken
      // is skipped rather than producing overlapping elements.
      if (hit.at < cursor) continue;
      if (hit.at > cursor) pieces.append(text.slice(cursor, hit.at));
      const link = document.createElement("a");
      link.setAttribute("href", hit.href);
      link.setAttribute("rel", "noreferrer noopener nofollow");
      link.setAttribute("target", "_blank");
      link.textContent = hit.id;
      pieces.append(link);
      cursor = hit.end;
    }
    if (cursor < text.length) pieces.append(text.slice(cursor));
    node.replaceWith(pieces);
  }
}

let hooked = false;
function hook() {
  if (hooked) return;
  DOMPurify.addHook("beforeSanitizeAttributes", (node) => {
    if (node instanceof Element) resolve(node);
  });
  DOMPurify.addHook("afterSanitizeAttributes", (node) => {
    if (node instanceof Element) tidy(node);
  });
  hooked = true;
}

// render turns markdown into markup a browser may be handed.
//
// Sanitized on the way out every time, never stored. A rule tightened next
// month then applies to text written last year, which it could not if the
// markup had been kept when the text arrived.
export function render(source: string): string {
  hook();
  const clean = DOMPurify.sanitize(md.render(source), {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    // ADD_ATTR *extends* what is allowed, so these are accepted from the
    // document as well as set by the hook. What stops an author supplying
    // them is that raw markup is off at the parser (`html: false` above), so
    // no author-written attribute reaches the sanitizer at all — and that is
    // the control to keep, not this list. These are here so the hook's own
    // additions survive attribute sanitizing.
    ADD_ATTR: ["rel", "target", "loading", "referrerpolicy"],
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    // Returned as nodes rather than as a string, so that the identifiers below
    // are linked by building elements instead of by editing markup. A regular
    // expression rewriting HTML is the shape that eventually matches inside a
    // tag it was not thinking about.
    RETURN_DOM_FRAGMENT: true,
  });
  autolink(clean);
  const holder = document.createElement("div");
  holder.append(clean);
  return holder.innerHTML;
}
