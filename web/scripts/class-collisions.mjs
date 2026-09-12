// Class names of ours that Tailwind also defines.
//
// Tailwind is imported wholesale into our stylesheet, and it emits a utility
// for any class name in the source that it recognizes. Where that name is also
// one of ours, both rules apply and Tailwind's wins for the properties it
// sets — silently, because the element still has our class and most of our
// rule still works. A column with `class="col fixed"` left the grid and
// nothing failed.
//
// Three names had already been renamed by hand after being found by eye, and a
// fourth was found by a review months later. So the set is derived rather than
// listed: every class our own stylesheet defines is put to Tailwind, and
// anything it answers for is a collision. A name Tailwind adds in a later
// version is caught the next time this runs.
//
// Utilities used deliberately in markup are not the subject. What is checked
// is the names we *define a rule for*, which is where the two can disagree.
import { compile } from "tailwindcss";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const here = path.dirname(new URL(import.meta.url).pathname);
const src = path.join(here, "..", "src");

async function stylesheets(dir) {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...(await stylesheets(full)));
    else if (entry.name.endsWith(".css")) found.push(full);
  }
  return found;
}

// Class selectors we write. Deliberately narrow: a bare `.name`, which is the
// only shape a single-class utility can collide with.
const defined = new Map();
for (const file of await stylesheets(src)) {
  const css = await readFile(file, "utf8");
  // Strip declaration blocks so that only selectors are read.
  for (const selector of css.replace(/\{[^{}]*\}/g, "{}").split(/[{}]/)) {
    for (const [, name] of selector.matchAll(/\.(-?[A-Za-z_][\w-]*)/g)) {
      if (!defined.has(name)) defined.set(name, path.relative(src, file));
    }
  }
}

// Class names of ours that collide with each other.
//
// An element carrying `class="due over"` is matched by `.due`, by `.over` and
// by `.due.over`, and all three apply. That is the point of a modifier — until
// the modifier's name is also a class of ours that means something else
// somewhere else, at which point an element picks up a rule written for a
// different element entirely.
//
// A two-word deadline chip did exactly this. `.over` was the full-screen
// backdrop behind the component dialog — `position: fixed; inset: 0`, half
// black, `z-index: 40` — and `.due.over` was the color an overdue chip is
// written in. A findings row one day late rendered its chip as an overlay
// across the whole viewport: the screen greyed out, nothing dismissed it, and
// because the chip sits inside a row that navigates on click, every click
// anywhere went to that finding.
//
// What is reported is narrow, because a modifier sharing a name with a text
// style is ordinary and correct: `.linkish.id` beside a bare `.id` that sets a
// font is two rules that agree. What cannot be right is a modifier whose bare
// rule takes an element **out of normal flow** — a chip does not become
// positioned because of the word beside it. So the test is the property, not
// the name.
const escapes = /(^|[\s;])(position\s*:\s*(fixed|absolute|sticky)|inset\s*:)/;
const declared = new Map();
const modifiers = new Map();
for (const file of await stylesheets(src)) {
  // Comments go first. A rule is read as the text before its brace, and a
  // comment sitting above one is part of that text — so a prose paragraph
  // above `.overpane` was read as the selector and the rule was never seen.
  const css = (await readFile(file, "utf8")).replace(/\/\*[\s\S]*?\*\//g, "");
  for (const [, selector, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    for (const part of selector.split(",")) {
      const one = part.trim();
      if (!/^(?:\.[-\w]+)+$/.test(one)) continue;
      const names = [...one.matchAll(/\.([-\w]+)/g)].map(([, name]) => name);
      if (names.length === 1) {
        declared.set(names[0], (declared.get(names[0]) ?? "") + ";" + body);
      } else {
        for (const name of names.slice(1)) {
          if (!modifiers.has(name)) modifiers.set(name, one);
        }
      }
    }
  }
}

const positioned = [...modifiers.keys()]
  .filter((name) => escapes.test(declared.get(name) ?? ""))
  .sort();

if (positioned.length > 0) {
  console.error(
    `${positioned.length} class name(s) are used as a modifier beside another class and\n` +
      `also have a rule of their own that takes an element out of normal flow, so\n` +
      `anything carrying both is positioned by a rule written for something else:\n`,
  );
  for (const name of positioned) {
    console.error(`  .${name}  (${defined.get(name)})  reached as ${modifiers.get(name)}`);
  }
  console.error(`\nRename the standalone one — ".overpane" rather than ".over".`);
  process.exit(1);
}

const root = path.dirname(require.resolve("tailwindcss/package.json"));
async function loadTailwind(id, base) {
  const file =
    id === "tailwindcss"
      ? path.join(root, "index.css")
      : path.resolve(base, id.replace(/^tailwindcss\//, root + "/"));
  return { path: file, base: path.dirname(file), content: await readFile(file, "utf8") };
}
const compiler = await compile('@import "tailwindcss";', {
  base: process.cwd(),
  loadStylesheet: loadTailwind,
  async loadModule() {
    throw new Error("this check compiles no modules");
  },
});

// Tailwind has to be imported in a notation Tailwind reads.
//
// `@import url("tailwindcss")` is valid CSS, means the same to a browser, and
// is what stylelint's standard configuration rewrites the string form into on
// sight. Tailwind reads only the string form, so after that rewrite it emits
// no utility at all — and nothing else changes, because the rest of the
// stylesheet is ours and still applies. An editor toolbar rendered as
// unstyled text for a day before anybody looked at it.
//
// Proved by compiling our own stylesheet and asking it for a utility, rather
// than by matching the import line: what has to hold is that utilities come
// out, and a text match would pass on the next notation nobody thought of.
// Font faces are not the subject here, so their imports resolve to nothing.
const ours = await compile(await readFile(path.join(src, "index.css"), "utf8"), {
  base: src,
  async loadStylesheet(id, base) {
    return id === "tailwindcss" || id.startsWith("tailwindcss/")
      ? loadTailwind(id, base)
      : { path: id, base, content: "" };
  },
  async loadModule() {
    throw new Error("this check compiles no modules");
  },
});
if (!/\.rounded-lg[\s,:{]/.test(ours.build(["rounded-lg"]))) {
  console.error(
    "src/index.css emits no Tailwind utilities, so every class from Tailwind is dead.\n\n" +
      '  Import it as `@import "tailwindcss";` — the url() notation compiles to nothing.\n',
  );
  process.exit(1);
}

const names = [...defined.keys()].sort();
const emitted = compiler.build(names);
const clashing = names.filter((name) =>
  new RegExp(`\\.${name.replace(/[-[\]{}()*+?.\\^$|]/g, "\\$&")}(?=[\\s,:{>+~])`).test(emitted),
);

// Class names nothing applies.
//
// A rule for a class no element carries is dead weight that reads as working
// code — `.ring` sat here styling nothing, and was only noticed because
// Tailwind happened to define the same name.
//
// Matched against the whole of the source rather than against `className=`
// alone, because class names are built as well as written: a template literal
// puts `col ${kind}` in the markup and the modifier appears nowhere as a
// literal, so anything stricter reports names that are plainly in use. That
// makes this deliberately weak — it finds a name mentioned nowhere at all,
// which is the case worth finding, and stays quiet otherwise.
const sources = [];
async function scripts(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await scripts(full);
    else if (/\.(tsx?|html)$/.test(entry.name)) sources.push(await readFile(full, "utf8"));
  }
}
await scripts(src);
const markup = sources.join("\n");

// Names that come from somewhere other than our own markup, so their absence
// says nothing: a charting library writes its own, and print rules are matched
// by the browser rather than by us.
const foreign = /^(recharts-|markdown-body$)/;

const unused = names.filter(
  (name) =>
    !foreign.test(name) &&
    !new RegExp(`[\\s"'\`.]${name.replace(/[-[\]{}()*+?.\\^$|]/g, "\\$&")}[\\s"'\`:.]`).test(
      markup,
    ),
);

if (unused.length > 0) {
  console.error(`${unused.length} class name(s) are styled and never applied:\n`);
  for (const name of unused) console.error(`  .${name}  (${defined.get(name)})`);
  console.error(`\nDelete the rule, or apply it.`);
  process.exit(1);
}

if (clashing.length > 0) {
  console.error(
    `${clashing.length} class name(s) we define are also Tailwind utilities, so Tailwind's\n` +
      `rule wins for the properties it sets and ours silently does not apply:\n`,
  );
  for (const name of clashing) console.error(`  .${name}  (${defined.get(name)})`);
  console.error(`\nRename ours — "was-fixed" rather than "fixed".`);
  process.exit(1);
}
console.log(
  `no collisions: ${names.length} class names checked against Tailwind, ` +
    `${modifiers.size} used as a modifier checked against our own rules`,
);
