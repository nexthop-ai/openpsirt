// Design tokens referred to and never defined.
//
// A `var(--thing)` naming a token that does not exist is not an error anywhere:
// CSS drops the declaration, the element keeps whatever it inherited, and the
// screen looks nearly right. Three of them were in the stylesheet — a radius, a
// type step and a color for something bad — each the result of a token being
// renamed with one reference left behind, and each invisible until somebody
// compared two screens side by side.
//
// So every reference is put to the set of definitions. A fallback counts as a
// definition of nothing: `var(--gone, 8px)` is a deliberate default and is
// exempt, because the author said what happens when it is absent.
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname);
const src = path.join(here, "..", "src");

async function sources(dir) {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...(await sources(full)));
    } else if (/\.(css|tsx|ts)$/.test(entry.name) && entry.name !== "schema.d.ts") {
      found.push(full);
    }
  }
  return found;
}

const files = await sources(src);

// What is defined: any `--name:` at the start of a declaration, in a
// stylesheet or in a style object a component hands an element — a token set
// per element is as defined as one set on a selector, and the swatch that
// draws two colors is exactly that.
const defined = new Set();
for (const file of files) {
  const text = await readFile(file, "utf8");
  for (const [, name] of text.matchAll(/(?:^|[;{,]|\s)["']?(--[a-zA-Z0-9_-]+)["']?\s*:/g)) {
    defined.add(name);
  }
}

// What is referred to, minus the ones carrying their own fallback.
const missing = new Map();
for (const file of files) {
  const text = await readFile(file, "utf8");
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const [, name, rest] of lines[i].matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)\s*(,?)/g)) {
      if (rest === "," || defined.has(name)) continue;
      const at = `${path.relative(path.join(here, ".."), file)}:${i + 1}`;
      if (!missing.has(name)) missing.set(name, []);
      missing.get(name).push(at);
    }
  }
}

if (missing.size === 0) {
  console.log(`every token referred to is defined (${defined.size} of them)`);
  process.exit(0);
}
for (const [name, where] of [...missing].sort()) {
  console.error(`${name} is used at ${where.join(", ")} and defined nowhere`);
}
console.error(
  `\n${missing.size} token(s) named and never defined. CSS drops the ` +
    `declaration silently, so the screen looks nearly right.`,
);
process.exit(1);
