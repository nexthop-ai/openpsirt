// The severity ladder, written down more than once.
//
// `src/ui/severities.ts` exists because the order and membership of these
// words had been written out eight times under seven names, with three
// different memberships — and a second copy is not a tidiness problem. It is
// how two screens come to disagree about which words are real: the tree drew
// four bands beside a count of all five, so a quarter of what was under a node
// was invisible and the numbers on the row did not add up to the number beside
// them.
//
// So a list of these words anywhere but there is refused. A `switch` over them
// is not a list — it is a mapping, and every arm is visible — and neither is a
// type. What this looks for is an array literal, which is the shape a ladder
// takes and the shape that silently loses a rung.
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname);
const src = path.join(here, "..", "src");
// Where the ladder is allowed to be written down.
const home = path.join(src, "ui", "severities.ts");

const RUNGS = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "unrated",
  "unknown",
  "negligible",
  "none",
]);

async function sources(dir) {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...(await sources(full)));
    else if (/\.(ts|tsx)$/.test(entry.name) && entry.name !== "schema.d.ts") found.push(full);
  }
  return found;
}

// Every array literal of string literals in a file, as the words it holds.
// Read with a regular expression rather than parsed: a literal list of quoted
// words is a shape a pattern recognizes exactly, and the alternative is a
// TypeScript parser in a check that exists to be cheap enough to always run.
function listsIn(text) {
  const out = [];
  for (const match of text.matchAll(
    /\[\s*((?:"[^"\n]*"|'[^'\n]*')(?:\s*,\s*(?:"[^"\n]*"|'[^'\n]*'))*)\s*,?\s*\]/g,
  )) {
    const words = match[1].split(",").map((each) =>
      each
        .trim()
        .replace(/^["']|["']$/g, "")
        .toLowerCase(),
    );
    out.push({ words, at: text.slice(0, match.index).split("\n").length });
  }
  return out;
}

let bad = 0;
let looked = 0;
for (const file of await sources(src)) {
  if (path.resolve(file) === path.resolve(home)) continue;
  const text = await readFile(file, "utf8");
  looked++;
  for (const { words, at } of listsIn(text)) {
    const rungs = words.filter((word) => RUNGS.has(word));
    // Two of them together is a ladder. One is a word being used.
    if (rungs.length < 2) continue;
    bad++;
    console.error(
      `${path.relative(src, file)}:${at}: [${words.join(", ")}] is the severity ladder written ` +
        `out again — import it from ui/severities.ts, and add the word there if it is missing`,
    );
  }
}
if (bad > 0) {
  console.error(`\n${bad} ${bad === 1 ? "copy" : "copies"} of the ladder outside ui/severities.ts`);
  process.exit(1);
}
console.log(`the severity ladder is written down once (${looked} files checked)`);
