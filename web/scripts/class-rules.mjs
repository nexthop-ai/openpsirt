// How a stylesheet's class rules are read, and which of them cannot be right.
//
// A module of its own so that a test can import it. The program beside this
// one does its work at import time — it walks the stylesheets, compiles
// Tailwind and exits non-zero on a finding — so a test that imported it would
// take the runner down at exactly the moment the check is doing its job.

// A modifier sharing a name with a text style is ordinary and correct:
// `.linkish.id` beside a bare `.id` that sets a font is two rules that agree.
// What cannot be right is a modifier whose bare rule takes an element **out of
// normal flow** — a chip does not become positioned because of the word beside
// it. So the test is the property, not the name.
const escapes = /(^|[\s;])(position\s*:\s*(fixed|absolute|sticky)|inset\s*:)/;

// rulesIn reads one stylesheet as two maps: what each bare class declares, and
// which classes are only ever reached as a modifier beside another.
//
// **Comments go first.** A rule is read as the text before its brace, and a
// comment sitting above one is part of that text — so a prose paragraph above
// `.overpane` was read as the selector and the rule was never seen.
//
// Lifted out of the walk so it can be asked directly: a gate reachable only by
// running the program over the tree has an exit code for its only evidence,
// and an exit code cannot tell a check that found nothing from one that looked
// at nothing.
export function rulesIn(text, into = { declared: new Map(), modifiers: new Map() }) {
  const css = text.replace(/\/\*[\s\S]*?\*\//g, "");
  for (const [, selector, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    for (const part of selector.split(",")) {
      const one = part.trim();
      if (!/^(?:\.[-\w]+)+$/.test(one)) continue;
      const names = [...one.matchAll(/\.([-\w]+)/g)].map(([, name]) => name);
      if (names.length === 1) {
        into.declared.set(names[0], (into.declared.get(names[0]) ?? "") + ";" + body);
      } else {
        for (const name of names.slice(1)) {
          if (!into.modifiers.has(name)) into.modifiers.set(name, one);
        }
      }
    }
  }
  return into;
}

// positionedModifiers is every class reached as a modifier whose own bare rule
// takes an element out of normal flow.
//
// Narrow on purpose: a modifier sharing a name with a text style is ordinary
// and correct. What cannot be right is a chip becoming positioned because of
// the word beside it — so the test is the property rather than the name.
export function positionedModifiers({ declared, modifiers }) {
  return [...modifiers.keys()].filter((name) => escapes.test(declared.get(name) ?? "")).sort();
}
