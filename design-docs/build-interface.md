# Interface checks

The tools `make web-check` runs over the interface source, and the class-name
and whole-interface checks the web tests hold.

Satisfies REQ-75.

## Contents

- [Interface tools](#interface-tools)
- [Web test runs](#web-test-runs)
- [Class-name checks](#class-name-checks)
- [Whole-interface checks](#whole-interface-checks)
- [Limits](#limits)

## Interface tools

| Tool | Covers |
|---|---|
| `tsc` | Strict, with unused locals and parameters, unchecked indexed access, verbatim module syntax |
| ESLint | The rules of hooks, and little else `tsc` misses |
| Prettier | TypeScript and CSS formatting |
| Stylelint | CSS correctness: unknown properties, duplicate selectors, notation; no whitespace rules |
| `npm run classes` | The class-name checks |
| `npm run lint`, after ESLint | A query's data defaulted to an empty list in a file never consulting the read's failure: its error, `known`, a count, a failure line beside a picker, or the component drawing a read's three arms. `silent-read:` and a reason exempt a read. `design-docs/interface.md` § A read that failed |
| `npm run copy` | More than 20 words of paragraph, hint or empty-state detail on a screen at once. `design-docs/interface.md` § Screen copy |

| Rule | Reason |
|---|---|
| Prettier alone formats | |
| ESLint carries the hook rules: an impure read in render, an effect running every time, a value assigned and unused | A style rule firing on working code teaches people to ignore output |
| Writing state from an effect is reported, never refused | Its fix, remounting with a key, must be checked in a browser |

## Web test runs

| Rule | Reason |
|---|---|
| Each test file runs in its own VM context and DOM, inside a child process running file after file | A process per file was 29 s against 9 s on four cores |
| Processes, never threads | Node applies a time zone change only on a main thread, and a zone test passes vacuously under UTC; such a test asserts the zone took effect |
| Whole-interface tests, addresses, query keys, screen copy and control names, share one file and one parse | 0.66 s against 1.19 s |

## Class-name checks

| Check | Rule |
|---|---|
| A class this project defines that Tailwind also defines | Tailwind, imported wholesale, emits a utility for any recognized name, and wins for the properties it sets: `class="col fixed"` takes `position: fixed`. Every class the stylesheet defines is put to Tailwind's compiler, so a new utility is caught |
| A rule that styles nothing | Matched against the whole source, since `col ${kind}` builds a modifier; it reports a name mentioned nowhere. Charting library names and the `language-` prefix are excluded |
| A class on an element nothing styles | A label with no fill is invisible on a dark canvas. Names Tailwind emits are excluded by asking its compiler |
| A modifier whose bare rule draws a box | A modifier such as `.state.warn` whose own rule sets display, margin, padding, border or background, longhands included, styles every element carrying it, so a table chip draws as a callout. A web test reads every stylesheet |

## Whole-interface checks

| Check | Rule |
|---|---|
| An export nothing else names | Fails, the interface's half of `make unreachable`; a test counts as a caller |
| An address no route answers, or one built outside the route module | Fails, and every query parameter the route table lists is held to a read on its screen. A Go test holds server links to the same table. `design-docs/interface.md` § The route table |
| An invalidation whose key no read's key starts with | Fails: the cache matches by prefix, so it refreshes nothing. Compared as far as each key is literal |

## Limits

| Limit | Detail |
|---|---|
| Only literal class names are read | A class built wholly from an interpolation is unseen |
| A name that is also a Tailwind utility passes the collision and unstyled checks | Both ask the same compiler |
| The unused-export check matches names, never imports | A name that is an ordinary word elsewhere passes |
