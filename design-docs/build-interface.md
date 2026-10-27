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
| `tsc` | Strict, with unused locals and parameters, unchecked indexed access and verbatim module syntax |
| ESLint | Only what `tsc` cannot see. The rules of hooks are why it is present |
| Prettier | Formatting of TypeScript and CSS, the counterpart to `gofmt` |
| Stylelint | CSS correctness: unknown properties, duplicate selectors, notation. Nothing about whitespace |
| `npm run classes` | The class-name checks below |
| `npm run lint`, after ESLint | A query's data defaulted to an empty list in a file never consulting that read's failure: its error, `known`, a count, a failure line beside a picker, or handing it whole to the component drawing a read's three arms. A read allowed to be quiet carries `silent-read:` and its reason. `design-docs/interface.md` § A read that failed holds the rule |
| `npm run copy` | A paragraph, hint or empty-state detail putting more than 20 words on a screen at once. `design-docs/interface.md` § Screen copy says what it measures |

| Rule | Reason |
|---|---|
| Formatting belongs to Prettier alone; Stylelint's whitespace rules are off | Two tools disagree |
| ESLint carries the hook rules and little else | A second opinion on style is noise beside a formatter, and a rule firing on working code teaches people to read past the output. The hook rules catch an impure read during render, a dependency list running an effect every time, and a value assigned and never used |
| Writing state from an effect is reported, never refused | The fix, remounting with a key, changes how a component mounts, so each has to be driven in a browser |

## Web test runs

| Rule | Reason |
|---|---|
| Each test file runs in a VM context of its own, with its own DOM, inside a child process running file after file | Starting a process per file was 70% of the run: 29 s against 9 s on four cores |
| They run in processes, never threads | Node applies a time zone change only on a process's main thread, and a test telling a typed minute from a local one passes vacuously under UTC. Such a test asserts the zone took effect |
| The tests reading the whole interface run in one file, over syntax trees built once | A test file is a module graph of its own, so separate files each parse every source: 1.19 s against 0.66 s |

## Class-name checks

| Check | Rule |
|---|---|
| A class this project defines that Tailwind also defines | Tailwind is imported wholesale and emits a utility for any class name in the source it recognizes, so both rules apply and Tailwind's wins for the properties it sets: `class="col fixed"` takes `position: fixed` and leaves the grid. Every class this stylesheet defines is put to Tailwind's compiler, and anything it answers for is a collision, so a utility a later version adds is caught |
| A rule that styles nothing | Matched against the whole source, never `className=` alone, because `col ${kind}` puts a modifier in the markup that appears nowhere as a literal. It finds a name mentioned nowhere at all. Charting library names and the markdown renderer's `language-` prefix are excluded |
| A class applied to an element nothing styles | A label with no fill is invisible on a dark canvas, and a state word with no rule renders like its opposite. Names Tailwind emits a rule for are excluded by asking its compiler |
| A modifier whose bare rule draws a box | A class reached as a modifier, `.state.warn`, whose own rule sets a display, margin, padding, border or background hands it to every element carrying the modifier at the same specificity, so a table chip draws as a callout. A modifier's bare rule sets none of those, longhands included; a web test reads every stylesheet |

## Whole-interface checks

| Check | Rule |
|---|---|
| An export nothing else names | A web test reads every module and fails on an export no other file mentions, the interface's half of `make unreachable`. A test counts as a caller |
| An address no route answers, or one built outside the route module | A web test reads every module for both, and holds every query parameter the route table lists to a read on the screen it renders. A Go test holds every server link to the same table and fails on one spelled outside its package. `design-docs/interface.md` § The route table has the rules |
| An invalidation whose key no read's key starts with | The query cache matches by prefix, so a key nothing reads refreshes nothing and a saved control looks unsaved. Compared as far as each key is literal |

## Limits

| Limit | Detail |
|---|---|
| Only class names written as literals are read | A class assembled wholly from an interpolation is invisible, and the checks stay quiet |
| A name that is also a Tailwind utility passes the collision and unstyled checks either way | Both ask the same compiler |
| The unused-export check matches names, never imports | A name that is an ordinary word elsewhere passes |
