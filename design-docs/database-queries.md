# Database queries

Rules every query obeys because the four engines differ: identifier quoting,
pattern matching, affected-row counts, recursion, collation, text, bulk
inserts, and the query shapes an engine answers wrongly.

Satisfies REQ-71.

## Contents

- [Identifier quoting](#identifier-quoting)
- [Silently wrong query shapes](#silently-wrong-query-shapes)
- [Pattern matching](#pattern-matching)
- [Affected-row counts](#affected-row-counts)
- [Recursion bound](#recursion-bound)
- [Collation](#collation)
- [Text truncation](#text-truncation)
- [Bulk inserts](#bulk-inserts)
- [Limits](#limits)

## Identifier quoting

Every identifier is quoted: declared, named and invented. A word is reserved
only bare, and the engines reserve different words: a column named `rank` is
refused by MySQL alone.

| Rule | Reason |
|---|---|
| A column reference a statement composes is quoted through one function in the database package | The quote character is the engine's own answer |
| A helper taking a column takes a named type: a quoted column, or an expression the caller composed | A plain string could carry a name from a query parameter |
| MySQL and MariaDB connections are asked for standard quoting, appended to the mode in force, never assigned | Assigning replaces an operator's mode |
| Strictness is named in the same mode | Without it a nine-character string is stored in a four-character column as four, silently |
| `NO_BACKSLASH_ESCAPES` is taken out of the mode whoever set it | The driver escapes a backslash as two, and under that mode both are stored, doubling on every write |
| A name a query invents avoids reserved words as well | MySQL 8 reserves `GROUPS`, so `AS groups` fails there |
| A helper placing a given column as written takes it quoted, and lists the columns it accepts quoted | |
| A helper building a column from a given alias writes the quotes around the alias | |

`make reserved` checks quoting by reading source as text.

| The gate reads | How |
|---|---|
| A name a query invents | Checked for being bare, never against the reserved list, which misses a word an engine reserves next, as MySQL 8.0 reserved `rank`, `groups` and `cume_dist` |
| Where a name is invented | `AS <word>`, a table renamed in a migration, and an alias a model declares |
| The migrations | The data-definition keywords too, with comments stripped first |
| A declared table or column, wherever a query writes it | In a statement, in a builder method's SQL argument, and in a clause assembled in a variable and handed to one. A column alone and after a qualifier; a qualified one is fixed by quoting both halves |
| What is a column | A declared name in lower case, since keywords are in capitals. A word before a parenthesis is a function. Arguments after a builder method's SQL are values |
| Which literals are statements | Any literal containing `FROM "` or `JOIN "`, wherever it is held. Every table is quoted, so prose never carries the marker |
| A qualified column outside a statement | An alias, a dot and a declared column, all lower case, in any literal of running code |
| A name invented with `AS` | Read as a declared column wherever a reference qualifies it, in any file |
| A table a query names | Read in every literal outside the migrations, against the tables the migrations made. A literal that is only a table name is read where a method naming a table is called |
| A clause assembled in a variable | Every literal the function puts in a variable, read where it is handed over, once |
| Tests | Held to it; the checker's own fixtures are its input and exempt |
| A schema declaration | A name after a keyword that always precedes one, and a name where a column belongs in the outermost parentheses. Any other statement kind, a condition, or a clause after an index's columns is refused as unreadable, so the first sequence, view, trigger, check or partial index extends the sweep |
| A name a migration declares | Against the list of words the engines reserve, regenerated from the engines |

| Literal | Read as |
|---|---|
| A clause: a comparison with spaces, a parenthesis, a list of qualified names, `LIKE`, `BETWEEN`, or another capitalized keyword | Every qualified column in it |
| One qualified name alone, handed to a call, returned, a field's value, or a constant of a named type | That name |
| An argument of a builder method or function that quotes its argument | Nothing: the callee quotes it |
| An argument of a standard library call, a map's key, a constant of plain string type | Nothing: a setting's key is written the same way |
| Anything in a test | Nothing: a test hands a detector the bare spellings it exists to find |

The alias half reads only literals recognizable as queries, and never doc
comments, because "as" is in most English sentences; the table half reads every
literal, because a query whose tables are all bare carries no marker. The pass counts the
literals it reads and fails on none. The schema is also read back from each
database and checked there. Two tests hold the silent truncation the mode's
strictness prevents, each seen to fail with the fix reverted.

## Silently wrong query shapes

A query written once that an engine answers wrongly, mostly without an error.

| Shape | What happens |
|---|---|
| A window function in a grouped statement over a join, with `HAVING` and a `COUNT(DISTINCT …)` | MariaDB 10.5 to 13.0 evaluates the `HAVING` wrongly with no error, and a distinct count beside it empties the result. Without any one of the four it is correct. The window goes in a statement over the grouping, read as a derived table |
| `SUM(CASE … END)` where an integer is wanted | A decimal on two engines, cast differently per engine. Counted as two `COUNT`s instead |
| Ordering by a column the grouping does not determine | MySQL refuses it |
| A correlated subquery in the select list, grouped on the same expression | MySQL and MariaDB refuse it under their default mode. Written as a join grouped on a column, counting distinct identifiers because the join multiplies rows |

## Pattern matching

A search term is matched literally: "50%" means a name containing "50%", and
"a_b" means what it says.

| Rule | Reason |
|---|---|
| Every value in a `LIKE` is escaped, and every clause states its escape character | SQLite has no default escape |
| The escape character is `#`, never a backslash | MySQL and MariaDB read `ESCAPE '\'` as an unterminated string |
| The escaping lives in the database package | |
| A pattern the code wrote is not escaped; a value somebody supplied is | A trailing `/%` matching an ecosystem prefix is the pattern; the ecosystem in it is not |
| A prefix that must match exactly is also compared exactly | SQLite's `LIKE` ignores ASCII case, so a trail matched by an identity's prefix would report another identity differing in case |
| Folding happens in Go | `LOWER()` is ASCII-only on SQLite. The component-name search and the name a build's claim is about compare against a folded copy made on the way in; an API key's name and a personal token's are stored folded |
| Issue identifiers, package identifiers, descriptions and the person picker compare against `LOWER()` of the column | It differs only outside ASCII |

## Affected-row counts

A conditional write learns of a lost race only from the number of rows its
update touched: zero means somebody got there first.

| Rule | Reason |
|---|---|
| Every connection reports rows matched, not changed | MySQL and MariaDB report rows changed by default, so a write whose values were already correct reports a false conflict |
| The count is read through one helper | An unreadable count is a fault, never zero, which callers read as a lost race |

A test asserts the count on all four engines, and removing the setting fails
exactly the two.

## Recursion bound

| Engine | Stops a recursive statement after | Told |
|---|---|---|
| MySQL | a thousand rounds, with an error | `cte_max_recursion_depth` of a million |
| MariaDB | a thousand rounds, returning what it has, with a warning | `max_recursive_iterations` of a million |
| PostgreSQL, SQLite | nothing | nothing |

A graph walk carries no depth, so its rounds are the longest chain, which may
pass a thousand and never passes the build's component count. The setting is made on the connection, named per engine, and left alone where the
database URL sets it. A test walks a chain of 1,100 down and up on all four,
and fails on MySQL and MariaDB without it.

## Collation

MySQL and MariaDB compare text case-insensitively by default. The tables that
need exact matching, such as a product's declared name, are created with binary
comparison.

## Text truncation

| Rule | Reason |
|---|---|
| A value shortened to fit is cut between characters, never at a byte offset | A byte offset lands inside a multi-byte character about two times in three |
| Keeping the head and keeping the tail are two functions, called everywhere | One trims backward and the other forward |
| A lookup key is cut in characters, as its column is declared; a value bounded by a byte budget is cut in bytes, on a character boundary | Which values are cut and which refused: `design-docs/database-schema.md` § Column widths |
| The query builder writes text as valid UTF-8, an invalid byte becoming U+FFFD | It writes every value into the statement text |
| A NUL fails the statement on PostgreSQL and SQLite, before reaching the engine, and is dropped on MySQL and MariaDB | |
| Text another program wrote is stored whatever its encoding, each NUL dropped where it is read | A scanner's output, git's account of a remote, an inventory, a VEX document, a package index's answer, a CVE record and a supplier's answer carry any bytes |

A test on each engine ends a scan run with a failure, a caution and versions
carrying invalid bytes and a NUL, and records a patch repository failure
quoting a remote error in invalid bytes and a NUL. Each is stored valid with
the surrounding text kept, and the repository waits its day.

## Bulk inserts

| Rule | Reason |
|---|---|
| Rows are written 500 to a statement | MySQL and MariaDB cap a statement's size, sixteen megabytes at the lowest default |
| A writer needing identifiers gets the ones the database stored | MySQL reports the first and the step. A cluster sets the step to its node count, so counting by one names a neighbor's row (REQ-71) |
| A writer needing no identifier reads none back | |
| On PostgreSQL such a batch is one array a column | The server parses a list of rows a value at a time and an array whole: 42 µs a row against 55 µs |
| A row type with a column naming its own default keeps the list of rows | A defaulted column, or a zero value stored as null, is decided row by row |

PostgreSQL checks each foreign key with a query per row, which is most of what
remains; MySQL and MariaDB check inside the storage engine.
`design-docs/database-measurements.md` § Bulk insert statements has the run.

A test writes the same rows through both statement kinds, every column kind and
syntax-like text among them, and compares what is stored. Another compares
each identifier a keyed insert returns with the one stored, across batches, and
on MySQL and MariaDB in a session stepping by three.

## Limits

| Limit | Detail |
|---|---|
| The quoting gate reads source as text | There is no parser for four dialects. A name reaching SQL from outside the file, a constant of plain string type holding one qualified name, and a column built from an alias at run time are invisible to it and are quoted where written |
