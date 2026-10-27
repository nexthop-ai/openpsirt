# Client fixtures

What each file is, and where it came from. The sources the outputs describe
are the reader's, in `internal/sarif/testdata/src/`.

| File | Origin |
|---|---|
| `clang18-a.plist`, `clang18-b.plist` | Real output. Ubuntu clang 18.1.3's static analyzer over `a.c` and `b.c`, one document per unit, written with `clang --analyze -Xclang -analyzer-output=plist-multi-file` from the source directory. Its paths are relative to that directory. Unmodified |
| `cppcheck222.xml` | Written here in cppcheck 2.22's XML version 2 shape, for the results its SARIF over the same sources reports, with the `information` entry cppcheck writes for a system header it cannot find |
| `endings/` | Written here: one function three times, kept with line feeds, kept with carriage returns and line feeds, and left to the checkout. `.gitattributes` says which |
