# Reader fixtures

What each file is, and where it came from.

| File | Origin |
|---|---|
| `src/` | Written here: two translation units and a header both include, each seeded with defects. The header's division by zero is reached from both units, which is the repeat a header's result makes |
| `clang18-a.sarif`, `clang18-b.sarif` | Real output. Ubuntu clang 18.1.3's static analyzer over `src/a.c` and `src/b.c`, one document per unit, written with `clang --analyze -Xclang -analyzer-output=sarif`. Each address is absolute, and the directory the units were analyzed in is replaced by `/home/builder/sonic/`, which is the shape a build host gives it. Unmodified otherwise |
| `cppcheck222.sarif` | Real output. cppcheck 2.22.0 over both units with `--enable=warning --output-format=sarif`, run from `src/`. Its addresses are relative to that directory and name no starting point, and only the rules that fired are listed. Unmodified |
