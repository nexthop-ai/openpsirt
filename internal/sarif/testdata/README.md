# Reader fixtures

What each file is, and where it came from.

| File | Origin |
|---|---|
| `src/` | Written here: two translation units and a header both include, each seeded with defects. The header's division by zero is reached from both units, which is the repeat a header's result makes |
| `sonic-cppcheck.sarif` | Written here, for the demo's analysis seed. cppcheck results under a sonic-buildimage checkout at `/home/builder/sonic/`, naming its repositories as the upload client writes them: the top, and the `src/sonic-dhcpmon` and `src/sonic-linkmgrd` submodules, which the demo inventory states as components. Results in each submodule, and one in neither |
| `clang18-a.sarif`, `clang18-b.sarif` | Real output. Ubuntu clang 18.1.3's static analyzer over `src/a.c` and `src/b.c`, one document per unit, written with `clang --analyze -Xclang -analyzer-output=sarif`. Each address is absolute, and the directory the units were analyzed in is replaced by `/home/builder/sonic/`, which is the shape a build host gives it. Unmodified otherwise |
| `cppcheck222.sarif` | Real output. cppcheck 2.22.0 over both units with `--enable=warning --output-format=sarif`, run from `src/`. Its addresses are relative to that directory and name no starting point, and only the rules that fired are listed. Unmodified |
| `clangtidy-artemis.sarif` | Real output, published. clang-tidy's report of a null dereference in a C++ exercise, converted to SARIF by `clang-tidy-sarif` as the ls1intum fork of sarif-rs writes it, which names the check as the rule as upstream does. Taken unmodified from `src/test/resources/test-data/static-code-analysis/reports/clang-tidy.sarif` in github.com/ls1intum/Artemis at commit `8f9d42bc1ddc83f932f34e68f0b6df061c0349af`, under the MIT license. Its address is absolute, under `/var/tmp/testing-dir/assignment/` |
| `codeql2150-cpp.sarif` | Real output, published. CodeQL 2.15.0's C++ queries over a small C++ interpreter, with every query it ran listed as a rule, `primaryLocationLineHash` on each result, and the extraction notifications for each file it expected and extracted. Taken unmodified from `components/codeql/examples/sample-report.sarif` in github.com/shellphish/artiphishell at commit `d5fcf7a2098cbde97e815b0aec5fe15edc24d096`, under the MIT license. Its addresses are under the starting point `%SRCROOT%`, which it leaves undefined |
