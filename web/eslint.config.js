// What tsc cannot see.
//
// The type check here is already strict — unused locals and parameters,
// unchecked indexed access, verbatim module syntax — so this is deliberately
// narrow. It carries the rules that catch real defects a type checker has no
// view of, and nothing that argues about style, which is Prettier's job.
//
// The rules of hooks are the reason it exists: an effect registering a
// document listener with no dependency array re-registers on every render, and
// three of those were here when this was added. No type checker can tell.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
  { ignores: ["dist", "src/api/schema.d.ts"] },
  js.configs.recommended,
  tseslint.configs.recommended,
  reactHooks.configs.flat["recommended-latest"],
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
  },
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: globals.node },
  },
);
