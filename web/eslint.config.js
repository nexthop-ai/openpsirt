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
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      // Reported rather than refused, and the distinction is deliberate.
      //
      // Every instance here is one pattern: local state reset when a prop
      // changes or when a panel opens. React's answer is to remount with a
      // key rather than to write state from an effect, which is a change to
      // how nine components are mounted rather than a change inside them —
      // each needing to be driven in a browser to know it still behaves.
      //
      // Left visible instead of switched off, because the rule is right and
      // the count is the honest measure of the work. Switching it off would
      // make the same nine invisible and let a tenth join them.
      "react-hooks/set-state-in-effect": "warn",
    },
  },
);
