// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// What tsc cannot see.
//
// The type check here is already strict — unused locals and parameters,
// unchecked indexed access, verbatim module syntax — so this is deliberately
// narrow. It carries the rules that catch real defects a type checker has no
// view of, and nothing that argues about style, which is Prettier's job.
//
// The rules of hooks are the reason it exists: an effect registering a
// document listener with no dependency array re-registers on every render,
// and no type checker can tell.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

// An ESLint rule refusing a disable directive that gives no reason.
//
// A disable switches a rule off where it would otherwise have caught a
// defect, so the line says why the exception is deliberate, after ESLint's
// own `--` separator: `eslint-disable-next-line rule -- reason`. Enabling a
// rule again needs no reason. It lives in this file because cached lint
// results are kept while this file is unchanged, so a rule in a file of its
// own could change under results cached for the old one.

const DISABLE = /^\s*eslint-disable(?:-line|-next-line)?(?=\s|$)/;
const REASON = /\s--\s*\S/;

// Whether a comment's text is a disable directive with no reason after it.
function unreasoned(text) {
  return DISABLE.test(text) && !REASON.test(text);
}

export const reasonedDisables = {
  meta: {
    type: "problem",
    docs: { description: "Require a reason on every eslint-disable directive" },
    schema: [],
    messages: {
      unreasoned: "Say why this exception is deliberate, after ' -- ' on the directive itself.",
    },
  },
  create(context) {
    return {
      Program() {
        for (const comment of context.sourceCode.getAllComments()) {
          if (unreasoned(comment.value)) {
            context.report({ loc: comment.loc, messageId: "unreasoned" });
          }
        }
      },
    };
  },
};

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
  // A rule switched off says why, on the directive, and a directive that
  // switches off nothing is an error rather than a warning.
  {
    linterOptions: { reportUnusedDisableDirectives: "error" },
    plugins: { local: { rules: { "reasoned-disables": reasonedDisables } } },
    rules: { "local/reasoned-disables": "error" },
  },
  // A label table over a word the server sends is keyed on the generated
  // union, so a word the server adds is a compile error rather than a raw
  // token on screen. A table over an open set says so with a disable naming
  // why.
  {
    files: ["src/screens/**/*.{ts,tsx}", "src/ui/**/*.{ts,tsx}", "src/app/**/*.{ts,tsx}"],
    ignores: ["**/*.test.{ts,tsx}"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "VariableDeclarator[init.type='ObjectExpression'][init.properties.length>0] > Identifier > TSTypeAnnotation > TSTypeReference[typeName.name='Record'] > TSTypeParameterInstantiation > TSStringKeyword:first-child",
          message:
            "Key this table on the generated union for the word it labels, or say why its keys are an open set.",
        },
        {
          selector:
            "TSSatisfiesExpression[expression.type='ObjectExpression'][expression.properties.length>0] > TSTypeReference[typeName.name='Record'] > TSTypeParameterInstantiation > TSStringKeyword:first-child",
          message:
            "Key this table on the generated union for the word it labels, or say why its keys are an open set.",
        },
        {
          selector:
            "VariableDeclarator[init.type='ObjectExpression'][init.properties.length>0] > Identifier > TSTypeAnnotation > TSTypeReference[typeName.name='Partial'] > TSTypeParameterInstantiation > TSTypeReference[typeName.name='Record'] > TSTypeParameterInstantiation > TSStringKeyword:first-child",
          message:
            "Key this table on the generated union for the word it labels, or say why its keys are an open set.",
        },
      ],
    },
  },
  // An address from outside is linked through Outward alone, which checks it
  // and draws what fails as words. A caller of the check itself is a caller
  // that can forget half of it.
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["**/*.test.{ts,tsx}", "src/ui/Outward.tsx"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["**/addressable"],
              importNames: ["linkable"],
              message: "Link an outside address with <Outward>, which checks it.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: globals.node },
  },
);
