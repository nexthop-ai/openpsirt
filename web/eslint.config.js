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
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: globals.node },
  },
);
