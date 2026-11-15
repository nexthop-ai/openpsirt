// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The published API document, read for the bounds the generated client drops:
// openapi-typescript keeps a parameter's type and leaves out its maximum and
// an array's maxItems.
import { readFileSync } from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { WEB } from "./parsed.mjs";

export function apiDocument() {
  return yaml.load(readFileSync(path.join(WEB, "..", "docs", "reference", "openapi.yaml"), "utf8"));
}

// The operation of one identifier, or nothing where the document has none.
function operationOf(document, id) {
  for (const methods of Object.values(document.paths ?? {})) {
    for (const operation of Object.values(methods)) {
      if (operation?.operationId === id) return operation;
    }
  }
  return undefined;
}

// A schema with its reference followed.
function resolved(document, schema) {
  const ref = schema?.$ref;
  if (!ref) return schema;
  return ref
    .replace(/^#\//, "")
    .split("/")
    .reduce((at, part) => at?.[part], document);
}

// The maximum of one query parameter of one operation.
export function queryMaximum(document, id, name) {
  const parameter = (operationOf(document, id)?.parameters ?? []).find(
    (each) => each.in === "query" && each.name === name,
  );
  return parameter?.schema?.maximum;
}

// The maxItems of one field of one operation's JSON request body.
export function bodyMaxItems(document, id, field) {
  const body = operationOf(document, id)?.requestBody?.content?.["application/json"]?.schema;
  return resolved(document, body)?.properties?.[field]?.maxItems;
}
