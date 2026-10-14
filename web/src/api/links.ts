// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { paths } from "./schema";

// An address a browser fetches directly: a file to download, a document to
// open, an attachment to show. Built from the generated paths rather than
// written out, so a route the server renames or reshapes is a compile error
// here instead of a link that answers 404.

// The names a path's placeholders take, read out of the path itself.
type Placeholders<S extends string> = S extends `${string}{${infer Name}}${infer Rest}`
  ? Name | Placeholders<Rest>
  : never;

// What a link asks, as the screen holds it. A string is a query already
// encoded, without its leading `?`. A key whose value is undefined is left
// off.
type Asked = URLSearchParams | string | Record<string, string | readonly string[] | undefined>;

// The values for a path's placeholders, required exactly where it has some.
type Filled<Names extends string> = [Names] extends [never]
  ? { path?: undefined; query?: Asked }
  : { path: Record<Names, string | number>; query?: Asked };

// A route the server answers as a file, in either format.
type FileRoute = Extract<keyof paths, `${string}.{format}`>;

// The query a link carries, encoded, or the empty string.
function encoded(query: Asked | undefined): string {
  if (query === undefined) return "";
  if (typeof query === "string") return query;
  if (query instanceof URLSearchParams) return query.toString();
  const out = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    if (typeof value === "string") out.append(key, value);
    else for (const each of value) out.append(key, each);
  }
  return out.toString();
}

// The address one route answers at, each placeholder filled and escaped for a
// path segment. A placeholder left without a value is refused rather than sent
// as its own name.
export function linkTo<P extends keyof paths & string>(
  path: P,
  ...[given]: [Placeholders<P>] extends [never] ? [Filled<never>?] : [Filled<Placeholders<P>>]
): string {
  const values: Record<string, string | number> = given?.path ?? {};
  const filled = path.replace(/\{([^}]+)\}/g, (_, name: string) => {
    if (!Object.hasOwn(values, name)) {
      throw new Error(`${path} needs a value for {${name}}`);
    }
    return encodeURIComponent(String(values[name]));
  });
  const query = encoded(given?.query);
  return query ? filled + "?" + query : filled;
}

// The address a report's file is fetched from, in the format asked for, with
// the same question the screen asked.
export function fileAt<P extends FileRoute>(
  path: P,
  format: "csv" | "json",
  ...[given]: [Exclude<Placeholders<P>, "format">] extends [never]
    ? [Filled<never>?]
    : [Filled<Exclude<Placeholders<P>, "format">>]
): string {
  const route = path as keyof paths & string;
  return (linkTo as (path: string, given: Filled<string>) => string)(route, {
    path: { ...(given?.path ?? {}), format },
    query: given?.query,
  });
}
