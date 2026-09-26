// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Thrown when the server refuses. Carries the status so a caller can tell an
// ended session from a real failure, and the server's own sentence so the
// screen shows what the server said rather than a sentence invented here.
export class Refused extends Error {
  constructor(
    readonly status: number,
    message: string,
    // The server's own faults, item by item, where it stated them. A
    // refusal that names fifteen versions is a paragraph as a sentence and a
    // list of choices as a list — the screen can only offer the second.
    readonly details: {
      location?: string;
      message?: string;
      value?: Record<string, unknown>;
    }[] = [],
  ) {
    super(message);
    this.name = "Refused";
  }
}

// The status a refusal carried, or nothing where it is not one.
//
// For the call sites where one of the two statuses `notYours` folds together
// has a meaning of its own: the reporter read answers 404 for "nobody recorded
// a reporter", which is the card's ordinary content, and 403 for "you do not
// hold triage here", which is not.
export function statusOf(error: unknown): number | undefined {
  return error instanceof Refused ? error.status : undefined;
}

// A refusal that is the server saying this is not somebody's to see.
//
// A card that is quiet for one person and drawn for another is the shape
// several screens want, and the test for it has to be the status rather than
// "the read failed": 403 and 404 are answers, and a 500 is a question nobody
// answered. Reading the second as the first draws an empty card that says
// there is nothing there.
export function notYours(error: unknown): boolean {
  return error instanceof Refused && (error.status === 403 || error.status === 404);
}

// A choice the server offered, with whatever else it takes to pick one.
export type Choice = { version: string; ecosystem?: string; namespace?: string };

// whichOf is the query that picks one component where its name is not enough:
// the version, and the ecosystem and namespace where a build holds one name at
// one version as two components. Empty parts are left out, and the server reads
// a part left out as "any".
export function whichOf(of: { version?: string; ecosystem?: string; namespace?: string }): {
  version?: string;
  ecosystem?: string;
  namespace?: string;
} {
  return {
    ...(of.version ? { version: of.version } : {}),
    ...(of.ecosystem ? { ecosystem: of.ecosystem } : {}),
    ...(of.namespace ? { namespace: of.namespace } : {}),
  };
}

// at returns the choices the server attached to one location.
export function at(error: unknown, location: string): Choice[] {
  if (!(error instanceof Refused)) return [];
  return error.details
    .filter((d) => d.location === location && d.message)
    .map((d) => ({
      version: d.message as string,
      ecosystem: typeof d.value?.ecosystem === "string" ? d.value.ecosystem : undefined,
      namespace: typeof d.value?.namespace === "string" ? d.value.namespace : undefined,
    }));
}

type Answer<T> = { data?: T; error?: unknown; response: Response };

// unwrap turns the client's { data, error } into a value or a throw, so every
// screen handles failure the same way through TanStack Query rather than each
// one inventing its own branch.
export function unwrap<T>({ data, error, response }: Answer<T>): T {
  if (error !== undefined || !response.ok) {
    throw new Refused(response.status, said(error, response), detailsOf(error));
  }
  return data as T;
}

// The sentence to show when the server refuses. Its own where it wrote one,
// the reason phrase where it did not — and the status on its own where there
// is no reason phrase either, which is every HTTP/2 response: the protocol
// carries the code and dropped the phrase, so `statusText` is the empty
// string and a screen showing it shows nothing at all.
function said(error: unknown, response: Response): string {
  return detailOf(error) ?? (response.statusText || `HTTP ${response.status}`);
}

function detailsOf(
  error: unknown,
): { location?: string; message?: string; value?: Record<string, unknown> }[] {
  if (typeof error === "object" && error !== null && "errors" in error) {
    const list = (error as { errors?: unknown }).errors;
    if (Array.isArray(list)) {
      return list.filter(
        (e): e is { location?: string; message?: string; value?: Record<string, unknown> } =>
          typeof e === "object" && e !== null,
      );
    }
  }
  return [];
}

function detailOf(error: unknown): string | undefined {
  if (typeof error === "object" && error !== null && "detail" in error) {
    const detail = (error as { detail?: unknown }).detail;
    if (typeof detail === "string") return detail;
  }
  return undefined;
}
