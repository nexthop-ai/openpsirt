// Thrown when the server refuses. Carries the status so a caller can tell an
// ended session from a real failure, and the server's own sentence so the
// screen shows what the server said rather than a sentence invented here.
export class Refused extends Error {
  constructor(
    readonly status: number,
    message: string,
    // What the server said was wrong, item by item, where it said so. A
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

// A choice the server offered, with whatever else it takes to pick one.
export type Choice = { version: string; ecosystem?: string };

// at returns the choices the server attached to one location.
export function at(error: unknown, location: string): Choice[] {
  if (!(error instanceof Refused)) return [];
  return error.details
    .filter((d) => d.location === location && d.message)
    .map((d) => ({
      version: d.message as string,
      ecosystem: typeof d.value?.ecosystem === "string" ? d.value.ecosystem : undefined,
    }));
}

type Answer<T> = { data?: T; error?: unknown; response: Response };

// unwrap turns the client's { data, error } into a value or a throw, so every
// screen handles failure the same way through TanStack Query rather than each
// one inventing its own branch.
export function unwrap<T>({ data, error, response }: Answer<T>): T {
  if (error !== undefined || !response.ok) {
    throw new Refused(response.status, detailOf(error) ?? response.statusText, detailsOf(error));
  }
  return data as T;
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
