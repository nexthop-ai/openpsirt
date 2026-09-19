import { useWho } from "../app/session";

// The bound on what a screen acting on a selection may do at once.
//
// Every such screen sends one request per selected row, so an unbounded
// selection is one click turning into as many round trips as the filter
// matched — and the server refuses past the deployment's cap anyway. A screen
// that does not read it discovers the limit one refusal at a time, which is
// exactly what the field was added to stop, and it was read by one of the
// three screens that loop.
//
// Zero means the deployment states no cap, and nothing is drawn.
export function useBulkCap(picked: number): { cap: number; over: boolean } {
  const cap = useWho().data?.bulk_cap ?? 0;
  return { cap, over: cap > 0 && picked > cap };
}

// overCapNotice is what a screen says when the selection is past it, in the
// one wording all three use.
export function overCapNotice(cap: number): string {
  return `${cap.toLocaleString()} at a time is what this deployment allows. Narrow the selection.`;
}
