// The guided review's own question, decided apart from the sheet
// that draws it.
//
// The review exists to confirm one thing: builds holding this issue at another
// version, where a tick is a claim about code nobody has looked at. Builds
// already matching are named there rather than asked about — a decision
// reaches those by lookup — and the confirmation that follows names them too.
// So where no build holds another version, both steps are a summary somebody
// presses through, which is two keystrokes on every decision of a day that
// runs to about a hundred and fifty.
//
// The care is in the empty answer that means "not read yet". A request still
// in flight, or one that failed, contributes nothing, and treating that
// silence as "no other versions" would submit past the question rather than
// skip a question that was not there. So the reach counts as read only when it
// has actually come back, and anything else opens the sheet.
export function nothingToReview(
  reach: { isSuccess: boolean },
  offered: readonly unknown[],
): boolean {
  if (!reach.isSuccess) return false;
  return offered.length === 0;
}
