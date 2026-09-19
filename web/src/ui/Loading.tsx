// The placeholder a screen shows while it is waiting.
//
// One component rather than the sentence typed out thirty-nine times in four
// spellings. Nothing about it is clever: the point is that a screen which
// changes how waiting looks changes it everywhere, and that the one thing this
// has to get right is announced rather than left to a reader who cannot see
// the page.
//
// `inline` is for waiting inside a line of text rather than in place of a
// block, which is the one real variation the thirty-nine had between them.
export function Loading({ inline = false }: { inline?: boolean }) {
  const said = "Loading…";
  // Announced politely: a reader using a screen reader otherwise hears nothing
  // between asking and arriving, which is indistinguishable from a page that
  // did nothing.
  if (inline) {
    return (
      <span className="hint" role="status">
        {said}
      </span>
    );
  }
  return (
    <p className="hint" role="status">
      {said}
    </p>
  );
}
