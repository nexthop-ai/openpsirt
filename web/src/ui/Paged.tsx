// A list that is a page of something larger says so.
//
// A page of fifty drawn as if it were everything reads as a count, and the
// count is wrong: "twelve pending" over a queue of three hundred, "select all
// 500" against thousands. Where the server says how many there are, the
// footer says how many of them are shown and pages through the rest; where
// it only caps what it returns, the footer says the cap was hit rather than
// letting the cap pass for the whole.
export function Paged({
  shown,
  total,
  offset = 0,
  limit,
  onGo,
  what = "shown",
}: {
  shown: number;
  // How many there are in all, where the server reports it.
  total?: number;
  offset?: number;
  // The most one request returns.
  limit: number;
  // Moves to another page. Absent where the list cannot be paged, in which
  // case only the count is said.
  onGo?: (offset: number) => void;
  what?: string;
}) {
  if (total === undefined) {
    // A hard cap with no total: the only honest thing to say is that the cap
    // was reached, which is all the server has said.
    if (shown < limit) return null;
    return (
      <p className="hint" style={{ margin: "8px 0 0" }}>
        The first {limit.toLocaleString()} are {what}; there may be more.
      </p>
    );
  }
  if (offset === 0 && total <= shown) return null;
  const from = Math.min(offset + 1, total);
  const upto = Math.min(offset + shown, total);
  return (
    <div
      className="hint"
      style={{ margin: "8px 0 0", display: "flex", alignItems: "center", gap: 6 }}
    >
      <span>
        Showing {from.toLocaleString()}–{upto.toLocaleString()} of {total.toLocaleString()}
      </span>
      {onGo && (
        <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          <button
            type="button"
            className="chip"
            disabled={offset === 0}
            onClick={() => onGo(Math.max(0, offset - limit))}
          >
            Previous
          </button>
          <button
            type="button"
            className="chip"
            disabled={upto >= total}
            onClick={() => onGo(offset + limit)}
          >
            Next
          </button>
        </span>
      )}
    </div>
  );
}
