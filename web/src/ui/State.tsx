// Where a claim has got to. "Pending" and "approved" are different in the one
// way that matters — a claim nobody has agreed to suppresses nothing — so they
// never share a color.
const means: Record<string, string> = {
  proposed: "pending approval. It suppresses nothing yet",
  approved: "approved, and in force",
  withdrawn: "withdrawn. Kept on the record",
  lapsed: "the code moved out from under it, so it no longer applies",
};

const label: Record<string, string> = {
  proposed: "Pending",
  approved: "Approved",
  withdrawn: "Withdrawn",
  lapsed: "Lapsed",
};

const cls: Record<string, string> = {
  proposed: "waiting",
  approved: "agreed",
  withdrawn: "open",
  lapsed: "lapsed",
};

export function State({ state }: { state?: string }) {
  if (!state) return null;
  return (
    <span className={`state ${cls[state] ?? "open"}`} title={means[state]}>
      {label[state] ?? state}
    </span>
  );
}
