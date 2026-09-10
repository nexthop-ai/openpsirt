import { Refused } from "../api/queries";

// A failure says what the server said. Inventing a friendlier sentence here
// would hide the one the server wrote — which names the line to fix, or which
// part of a declaration is missing, and is the more useful of the two.
export function Failed({ error, what }: { error: unknown; what: string }) {
  const said = error instanceof Refused ? error.message : null;
  return (
    <div
      className="card"
      style={{
        borderColor: "var(--sev-critical)",
        background: "var(--sev-exploited-bg)",
      }}
    >
      <p style={{ margin: 0, fontWeight: 600 }}>{what}</p>
      {said && (
        <p className="hint" style={{ margin: "4px 0 0" }}>
          {said}
        </p>
      )}
    </div>
  );
}
