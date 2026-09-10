// What a list says when it has nothing in it. A blank panel reads as broken,
// and "no results" reads as a filter problem even when nothing was filtered —
// so the caller says which of the two this is.
export function Empty({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="card" style={{ textAlign: "center", padding: "34px 20px" }}>
      <p style={{ margin: 0, fontWeight: 600 }}>{title}</p>
      {detail && (
        <p className="hint" style={{ margin: "4px 0 0" }}>
          {detail}
        </p>
      )}
    </div>
  );
}
