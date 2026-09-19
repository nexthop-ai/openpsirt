import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "./Failed";
import { Outcome } from "./Outcome";
import { Wide } from "./Wide";

// The triage a line inherits from another, and the part of it to take.
//
// The reach is computed either way; what this adds is the choosing. A carry
// that happened silently would be one nobody reviewed, and the four groups are
// four different things — only two of them are questions.
export function Carried({ at }: { at: { product: string; stream: string; variant: string } }) {
  const [from, setFrom] = useState("");
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const queries = useQueryClient();

  // The other lines of this product, to carry from.
  const streams = useQuery({
    queryKey: ["streams", at.product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams", {
          params: { path: { product: at.product } },
        }),
      ),
  });

  const preview = useQuery({
    queryKey: ["carried", at, from],
    enabled: from !== "",
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/carried", {
          params: { path: at, query: { from, from_variant: at.variant } },
        }),
      ),
  });

  const carry = useMutation({
    mutationFn: async (decisions: number[]) =>
      unwrap(
        await api.POST("/v1/products/{product}/streams/{stream}/variants/{variant}/carried", {
          params: { path: at, query: { from, from_variant: at.variant } },
          body: { decisions },
        }),
      ),
    onSuccess: async () => {
      setPicked(new Set());
      await queries.invalidateQueries({ queryKey: ["carried"] });
      await queries.invalidateQueries({ queryKey: ["queue"] });
    },
  });

  const others = (streams.data?.items ?? []).filter((s) => s.name !== at.stream);
  const moved = preview.data?.moved ?? [];
  const postponed = preview.data?.postponed ?? [];

  function toggle(id: number) {
    const next = new Set(picked);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setPicked(next);
  }

  return (
    <section className="panel" style={{ marginTop: 14 }}>
      <h3 title="Carried from another release line">Inherited decisions</h3>

      <div className="field" style={{ maxWidth: "40ch" }}>
        <label htmlFor="carry-from">Carry from</label>
        <select id="carry-from" value={from} onChange={(e) => setFrom(e.target.value)}>
          <option value="">Pick a line</option>
          {others.map((s) => (
            <option key={s.name} value={s.name ?? ""}>
              {s.name} {s.kind === "tag" ? "(tag)" : ""}
            </option>
          ))}
        </select>
      </div>

      {preview.isError && (
        <Failed
          error={preview.error}
          what="The claims this line would inherit could not be read."
        />
      )}

      {from !== "" && preview.data && (
        <>
          <p className="hint">
            <b>{preview.data.applying ?? 0}</b> reach this line already · <b>{moved.length}</b>{" "}
            moved · <b>{postponed.length}</b> postponed · <b>{preview.data.absent ?? 0}</b> cover
            nothing here.
          </p>

          {moved.length === 0 && postponed.length === 0 ? (
            <p className="hint">Nothing here needs a fresh answer.</p>
          ) : (
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 32 }} />
                    <th>Issue</th>
                    <th>Component</th>
                    <th>Was</th>
                    <th>Now</th>
                    <th>Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {[...moved, ...postponed].map((row) => (
                    <tr key={row.decision}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Carry ${row.vulnerability}`}
                          checked={picked.has(row.decision ?? 0)}
                          onChange={() => toggle(row.decision ?? 0)}
                        />
                      </td>
                      <td>
                        <span className="id">{row.vulnerability}</span>
                      </td>
                      <td>{row.component}</td>
                      <td className="hint">{row.was}</td>
                      <td>{row.now}</td>
                      <td>
                        <Outcome outcome={row.outcome} />
                        {/* A deferral carries the total it has already run
                            for, because that is what agreeing to it again
                            agrees to. */}
                        {row.deferred_days ? (
                          <span className="hint"> · put off {row.deferred_days} days so far</span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Wide>
          )}

          {carry.error != null && <Failed error={carry.error} what="Those could not be carried." />}
          <div className="actions" style={{ marginTop: 8 }}>
            <button
              type="button"
              className="btn"
              disabled={picked.size === 0 || carry.isPending}
              onClick={() => carry.mutate([...picked])}
            >
              Carry {picked.size > 0 ? picked.size : ""} for review
            </button>
            <span className="hint">
              Each needs a second person. The version moved, so the old judgment stopped applying.
            </span>
          </div>
        </>
      )}
    </section>
  );
}
