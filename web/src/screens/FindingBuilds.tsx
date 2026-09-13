import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";

// Correcting which builds a recorded flaw affects.
//
// **The endpoint answered and nothing called it.** The first belief about a
// flaw is written down before the analysis is finished — that is the point of
// being able to record one early — so it has to be correctable, and it was
// correctable only by somebody holding a shell.
//
// **The set is stated as a whole**, not edited a build at a time, because a
// set somebody can read back and check is not the same thing as a stream of
// additions and removals. Widening opens findings; narrowing closes them as
// `invalid` — never affected, rather than no longer affected — which is why a
// reason is required whenever a build comes out, and why the words here say
// "was never affected" rather than "fixed".
//
// Folded until asked, like the advisory: it reads two lists to draw itself,
// and most visits to a finding are not somebody correcting its filing.

// The separator between a build's two names. Not a character either name can
// hold, so a key cannot be two builds.
const APART = "\u0000";

export function AffectedBuilds({
  product,
  vulnerability,
}: {
  product: string;
  vulnerability: string;
}) {
  const queries = useQueryClient();
  const [open, setOpen] = useState(false);
  // Null until somebody touches a box: what is drawn is what the flaw says
  // now, and a set nobody has edited is not an edit.
  const [chosen, setChosen] = useState<string[] | null>(null);
  const [because, setBecause] = useState("");

  // Every build of this product a scan has reached. The endpoint refuses one
  // that has never been scanned, so offering it would be offering a refusal.
  const builds = useQuery({
    enabled: open,
    queryKey: ["releases", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/releases", { params: { path: { product } } })),
    retry: false,
  });
  // Which of them hold it now. The same request the issue screen makes, under
  // the same key, so opening this after reading that page asks nothing.
  const holds = useQuery({
    enabled: open,
    queryKey: ["issue", vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/issues/{vulnerability}", {
          params: { path: { vulnerability }, query: { limit: 200 } },
        }),
      ),
    retry: false,
  });

  const now = useMemo(() => {
    const held = new Set<string>();
    for (const row of holds.data?.items ?? []) {
      if (row.product === product) held.add(`${row.stream}${APART}${row.variant}`);
    }
    return held;
  }, [holds.data, product]);

  const set = useMutation({
    mutationFn: async (picked: string[]) =>
      unwrap(
        await api.PUT("/v1/products/{product}/issues/{vulnerability}/builds", {
          params: { path: { product, vulnerability } },
          body: {
            builds: picked.map((each) => {
              const [stream = "", variant = ""] = each.split(APART);
              return { stream, variant };
            }),
            ...(because.trim() ? { reason: because.trim() } : {}),
          },
        }),
      ),
    onSuccess: () => {
      setChosen(null);
      setBecause("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
      void queries.invalidateQueries({ queryKey: ["findings"] });
      void queries.invalidateQueries({ queryKey: ["issue", vulnerability] });
    },
  });

  const picked = chosen ?? [...now];
  const held = new Set(picked);
  const removing = [...now].filter((each) => !held.has(each));
  const adding = picked.filter((each) => !now.has(each));
  const changed = removing.length > 0 || adding.length > 0;
  const wantsReason = removing.length > 0 && because.trim() === "";

  return (
    <div className="card">
      <h3>
        <button
          type="button"
          className="linkish"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open ? "▾" : "▸"} Which builds this affects
        </button>
      </h3>
      <p className="reading" style={{ marginBottom: 8 }}>
        Send the full list, not a change to it. Removing a build closes its findings as
        <b>never affected</b>, which needs a reason.
      </p>
      {!open ? null : builds.isPending || holds.isPending ? (
        <p className="hint">Reading what this is filed against…</p>
      ) : (
        <>
          {set.error != null && <Failed error={set.error} what="That could not be set." />}
          {set.data && (
            <p className="hint">
              {set.data.added} added · {set.data.closed} closed as never affected.
            </p>
          )}
          <div className="field">
            {(builds.data?.items ?? []).map((build) => {
              const key = `${build.stream}${APART}${build.variant}`;
              return (
                <label key={key} style={{ display: "block", marginBottom: 4 }}>
                  <input
                    type="checkbox"
                    checked={held.has(key)}
                    onChange={(event) => {
                      const next = new Set(picked);
                      if (event.target.checked) next.add(key);
                      else next.delete(key);
                      setChosen([...next]);
                    }}
                  />{" "}
                  <span className="id">
                    {build.stream} · {build.variant}
                  </span>{" "}
                  <span className="hint">{build.kind === "tag" ? "tag" : "branch"}</span>
                </label>
              );
            })}
          </div>
          {removing.length > 0 && (
            <div className="field">
              <label htmlFor="affects-because">
                Why{" "}
                {removing.length === 1 ? "that build was" : `those ${removing.length} builds were`}{" "}
                never affected{" "}
                <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--sev-high)" }}>
                  required
                </span>
              </label>
              <textarea
                id="affects-because"
                value={because}
                placeholder="The vulnerable code was added after this branch was cut."
                onChange={(event) => setBecause(event.target.value)}
                style={{ minHeight: 70 }}
              />
            </div>
          )}
          <button
            type="button"
            className="btn"
            disabled={!changed || picked.length === 0 || wantsReason || set.isPending}
            onClick={() => set.mutate(picked)}
          >
            {set.isPending ? "Setting…" : "Set which builds it affects"}
          </button>
          {picked.length === 0 && (
            <span className="hint" style={{ marginLeft: 8 }}>
              Pick at least one build.
            </span>
          )}
        </>
      )}
    </div>
  );
}
