import { useState } from "react";
import { overCapNotice, useBulkCap } from "../ui/bulk";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Body } from "../api/client";
import { pathTo, usePaging } from "./list";
import { scopeQuery, useScope } from "../app/scope";
import { useWho } from "../app/session";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Holder } from "../ui/Holder";
import { Failed } from "../ui/Failed";
import { Severity, Exploited } from "../ui/Severity";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";

// A page of what nobody holds. The head says the total; the page says what
// of it is in front of somebody.
const PAGE = 50;

// Work nobody owns, across every product somebody can see. Unassigned is a
// state to be asked about rather than an absence: work that falls between
// people is invisible unless it can be listed, and it is exactly what hides
// when every screen shows one product.
export function Unassigned() {
  const scope = scopeQuery(useScope());
  const { offset, go } = usePaging();
  const queries = useQueryClient();
  // The rows themselves, not just their keys.
  //
  // The selection survives paging and the page does not, so a loop built from
  // what is on screen acts on a part of what was ticked — and then reports and
  // clears the whole of it. Holding the row is what lets the action iterate
  // the selection.
  const [picked, setPicked] = useState<Map<string, Owned>>(new Map());
  // Which of them were refused, so a second press retries those and not the
  // ones already recorded.
  const [refused, setRefused] = useState<unknown>(null);
  const { cap, over } = useBulkCap(picked.size);
  const [person, setPerson] = useState("");
  const rows = useQuery({
    queryKey: ["unassigned", scope, offset],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/unassigned", { params: { query: { limit: PAGE, offset, ...scope } } }),
      ),
  });
  const me = useWho();
  // Who may be offered here, rather than everybody. Listing people asks for
  // administration, so a triager saw "Assign to…" and nothing else.
  //
  // The narrower question is per product, and this list spans every product
  // somebody can see — so the picker fills once a product is chosen, and
  // taking work yourself works either way, which is the case that was most
  // obviously missing.

  const assign = useMutation({
    mutationFn: async (to: { row: Owned; person: string; team?: boolean }) =>
      unwrap(
        await api.PUT(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/findings/{vulnerability}/components/{component}/assignment",
          {
            params: {
              path: {
                product: to.row.product ?? "",
                stream: to.row.stream ?? "",
                variant: to.row.variant ?? "",
                vulnerability: to.row.vulnerability ?? "",
                component: to.row.component ?? "",
              },
            },
            body: to.team ? { team: to.person } : { person: to.person },
          },
        ),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["unassigned"] });
      void queries.invalidateQueries({ queryKey: ["holdings"] });
      void queries.invalidateQueries({ queryKey: ["home"] });
    },
  });

  if (rows.isPending) return <Loading />;
  if (rows.isError) {
    return <Failed error={rows.error} what="What is unassigned could not be read." />;
  }

  const items = rows.data?.items ?? [];
  // What identifies a row for picking, which is what it is *about* rather than
  // where it happens to be listed. The build is one of several where the code
  // is built more than one way, so including it would give the same piece of
  // work two keys if the representative ever changed.
  const keyOf = (row: Owned) =>
    `${row.product} ${row.vulnerability} ${row.component} ${row.version}`;

  // The same action repeated, not a different one — each finding records who
  // it went to and when.
  //
  // Over the selection rather than over the page, and every refusal is carried
  // to the end rather than stopping at the first: a partial run that stops
  // leaves some rows recorded and some not, with nothing on screen saying
  // which. What is left ticked afterwards is exactly what was refused, so
  // pressing again retries those alone.
  async function assignTo(to: string, team?: boolean) {
    const left = new Map<string, Owned>();
    let failure: unknown = null;
    for (const [key, row] of picked) {
      try {
        await assign.mutateAsync({ row, person: to, team });
      } catch (error) {
        left.set(key, row);
        failure ??= error;
      }
    }
    setPicked(left);
    setRefused(failure);
  }

  return (
    <>
      <div className="screen-head">
        <h2>Unassigned</h2>
        <p>
          Open findings with nobody assigned,{" "}
          {scope.product
            ? [scope.product, scope.stream, scope.variant].filter(Boolean).join(" · ")
            : "across every product you can see"}{" "}
          · {(rows.data?.total ?? 0).toLocaleString()} in total
        </p>
      </div>

      {refused != null && (
        <Failed error={refused} what="Some of those could not be assigned, and stay selected." />
      )}

      {items.length === 0 ? (
        <Empty title="Everything open has somebody on it." />
      ) : (
        <>
          <div className="batchbar">
            <span>
              <b>{picked.size === 0 ? "Nothing selected" : `${picked.size} selected`}</b>
            </span>
            {/* Bounded by what this deployment allows in one act, and said
                rather than met one refusal at a time: both buttons here send
                a request per selected row. */}
            {over && (
              <span className="alert" role="status">
                {overCapNotice(cap)}
              </span>
            )}
            <span className="spacer" />
            {/* Taking unowned work is a triager's own and needs nobody's
                picker, so it is a button of its own rather than a step
                through a select that may be empty. */}
            <button
              type="button"
              className="btn"
              disabled={picked.size === 0 || me.data?.identity == null || assign.isPending || over}
              onClick={() => void assignTo(me.data!.identity)}
            >
              {picked.size === 0 ? "Take" : `Take ${picked.size}`}
            </button>
            {/* Who may hold this is a per-product question, and this list
                spans every product somebody can see — so it fills once a
                product is chosen. Taking work yourself needs no picker and
                works either way, which is the button beside it. */}
            <div style={{ minWidth: 220 }}>
              <Holder
                product={scope.product ?? ""}
                value={null}
                // Said in the control rather than only in a tooltip: a box
                // that looks live, does nothing, and explains itself on hover
                // is one somebody clicks into and gets no answer from.
                placeholder={scope.product ? "Assign to…" : "Pick a product to assign"}
                none="Nobody"
                disabled={!scope.product}
                onPick={(held) => setPerson(held ? `${held.kind}:${held.identity}` : "")}
              />
            </div>
            <button
              type="button"
              className="btn"
              disabled={picked.size === 0 || !person || assign.isPending || over}
              onClick={() =>
                void assignTo(person.slice(person.indexOf(":") + 1), person.startsWith("team:"))
              }
            >
              {picked.size === 0 ? "Assign" : `Assign ${picked.size}`}
            </button>
          </div>

          <Wide style={{ marginTop: 10 }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 34 }}>
                    <input
                      type="checkbox"
                      aria-label="Select every row shown"
                      checked={picked.size > 0 && items.every((row) => picked.has(keyOf(row)))}
                      onChange={(event) => {
                        // The page, added to or taken out of the selection —
                        // which spans pages, so this cannot replace it.
                        const next = new Map(picked);
                        for (const row of items) {
                          if (event.target.checked) next.set(keyOf(row), row);
                          else next.delete(keyOf(row));
                        }
                        setPicked(next);
                      }}
                    />
                  </th>
                  <th>Severity</th>
                  <th>Issue</th>
                  <th>Component</th>
                  <th>Build</th>
                  <th className="num">Locations</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={keyOf(row)} className="row">
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select ${row.vulnerability}`}
                        checked={picked.has(keyOf(row))}
                        onChange={(event) => {
                          const next = new Map(picked);
                          if (event.target.checked) next.set(keyOf(row), row);
                          else next.delete(keyOf(row));
                          setPicked(next);
                        }}
                      />
                    </td>
                    <td>
                      <Severity word={row.severity} />
                    </td>
                    <td>
                      <Link
                        to={pathTo(
                          {
                            product: row.product ?? "",
                            stream: row.stream ?? "",
                            variant: row.variant ?? "",
                          },
                          row,
                        )}
                        className="id"
                      >
                        {row.vulnerability}
                      </Link>{" "}
                      <Exploited when={row.exploited} />
                    </td>
                    <td>
                      <span className="id">{row.component}</span>{" "}
                      <span className="id" style={{ color: "var(--faint)" }}>
                        {row.version}
                      </span>
                    </td>
                    <td className="hint">
                      {row.product}
                      {(row.builds ?? 1) > 1 ? (
                        // Not the one build named on the row. The same code
                        // built several ways is one piece of work — assigning
                        // it takes on every build of it — and naming one would
                        // read as being about that one.
                        <> · {row.builds} builds</>
                      ) : (
                        <>
                          {" "}
                          · {row.stream} · {row.variant}
                        </>
                      )}
                    </td>
                    <td className="num">{row.places}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
          <Paged
            shown={items.length}
            total={rows.data?.total}
            offset={offset}
            limit={PAGE}
            onGo={go}
          />
        </>
      )}
    </>
  );
}

type Owned = Body<"UnassignedBody">;
