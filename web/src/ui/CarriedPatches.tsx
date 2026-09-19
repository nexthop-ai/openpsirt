import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { on } from "../ui/when";
import { notACredential } from "../ui/noautofill";
import { Paged } from "../ui/Paged";
import { Wide } from "./Wide";

// What a build says it deals with itself, over time.
//
// The one thing a version comparison can never see. A distribution carries
// a fix into a package without moving its version, so the only evidence is the
// build saying so in its own inventory — which was stored and read by nothing
// a person could reach.
//
// A history rather than a list of what is true tonight. Each row says when
// the build first said it and when it stopped, because a claim that stopped is
// the interesting one: somebody dropped a patch, and the finding it answered
// is back. A list of what is current would not have that row at all.

const PAGE = 25;

export function CarriedPatches({
  at,
}: {
  at: { product: string; stream: string; variant: string };
}) {
  const [component, setComponent] = useState("");
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(false);

  const carried = useQuery({
    enabled: open,
    queryKey: ["carried-patches", at, component, offset],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/carried-patches",
          {
            params: {
              path: at,
              query: { limit: PAGE, offset, ...(component ? { component } : {}) },
            },
          },
        ),
      ),
  });

  const rows = carried.data?.items ?? [];
  const total = carried.data?.total ?? 0;

  return (
    <section
      className="panel"
      style={{ marginTop: 14 }}
      title="Fixes applied without a version change"
    >
      <h3>
        <button
          type="button"
          className="linkish"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open ? "▾" : "▸"} Backported patches
        </button>
      </h3>
      {!open ? null : carried.isError ? (
        <Failed error={carried.error} what="What this build carries could not be read." />
      ) : (
        <>
          <div className="filters">
            <label className="field">
              <span>About one package</span>
              <input
                {...notACredential}
                type="text"
                value={component}
                placeholder="the name the claim gives"
                onChange={(event) => {
                  setComponent(event.target.value);
                  setOffset(0);
                }}
              />
              <span className="hint">
                Matched on what the claim names, not on what the build still carries.
              </span>
            </label>
          </div>
          {rows.length === 0 ? (
            <p className="hint">
              Nothing declared. These arrive with the inventory, never derived.
            </p>
          ) : (
            <>
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Issue</th>
                      <th>About</th>
                      <th>Kind</th>
                      <th>Said</th>
                      <th>Since</th>
                      <th>Until</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row, i) => (
                      <tr key={`${row.vulnerability} ${row.subject} ${i}`}>
                        <td className="id">{row.vulnerability}</td>
                        <td className="id">{row.subject}</td>
                        <td>
                          {row.pedigree ? (
                            <span className="state agreed" title="A patch carried in the package">
                              carried patch
                            </span>
                          ) : (
                            <span className="hint">statement</span>
                          )}
                        </td>
                        <td>
                          {(row.status ?? "").replaceAll("_", " ")}
                          {!row.suppresses && <span className="hint"> · answers nothing</span>}
                          {row.justification && (
                            <>
                              <br />
                              <span className="hint">{row.justification.replaceAll("_", " ")}</span>
                            </>
                          )}
                          {/* The build's own prose, shown and never rendered
: it arrives in a document somebody else
                              wrote. */}
                          {row.statement && (
                            <>
                              <br />
                              <span className="hint" style={{ whiteSpace: "pre-wrap" }}>
                                {row.statement}
                              </span>
                            </>
                          )}
                        </td>
                        <td className="hint">{on(row.since)}</td>
                        <td>
                          {row.until ? (
                            <span className="state lapsed" title="The build stopped saying it">
                              {on(row.until)}
                            </span>
                          ) : (
                            <span className="hint">still</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Wide>
              <Paged
                shown={rows.length}
                total={total}
                offset={offset}
                limit={PAGE}
                onGo={setOffset}
                what="listed"
              />
            </>
          )}
        </>
      )}
    </section>
  );
}
