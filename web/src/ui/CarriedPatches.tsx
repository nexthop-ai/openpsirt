// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { on } from "../ui/when";
import { notACredential } from "../ui/noautofill";
import { Paged } from "../ui/Paged";
import { Wide } from "./Wide";

// The claims a build makes about dealing with things itself, over time.
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
      title="Patches and VEX statements this build's own inventory declares. A fixed or not-affected status suppresses matching findings"
    >
      <h3>
        <button
          type="button"
          className="linkish"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open ? "▾" : "▸"} Declared patches and VEX
        </button>
      </h3>
      {!open ? null : carried.isError ? (
        <Failed error={carried.error} what="The patches this build carries could not be read." />
      ) : (
        <>
          <div className="filters">
            <input
              {...notACredential}
              type="text"
              value={component}
              placeholder="Package"
              aria-label="Package"
              title="The package name as the declaration gives it"
              style={{ width: 220 }}
              onChange={(event) => {
                setComponent(event.target.value);
                setOffset(0);
              }}
            />
          </div>
          {rows.length === 0 ? (
            <p className="hint">{component ? "None for that package" : "None declared"}</p>
          ) : (
            <>
              <Wide>
                <table>
                  <thead>
                    <tr>
                      <th>Issue</th>
                      <th>Package</th>
                      <th>Kind</th>
                      <th>Status</th>
                      <th>Declared</th>
                      <th>Dropped</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row, i) => (
                      <tr key={`${row.vulnerability} ${row.subject} ${i}`}>
                        <td className="id">{row.vulnerability}</td>
                        <td className="id">
                          {row.version ? `${row.subject} ${row.version}` : row.subject}
                          {row.within && (
                            <span className="hint">
                              {" "}
                              inside {row.within}
                              {row.within_version && <> {row.within_version}</>}
                            </span>
                          )}
                        </td>
                        <td>
                          {row.pedigree ? (
                            <span
                              className="state agreed"
                              title="A patch in the package's pedigree"
                            >
                              patch
                            </span>
                          ) : (
                            <span className="hint" title="A VEX statement sent with the build">
                              VEX
                            </span>
                          )}
                        </td>
                        <td>
                          {(row.status ?? "").replaceAll("_", " ")}
                          {!row.suppresses && (
                            <span className="hint" title="This status suppresses no finding">
                              {" "}
                              · no effect
                            </span>
                          )}
                          {row.justification && (
                            <>
                              <br />
                              <span className="hint">{row.justification.replaceAll("_", " ")}</span>
                            </>
                          )}
                          {/* The build's own prose, shown and never rendered: it
                              arrives in a document somebody else wrote. */}
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
                            <span
                              className="state lapsed"
                              title="A later inventory stopped declaring it"
                            >
                              {on(row.until)}
                            </span>
                          ) : (
                            <span className="hint">—</span>
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
