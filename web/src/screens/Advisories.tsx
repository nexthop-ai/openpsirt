import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { PAGE, useAdvisories, useStartAdvisory } from "../api/advisories";
import { AddButton } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { standing, statusLabel } from "./advisory";

// Every advisory this deployment has minted, newest first.
//
// The rare, deliberate document: single or low double digits a year. So the
// list is for finding one rather than for working through them — no filters,
// no selection, no bulk anything.
//
// An advisory covering a product somebody holds nothing on is not listed and
// the total says the same, which is the server's narrowing. A document is read
// whole or not at all.

export function Advisories() {
  const navigate = useNavigate();
  const [offset, setOffset] = useState(0);
  const rows = useAdvisories(offset);
  const start = useStartAdvisory();

  if (rows.isPending) return <Loading />;
  if (rows.isError) return <Failed error={rows.error} what="The advisories could not be read." />;

  const items = rows.data?.items ?? [];
  const total = rows.data?.total;

  return (
    <>
      <div className="screen-head">
        <h2>
          Advisories <span className="n">{(total ?? items.length).toLocaleString()}</span>
        </h2>
        <p>What this deployment has said about its own flaws, newest first.</p>
        <AddButton
          label="Start an advisory"
          onClick={() =>
            start.mutate(undefined, {
              // Straight to it. A name is all the act produces, and what to
              // call the document and which flaws it covers are decided on
              // the screen the name opens.
              onSuccess: (made) => navigate(`/advisories/${encodeURIComponent(made.advisory)}`),
            })
          }
        />
      </div>

      {start.isError && (
        <Failed error={start.error} what="No advisory could be started. Nothing was minted." />
      )}

      {items.length === 0 ? (
        <Empty
          title="No advisories."
          detail="An advisory is written for a flaw recorded here, an embargo reaching its date, or an inherited issue worth saying something about."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Advisory</th>
                <th>Status</th>
                <th className="num">Flaws</th>
                <th className="num">Products</th>
                <th className="num">Out</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.advisory} className="row">
                  <td>
                    <Link className="id" to={`/advisories/${encodeURIComponent(row.advisory)}`}>
                      {row.advisory}
                    </Link>
                    {row.title && <div className="hint">{row.title}</div>}
                  </td>
                  <td>
                    <span
                      className={`state ${standing(row.status)?.tone ?? ""}`}
                      title={standing(row.status)?.means}
                    >
                      {statusLabel(row.status)}
                    </span>
                  </td>
                  <td className="num">{row.issues}</td>
                  <td className="num">{row.products}</td>
                  <td className="num">{row.issuances}</td>
                  <td className="hint">{on(row.minted_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}
      <Paged shown={items.length} total={total} offset={offset} limit={PAGE} onGo={setOffset} />
    </>
  );
}
