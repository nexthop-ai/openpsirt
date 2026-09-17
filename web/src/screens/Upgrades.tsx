import { Link, useParams } from "react-router-dom";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Wide } from "../ui/Wide";

// Where a promise stands, said in words rather than left to a color.
const STANDING: Record<string, string> = {
  planned: "promised, with work outstanding and the date still ahead",
  landed: "every piece of it gone, which the scans say",
  lapsed: "the date has passed and work is outstanding",
};

// Lapsed first, then what is still promised, then what has landed.
function rank(state?: string): number {
  return state === "lapsed" ? 0 : state === "landed" ? 2 : 1;
}

// What one build is waiting on, by the upgrade that would deliver it.
//
// Called "release plan" once, which read as the plan for the product's own
// release. It is dependency hygiene: which packages this build is waiting to
// move, and how much of each has landed.
//
// The fix-bundle query read from the other end: a triager reads a bump and the
// issues it closes, a coordinator reads a build and the bumps it is waiting
// on. One query, so the two cannot come to disagree.
export function Upgrades() {
  const { product = "", stream = "", variant = "" } = useParams();
  const plan = useQuery({
    queryKey: ["pending-upgrades", product, stream, variant],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/pending-upgrades",
          {
            params: { path: { product, stream, variant } },
          },
        ),
      ),
  });

  if (plan.isPending) return <Loading />;
  if (plan.isError) {
    return <Failed error={plan.error} what="The pending upgrades could not be read." />;
  }
  // Lapsed first: it is the row somebody has to do something about, and the
  // rest of the screen is a status board.
  const rows = [...(plan.data?.items ?? [])].sort((a, b) => rank(a.state) - rank(b.state));
  const late = rows.filter((row) => row.state === "lapsed").length;

  return (
    <>
      <div className="screen-head">
        <h2>
          Pending upgrades{" "}
          <span className="n">{rows.filter((row) => row.state !== "landed").length}</span>
        </h2>
        <p>
          What {stream} · {variant} is waiting on, by the upstream bump that would deliver it.
          Nothing here is declared done by hand: a piece of work has landed when the build stops
          holding it, which the scans already say — and where it stands is read the same way, from
          the scans and the date somebody promised.
        </p>
        {late > 0 && (
          <div className="alert warn">
            <strong>
              {late} {late === 1 ? "upgrade is" : "upgrades are"} past the date promised
            </strong>
            <span>Findings stay covered. The upgrade goes back to whoever is carrying it.</span>
          </div>
        )}
      </div>

      {rows.length > 0 && (
        <p className="hint">
          {/* A link somebody follows rather than a request this page makes, so
              the browser fetches it with the session it already has. */}
          The whole of it as a file — <a href={fileAt(product, stream, variant, "csv")}>CSV</a> ·{" "}
          <a href={fileAt(product, stream, variant, "json")}>JSON</a>, with the build it is about
          and the day it was taken stated in it.
        </p>
      )}

      {rows.length === 0 ? (
        <Empty
          title="Nothing is planned for this build."
          detail={
            "Plan one from a component's screen: pick the releases, the version to " +
            "move to, and the date. Progress comes from the scans."
          }
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Bump</th>
                <th>Moving to</th>
                <th>Packages</th>
                <th className="num">Would close</th>
                <th>Promised by</th>
                <th>Held by</th>
                <th>Waiting since</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const done = row.state === "landed";
                return (
                  <tr key={row.fold} className="row">
                    <td>
                      {/* The claim it was argued under, which is where the
                          reasoning, the approval and the conversation about
                          the upgrade are. Not the decision it wrote: a
                          decision is one claim about one issue at one place,
                          so clicking one would answer about a single CVE. */}
                      {row.claim_id ? (
                        <Link to={`/claims/${row.claim_id}`} className="linkish id">
                          {row.upstream}
                        </Link>
                      ) : (
                        <span className="id">{row.upstream}</span>
                      )}{" "}
                      <span className="hint">{row.from}</span>
                    </td>
                    {/* A column rather than gray hint text beside the name:
                        the version a release is moving to is the thing
                        somebody is waiting on. */}
                    <td>
                      <span className="id">{row.to}</span>
                    </td>
                    <td className="hint">{(row.components ?? []).join(", ")}</td>
                    <td className="num">
                      <span
                        className={
                          done
                            ? "state agreed"
                            : row.state === "lapsed"
                              ? "state lapsed"
                              : "state waiting"
                        }
                        title={STANDING[row.state ?? ""] ?? ""}
                      >
                        {done ? "landed" : `${row.issues} ${row.issues === 1 ? "issue" : "issues"}`}
                      </span>
                    </td>
                    <td className="hint">
                      {row.by ? on(row.by) : "—"}
                      {row.state === "lapsed" && <span className="state lapsed"> past</span>}
                    </td>
                    <td className="hint">{row.held_by || "no one"}</td>
                    <td className="hint">{on(row.declared_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Wide>
      )}
    </>
  );
}

// Where the file comes from.
function fileAt(product: string, stream: string, variant: string, format: string): string {
  return (
    `/v1/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}/pending-upgrades.${format}`
  );
}
