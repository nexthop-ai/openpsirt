import { decidedAs } from "../ui/decided";
import { useQuery } from "@tanstack/react-query";
import { Loading } from "../ui/Loading";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Refused, unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Severity, Exploited } from "../ui/Severity";
import { IssueAdvisory } from "./IssueAdvisory";
import { IssueNotes } from "./FindingNotes";
import { useWho } from "../app/session";
import { Wide } from "../ui/Wide";

// One issue, everywhere it sits.
//
// The work starts from an issue as often as from a product. "A critical
// just landed in openssl — which of our products ship an affected version" was
// a question asked one product at a time, and at a dozen products that is the
// first thing anybody complains about.
//
// One row per build and component, not per place: the same component in
// two builds is two things somebody ships, and sixty places of it in one build
// is one piece of work with a count.
export function Issue() {
  const { vulnerability = "" } = useParams();
  const who = useWho();
  // The identity alone. A note records who wrote it by the name they sign in
  // under, and matching a display name as well made ownership turn on a label
  // anybody can be given.
  const mine = (writtenBy: string) => !!who.data && writtenBy === who.data.identity;
  const found = useQuery({
    queryKey: ["issue", vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/issues/{vulnerability}", {
          params: { path: { vulnerability }, query: { limit: 200 } },
        }),
      ),
    retry: false,
  });

  if (found.isPending) return <Loading />;
  if (found.isError) {
    // A 404 is the answer to the question this screen asks — nothing you can
    // read carries the issue. Anything else is a read that did not happen,
    // and saying "nothing carries this" about it is a wrong answer with the
    // confidence of a right one.
    const nothing = found.error instanceof Refused && found.error.status === 404;
    return (
      <>
        <div className="screen-head">
          <h2>
            <span className="id">{vulnerability}</span>
          </h2>
        </div>
        {nothing ? (
          <Empty
            title="Nothing you can see carries this."
            detail="Nothing you can read holds it."
          />
        ) : (
          <Failed error={found.error} what="This issue could not be read." />
        )}
      </>
    );
  }

  const it = found.data;
  const rows = it?.items ?? [];
  // The products carrying it, once each and in the order they appear. An
  // advisory names a flaw together with the product it is covered in, and
  // this issue may sit in several.
  // Anything of it still undisclosed there is folded in per
  // product, because one undisclosed place makes the whole of it undisclosed
  // for anybody deciding what may be said about it.
  const products = Array.from(
    rows
      .reduce((seen, row) => {
        const name = row.product ?? "";
        if (!name) return seen;
        const held = seen.get(name);
        seen.set(name, {
          called: held?.called || row.product_name || name,
          undisclosed: !!held?.undisclosed || !!row.undisclosed,
        });
        return seen;
      }, new Map<string, { called: string; undisclosed: boolean }>())
      .entries(),
  ).map(([name, held]) => ({ name, ...held }));
  return (
    <>
      <div className="screen-head">
        <h2>
          <span className="id">{it?.vulnerability}</span> <Severity word={it?.severity} />{" "}
          {it?.exploited && <Exploited when />}
        </h2>
        <p>
          {(it?.products ?? 0).toLocaleString()}{" "}
          {(it?.products ?? 0) === 1 ? "product" : "products"} · {(it?.total ?? 0).toLocaleString()}{" "}
          {(it?.total ?? 0) === 1 ? "build" : "builds"} carry it — one row per build and component,
          however many places each sits at
        </p>
      </div>

      {(it?.aliases ?? []).length > 0 && (
        <p className="hint" style={{ marginBottom: 10 }}>
          Also known as <span className="id">{(it?.aliases ?? []).join(" · ")}</span>
        </p>
      )}

      {it?.description && (
        <div className="card" style={{ marginBottom: 12 }}>
          {/* What a scan file said is shown and never rendered. */}
          <p style={{ whiteSpace: "pre-wrap", margin: 0 }}>{it.description}</p>
        </div>
      )}

      {/* The one output of this tool that leaves the company, and until now
          the one output nobody here could make: both endpoints answered and
          nothing called them. Per product, because that is the grain of the
          document. */}
      {products.length > 0 && (
        <IssueAdvisory vulnerability={it?.vulnerability ?? ""} products={products} />
      )}

      {/* What people have written about this issue, a product at a time. The
          thread is here whether or not anybody has decided anything, which is
          the whole of what separates it from a claim's comments. */}
      {products.length > 0 && (
        <IssueNotes vulnerability={it?.vulnerability ?? ""} products={products} mine={mine} />
      )}

      {rows.length === 0 ? (
        <Empty title="Nothing carries it." detail="Nothing open in what you can see holds this." />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Product</th>
                <th>Build</th>
                <th>Component</th>
                <th className="num">Locations</th>
                <th>State</th>
                <th>Due</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={`${row.product} ${row.stream} ${row.variant} ${row.component}`}
                  className="row"
                >
                  <td>{row.product_name || row.product}</td>
                  <td className="hint">
                    {row.stream} · {row.variant}
                  </td>
                  <td>
                    <Link
                      to={
                        `/products/${encodeURIComponent(row.product ?? "")}` +
                        `/streams/${encodeURIComponent(row.stream ?? "")}` +
                        `/variants/${encodeURIComponent(row.variant ?? "")}` +
                        `/findings/${encodeURIComponent(it?.vulnerability ?? "")}` +
                        `/components/${encodeURIComponent(row.component ?? "")}` +
                        (row.version ? `?version=${encodeURIComponent(row.version)}` : "")
                      }
                      className="id"
                    >
                      {row.component}
                    </Link>{" "}
                    <span className="id" style={{ color: "var(--faint)" }}>
                      {row.version}
                    </span>
                    {row.undisclosed && (
                      <>
                        {" "}
                        <span className="state waiting" title="Not disclosed">
                          undisclosed
                        </span>
                      </>
                    )}
                  </td>
                  <td className="num">{row.places}</td>
                  <td>
                    <span className={`state ${decidedAs(row.state).cls}`}>
                      {decidedAs(row.state).word}
                    </span>
                  </td>
                  <td className="hint">
                    {row.due ?? "—"}
                    {row.fixed_in && (
                      <>
                        {" "}
                        · fixed in <span className="id">{row.fixed_in}</span>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      {(it?.total ?? 0) > rows.length && (
        <p className="hint" style={{ marginTop: 10 }}>
          Showing {rows.length.toLocaleString()} of {(it?.total ?? 0).toLocaleString()}. A kernel
          flaw across a dozen products is a real answer and an unbounded page is one nobody reads.
        </p>
      )}
    </>
  );
}
