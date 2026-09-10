import { decidedAs } from "../ui/decided";
import { useQuery } from "@tanstack/react-query";
import { Loading } from "../ui/Loading";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Severity, Exploited } from "../ui/Severity";
import { IssueAdvisory } from "./IssueAdvisory";

// One issue, everywhere it sits.
//
// **The work starts from an issue as often as from a product.** "A critical
// just landed in openssl — which of our products ship an affected version" was
// a question asked one product at a time, and at a dozen products that is the
// first thing anybody complains about.
//
// **One row per build and component**, not per place: the same component in
// two builds is two things somebody ships, and sixty places of it in one build
// is one piece of work with a count.
export function Issue() {
  const { vulnerability = "" } = useParams();
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
    return (
      <>
        <div className="screen-head">
          <h2>
            <span className="id">{vulnerability}</span>
          </h2>
        </div>
        <Empty
          title="Nothing you can see carries this."
          detail="Either nothing here has it, or it sits only in products you hold nothing on — which are the same answer on purpose."
        />
      </>
    );
  }

  const it = found.data;
  const rows = it?.items ?? [];
  // The products carrying it, once each and in the order they appear. The
  // advisory is a statement about one product, and this issue may sit in
  // several.
  const products = Array.from(
    rows
      .reduce((seen, row) => {
        const name = row.product ?? "";
        if (name && !seen.has(name)) seen.set(name, row.product_name || name);
        return seen;
      }, new Map<string, string>())
      .entries(),
  ).map(([name, called]) => ({ name, called }));
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
          Also known as <span className="id">{(it?.aliases ?? []).join(" · ")}</span>. A name
          assigned later is another name for the same issue; nothing keyed on it moved.
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

      {rows.length === 0 ? (
        <Empty title="Nothing carries it." detail="Nothing open in what you can see holds this." />
      ) : (
        <div className="tablewrap">
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
        </div>
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
