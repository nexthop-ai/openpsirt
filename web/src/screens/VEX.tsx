import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Moved } from "../ui/Moved";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";

// The VEX document for one build: what it says now, what has gone out, and
// recording another.
//
// Recording hands back the document it recorded, which is the one to send: it
// carries the version it is recorded under. Each revision that went out stays
// readable as it went out.
export function VEX() {
  const { product = "", stream = "", variant = "" } = useParams();
  const path = { product, stream, variant };
  const base =
    `/v1/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}/vex`;
  const queries = useQueryClient();

  const gone = useQuery({
    queryKey: ["vex-issuances", product, stream, variant],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/vex/issuance", {
          params: { path },
        }),
      ),
  });
  const record = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/streams/{stream}/variants/{variant}/vex/issuance", {
          params: { path },
        }),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["vex-issuances", product, stream, variant] });
    },
  });

  const rows = gone.data?.items ?? [];

  return (
    <>
      <nav aria-label="Breadcrumb" className="hint" style={{ marginBottom: 8 }}>
        <Link to={`/products/${encodeURIComponent(product)}`}>{product}</Link> /{" "}
        <Link to={`/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(stream)}`}>
          {stream}
        </Link>{" "}
        / {variant}
      </nav>
      <div className="screen-head">
        <h2>VEX document</h2>
        <p>
          For a customer&rsquo;s own scanner. Approved dismissals and public findings only.{" "}
          <a href={base}>Current document (JSON)</a>
        </p>
      </div>

      <div className="card">
        <h3>What has gone out</h3>
        {gone.isPending ? (
          <Loading inline />
        ) : gone.isError ? (
          <Failed error={gone.error} what="What has gone out could not be read." />
        ) : rows.length === 0 ? (
          <p className="hint">It has not gone out.</p>
        ) : (
          <>
            {gone.data?.changed !== undefined && <Moved changed={gone.data.changed} />}
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th className="num">Version</th>
                    <th>Published</th>
                    <th>By</th>
                    <th>Digest</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.version} className="row">
                      <td className="num">{row.version}</td>
                      <td className="hint">{on(row.issued_at)}</td>
                      <td>{row.issued_by}</td>
                      <td className="id">{row.digest}</td>
                      <td>
                        <a href={`${base}/issuance/${row.version}`}>JSON</a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Wide>
          </>
        )}

        <div className="actions" style={{ marginTop: 10 }}>
          <button
            type="button"
            className="btn"
            title="Needs a triage role on this product"
            disabled={record.isPending}
            onClick={() => record.mutate()}
          >
            {record.isPending ? "Recording…" : "Record that it went out"}
          </button>
        </div>
        {record.isSuccess && (
          <p className="hint">
            Recorded as version {record.data.version}.{" "}
            <a href={`${base}/issuance/${record.data.version}`}>Download what to send</a>
          </p>
        )}
        <p className="hint">Send the document recording hands back. It carries its version.</p>
        {record.isError && <Failed error={record.error} what="That was not recorded." />}
      </div>
    </>
  );
}
