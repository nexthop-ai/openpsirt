import { notACredential } from "../ui/noautofill";
import { useState } from "react";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Crumbs } from "../ui/Crumbs";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Wide } from "../ui/Wide";

// A variant is the same code built a different way — a chip, an architecture,
// an operating system. It belongs to the product and is declared once, not
// restated per release. With a release in the path this lists what that
// release was actually built as; without one, what the product declares.
export function Variants() {
  const { product = "", stream = "" } = useParams();
  const queries = useQueryClient();
  const who = useWho();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [facing, setFacing] = useState(true);

  const ofRelease = useQuery({
    queryKey: ["variants", product, stream],
    enabled: !!stream,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants", {
          params: { path: { product, stream } },
        }),
      ),
  });
  const ofProduct = useQuery({
    queryKey: ["variants", product],
    enabled: !stream,
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/variants", { params: { path: { product } } })),
  });
  const variants = stream ? ofRelease : ofProduct;

  const declare = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/variants", {
          params: { path: { product } },
          body: { name: name.trim(), customer_facing: facing },
        }),
      ),
    onSuccess: () => {
      setName("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["variants", product] });
      void queries.invalidateQueries({ queryKey: ["variants", product, stream] });
    },
  });

  if (variants.isPending) return <Loading />;
  if (variants.isError) {
    return <Failed error={variants.error} what="The variants could not be read." />;
  }

  const items = variants.data?.items ?? [];
  return (
    <>
      <Crumbs product={product} stream={stream || undefined} />
      <div className="screen-head">
        <h2>Variants</h2>
        <p>
          {stream ? `The ways ${product} · ${stream} is built.` : `The ways ${product} is built.`}{" "}
          The same code, built a different way.
        </p>
        {who.data?.admin && <AddButton label="Add variant" onClick={() => setAdding(true)} />}
      </div>

      <div className="alert info" style={{ marginBottom: 14 }}>
        <strong>A variant is a different way of building the same source</strong>
        <span>
          A different architecture, OS, chip or board, or a test-only build. Not a release: those
          are branches and tags.
        </span>
      </div>

      {items.length === 0 ? (
        <Empty
          title={stream ? "Nothing has been scanned here." : "No variant is declared."}
          detail={
            stream
              ? "Appears under a release once a scan is filed against it."
              : "Declare one before a build can file a scan against it."
          }
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Ships to customers</th>
                <th className="num">Open</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((variant) => (
                <tr key={variant.name} className="row">
                  <td>
                    <span className="id">{variant.name}</span>
                  </td>
                  {/* Absent reads as yes: an unclassified build ranks as though
                      it ships, so silence must not look like a denial. */}
                  <td>
                    <span
                      className={variant.customer_facing === false ? "state open" : "state agreed"}
                    >
                      {variant.customer_facing === false ? "No — internal only" : "Yes"}
                    </span>
                  </td>
                  <td className="num">{(variant.open ?? 0).toLocaleString()}</td>
                  <td>
                    {stream && (
                      <Link
                        to={
                          `/products/${encodeURIComponent(product)}` +
                          `/streams/${encodeURIComponent(stream)}` +
                          `/variants/${encodeURIComponent(variant.name ?? "")}/findings`
                        }
                        className="linkish"
                      >
                        Findings →
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      <Declare
        title="Add variant"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() => declare.mutate()}
        error={declare.error}
        busy={declare.isPending || name.trim() === ""}
        ok="Add variant"
        hint="Declared once per product, not per release, so win, windows and win32 do not become three variants."
      >
        {/* The label wraps the input, as every other field here does. Beside
            it with no htmlFor and no id, a screen reader announced a text
            field with no name at all. */}
        <label className="field">
          <span>Product</span>
          <input {...notACredential} type="text" value={product} disabled />
        </label>
        <Field
          label="Name"
          value={name}
          onChange={setName}
          placeholder="broadcom"
          hint="What the build targets: chip, architecture or OS"
        />
        <div className="field">
          <label htmlFor="declare-facing">Ships to customers</label>
          <select
            id="declare-facing"
            value={facing ? "yes" : "no"}
            onChange={(event) => setFacing(event.target.value === "yes")}
          >
            <option value="yes">Yes</option>
            <option value="no">No</option>
          </select>
        </div>
      </Declare>
    </>
  );
}
