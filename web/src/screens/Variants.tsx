import { notACredential } from "../ui/noautofill";
import { useState } from "react";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { buildPath } from "./list";
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
  // The variant the edit drawer is open on, by its stored name. Empty is
  // closed, so one piece of state answers both which row and whether.
  const [editing, setEditing] = useState("");
  const [renameTo, setRenameTo] = useState("");
  const [editFacing, setEditFacing] = useState(true);

  const ofRelease = useQuery({
    queryKey: ["variants", product, stream, "counts"],
    enabled: !!stream,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants", {
          params: { path: { product, stream }, query: { counts: true } },
        }),
      ),
  });
  const ofProduct = useQuery({
    queryKey: ["variants", product, "counts"],
    enabled: !stream,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/variants", {
          params: { path: { product }, query: { counts: true } },
        }),
      ),
  });
  const variants = stream ? ofRelease : ofProduct;

  // Both lists, because the two answer different questions about the same
  // variant: what the product declares, and what a release was built as.
  const invalidate = () => {
    void queries.invalidateQueries({ queryKey: ["variants", product] });
    void queries.invalidateQueries({ queryKey: ["variants", product, stream] });
  };

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
      invalidate();
    },
  });

  const amend = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/v1/products/{product}/variants/{variant}", {
          params: { path: { product, variant: editing } },
          body: {
            ...(renameTo.trim() && renameTo.trim() !== editing ? { name: renameTo.trim() } : {}),
            customer_facing: editFacing,
          },
        }),
      ),
    onSuccess: () => {
      setEditing("");
      invalidate();
    },
  });

  const retire = useMutation({
    mutationFn: async (variant: string) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/variants/{variant}", {
          params: { path: { product, variant } },
        }),
      ),
    onSuccess: invalidate,
  });

  const edit = (variant: { name?: string; customer_facing?: boolean }) => {
    setEditing(variant.name ?? "");
    setRenameTo(variant.name ?? "");
    setEditFacing(variant.customer_facing !== false);
    amend.reset();
  };

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
                    <span className="id">{variant.name}</span>{" "}
                    {/* Only a release's list carries one: the product's own
                        list stops offering a variant that is retired, and this
                        one keeps naming what the release was built as. */}
                    {variant.retired && <span className="state lapsed">Retired</span>}
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
                  <td className="actions">
                    {stream ? (
                      <Link
                        to={`${buildPath({ product, stream, variant: variant.name ?? "" })}/findings`}
                        className="linkish"
                      >
                        Findings →
                      </Link>
                    ) : (
                      who.data?.admin && (
                        <>
                          <button type="button" className="linkish" onClick={() => edit(variant)}>
                            Edit
                          </button>{" "}
                          <button
                            type="button"
                            className="linkish"
                            style={{ color: "var(--muted)" }}
                            title="Take it out of use. Findings, decisions and published documents keep naming it."
                            disabled={retire.isPending}
                            onClick={() => retire.mutate(variant.name ?? "")}
                          >
                            Retire
                          </button>
                        </>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      <Declare
        title={`Edit ${editing}`}
        open={editing !== ""}
        onClose={() => setEditing("")}
        onSubmit={() => amend.mutate()}
        error={amend.error}
        busy={amend.isPending || renameTo.trim() === ""}
        ok="Save"
        hint="A name cannot be corrected once a VEX document has gone out for this variant: readers already hold the document by it. Retire it and declare the intended name instead."
      >
        <Field
          label="Name"
          value={renameTo}
          onChange={setRenameTo}
          placeholder="broadcom"
          hint="What builds and scans call it"
        />
        <div className="field">
          <label htmlFor="edit-facing">Ships to customers</label>
          <select
            id="edit-facing"
            value={editFacing ? "yes" : "no"}
            onChange={(event) => setEditFacing(event.target.value === "yes")}
          >
            <option value="yes">Yes</option>
            <option value="no">No</option>
          </select>
          <span className="hint">Feeds how urgent a finding here is</span>
        </div>
      </Declare>

      {/* A refused retirement is said. Without it the button re-enables and
          the row stays, which reads as nothing having happened. */}
      {retire.error != null && <Failed error={retire.error} what="That could not be retired." />}

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
          hint="The build's target: chip, architecture or OS"
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
