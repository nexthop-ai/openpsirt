import { THE_LINE } from "../ui/severities";
import { useState } from "react";
import { Loading } from "../ui/Loading";
import { on, since } from "../ui/when";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { EndOfLife } from "../ui/EndOfLife";
import { Failed } from "../ui/Failed";
import type { Who } from "../app/session";
import { Wide } from "../ui/Wide";

// You pick a product first, and everything below is bound to it. What each one
// holds is on the row, so the list answers the question it exists to answer
// without every row being opened.
export function Products({ who }: { who: Who }) {
  const queries = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  // The product the edit drawer is open on, by its stored name. Empty is
  // closed, so one piece of state answers both which row and whether.
  const [editing, setEditing] = useState("");
  const [renameTo, setRenameTo] = useState("");
  const [showAs, setShowAs] = useState("");
  // Counted, and keyed as counted. What is open against each row is asked for
  // rather than always done, and a read that asked shares nothing with one
  // that did not — keyed the same, the picker's uncounted answer and this
  // screen's would be one cache entry and whichever arrived first would win.
  const products = useQuery({
    queryKey: ["products", "counts"],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products", { params: { query: { counts: true } } })),
  });
  const declare = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products", {
          body: { name: name.trim(), display_name: displayName.trim() || undefined },
        }),
      ),
    onSuccess: () => {
      setName("");
      setDisplayName("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["products"] });
    },
  });

  const amend = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/v1/products/{product}", {
          params: { path: { product: editing } },
          body: {
            ...(renameTo.trim() && renameTo.trim() !== editing ? { name: renameTo.trim() } : {}),
            display_name: showAs.trim(),
          },
        }),
      ),
    onSuccess: () => {
      setEditing("");
      void queries.invalidateQueries({ queryKey: ["products"] });
    },
  });

  const retire = useMutation({
    mutationFn: async (product: string) =>
      unwrap(await api.DELETE("/v1/products/{product}", { params: { path: { product } } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["products"] }),
  });

  const edit = (product: { name?: string; display_name?: string }) => {
    setEditing(product.name ?? "");
    setRenameTo(product.name ?? "");
    setShowAs(product.display_name || product.name || "");
    amend.reset();
  };

  const setEndOfLife = useMutation({
    mutationFn: async ({ product, on }: { product: string; on: string }) =>
      unwrap(
        await api.PUT("/v1/products/{product}/end-of-life", {
          params: { path: { product } },
          body: { on },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["products"] }),
  });

  const setFloor = useMutation({
    mutationFn: async ({ product, floor }: { product: string; floor: Line }) =>
      unwrap(
        await api.PUT("/v1/products/{product}/triage-floor", {
          params: { path: { product } },
          body: { floor },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["products"] }),
  });

  if (products.isPending) return <Loading />;
  if (products.isError) {
    return <Failed error={products.error} what="The products could not be read." />;
  }

  const items = products.data?.items ?? [];
  // One instant for the whole table rather than a reading per row. Two rows
  // judged against two different "now"s is a difference nobody would ever see
  // reported, and a week-old threshold does not need better than this.
  //
  // Reading the clock is impure whether it happens here or inside a memo,
  // because a memo's body still runs during render. There is no pure source
  // for it: the answer this asks for is what the time is, and the alternatives
  // are state written from an effect, which is the pattern this same ruleset
  // argues against, or a field the server does not send. So the rule is
  // switched off for this line and stays on everywhere else.
  // eslint-disable-next-line react-hooks/purity
  const asOf = Date.now();

  return (
    <>
      <div className="screen-head">
        <h2>Products</h2>
        <p>Products are declared before scans can be filed against them.</p>
        {who.admin && <AddButton label="Add product" onClick={() => setAdding(true)} />}
      </div>

      {setEndOfLife.isError && (
        <Failed error={setEndOfLife.error} what="That support date could not be set." />
      )}
      {setFloor.isError && (
        <Failed error={setFloor.error} what="That triage line could not be set." />
      )}

      {items.length === 0 ? (
        <Empty
          title="You can reach no product yet."
          detail={
            who.admin
              ? "Declare one before a build can file a scan against it."
              : "An administrator grants a role before anything appears here."
          }
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Product</th>
                <th className="num">Branches</th>
                <th className="num">Tags</th>
                <th className="num">Variants</th>
                {/* Findings, not distinct issues: one issue at one component,
                    counted once per build it is in. The rail's own number is
                    the same unit and the tree's is not, so the column says
                    which. */}
                <th className="num" title="Open findings — an issue at a component, per build">
                  Open findings
                </th>
                <th>Triage from</th>
                <th>Out of support</th>
                <th>Last inventory</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((product) => {
                const stale =
                  !!product.last_scan_at &&
                  asOf - Date.parse(product.last_scan_at) > 7 * 86_400_000;
                return (
                  <tr key={product.name} className="row">
                    <td>
                      {/* The product's own page rather than its branches
. This table is an administration surface —
                          a triage line in a select, a date in an input — and
                          "how is this one doing" is a different question that
                          had nowhere to go. */}
                      <Link to={`/products/${encodeURIComponent(product.name)}`} className="id">
                        {product.display_name || product.name}
                      </Link>
                      {product.display_name && product.display_name !== product.name && (
                        <>
                          <br />
                          <span className="id" style={{ color: "var(--faint)" }}>
                            {product.name}
                          </span>
                        </>
                      )}
                    </td>
                    <td className="num">{product.branches ?? 0}</td>
                    <td className="num">{product.tags ?? 0}</td>
                    <td className="num">{product.variants ?? 0}</td>
                    <td className="num">{(product.open ?? 0).toLocaleString()}</td>
                    <td>
                      <Floor
                        product={product.name ?? ""}
                        stated={product.triage_floor ?? ""}
                        admin={who.admin}
                        onSet={(floor) => setFloor.mutate({ product: product.name ?? "", floor })}
                      />
                    </td>
                    <td>
                      <EndOfLife
                        what={`${product.name} goes out of support`}
                        on={product.end_of_life ?? ""}
                        admin={who.admin}
                        onSet={(on) => setEndOfLife.mutate({ product: product.name ?? "", on })}
                      />
                    </td>
                    <td
                      className={stale ? "" : "hint"}
                      style={stale ? { color: "var(--sev-high)", fontWeight: 600 } : undefined}
                    >
                      {product.last_scan_at ? (
                        <span title={on(product.last_scan_at)}>{since(product.last_scan_at)}</span>
                      ) : (
                        "never"
                      )}
                    </td>
                    <td>
                      <Link
                        to={`/products/${encodeURIComponent(product.name)}/streams`}
                        className="linkish"
                      >
                        Manage
                      </Link>
                      {who.admin && (
                        <>
                          {" "}
                          <button
                            type="button"
                            className="linkish"
                            title="Correct what it is called."
                            onClick={() => edit(product)}
                          >
                            Edit
                          </button>{" "}
                          <button
                            type="button"
                            className="linkish"
                            style={{ color: "var(--muted)" }}
                            title="Take it out of use, with its releases and variants. Findings, decisions and published documents keep naming it."
                            disabled={retire.isPending}
                            onClick={() => retire.mutate(product.name ?? "")}
                          >
                            Retire
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
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
        busy={amend.isPending || renameTo.trim() === "" || showAs.trim() === ""}
        ok="Save"
        hint="The name cannot be corrected once a document naming this product has gone out: readers hold it by that name. The shown name is not in any identifier and moves freely."
      >
        <Field
          label="Name"
          value={renameTo}
          onChange={setRenameTo}
          placeholder="sonic"
          hint="What scans, paths and documents call it"
        />
        <Field
          label="Shown as"
          value={showAs}
          onChange={setShowAs}
          placeholder="SONiC"
          hint="What screens and reports show"
        />
      </Declare>

      {/* A refused retirement is said. Without it the button re-enables and
          the row stays, which reads as nothing having happened. */}
      {retire.error != null && <Failed error={retire.error} what="That could not be retired." />}

      <Declare
        title="Add product"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() => declare.mutate()}
        error={declare.error}
        busy={declare.isPending || name.trim() === ""}
        ok="Add product"
        hint="Declared rather than created on first use, so a typo in a pipeline cannot invent a product."
      >
        <Field
          label="Name"
          value={name}
          onChange={setName}
          placeholder="sonic"
          hint="The name scans use for it. Capitals do not matter."
        />
        <Field
          label="Display name"
          value={displayName}
          onChange={setDisplayName}
          placeholder="SONiC"
          hint="Optional. Defaults to the name"
        />
      </Declare>
    </>
  );
}

// The words a line may be, plus the one that is not a word at all: following
// the deployment. Following is not the same as stating the deployment's
// current line — a product that stated it would stop following the next time
// the deployment changed its mind, and nobody would see that happen.
type Line = "" | (typeof THE_LINE)[number];

const lines: Line[] = ["", ...THE_LINE];

// The least severity a product triages, and a way to say something else.
//
// Below the line a finding is still recorded, still counted and still
// reportable; it is out of the working list, not out of the system. Shown to
// everybody because it explains a number, and editable by an administrator
// because hiding findings is what every other part of this gates.
function Floor({
  product,
  stated,
  admin,
  onSet,
}: {
  product: string;
  stated: Line;
  admin: boolean;
  onSet: (floor: Line) => void;
}) {
  if (!admin) {
    return stated ? <span>{stated}</span> : <span className="hint">deployment&rsquo;s</span>;
  }
  return (
    <select
      value={stated}
      aria-label={`What ${product} considers worth triaging`}
      onChange={(event) => onSet(event.target.value as Line)}
      title="Below this line a finding is still recorded and counted, and is out of the working list"
    >
      {lines.map((word) => (
        <option key={word || "inherit"} value={word}>
          {word || "deployment\u2019s"}
        </option>
      ))}
    </select>
  );
}
