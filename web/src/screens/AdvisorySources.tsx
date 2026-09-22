import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Wide } from "../ui/Wide";
import { since } from "../ui/when";

// The suppliers whose published advisories this deployment reads.
//
// Per product, because that is what a claim is recorded against: a supplier
// feeding two products is two rows, and withdrawing one leaves the other
// standing. So the panel takes a product before it takes an address.
//
// What arrives is evidence beside a finding and a prefill for a decision, never
// a judgment of ours — which is the same thing an uploaded advisory is, and the
// reason this panel says nothing about what any of it decides.
//
// Administrator-only, and the whole panel rather than its controls: the
// endpoint behind it refuses anybody else, so drawn for an auditor it would be
// a table that could only fail to load.

type Source = Body<"AdvisorySourceBody">;

// The suppliers configured against one product. Asked only once a product is
// chosen, because the endpoint is per product and there is no list across them.
function useSources(product: string) {
  return useQuery({
    queryKey: ["advisory-sources", product],
    enabled: product !== "",
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/advisory-sources", {
          params: { path: { product } },
        }),
      ),
  });
}

// How this supplier is doing, in the words a reader uses.
//
// The last attempt and the last one that worked are different facts, and the
// gap between them is the whole answer to "how long has this been broken". Drawn
// from the successful read, so a publisher that has been refusing for a week
// says a week rather than saying it failed three hours ago.
function Read({ row }: { row: Source }) {
  if (row.because) {
    return (
      <span className="state closed" title={row.because}>
        {row.read ? <>failing, last read {since(row.read)}</> : <>never read</>}
      </span>
    );
  }
  if (!row.read) return <span style={{ color: "var(--faint)" }}>not yet</span>;
  return <>{since(row.read)}</>;
}

export function AdvisorySources() {
  const queries = useQueryClient();
  const [product, setProduct] = useState("");
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");

  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
  const sources = useSources(product);

  const add = useMutation({
    mutationFn: async (body: { name: string; url: string }) =>
      unwrap(
        await api.POST("/v1/products/{product}/advisory-sources", {
          params: { path: { product } },
          body,
        }),
      ),
    onSuccess: () => {
      setName("");
      setUrl("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["advisory-sources", product] });
    },
  });
  const withdraw = useMutation({
    mutationFn: async (which: string) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/advisory-sources/{name}", {
          params: { path: { product, name: which } },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["advisory-sources", product] }),
  });

  const known = products.data?.items ?? [];
  const rows = sources.data?.items ?? [];

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="screen-head">
        <h3>Advisory sources</h3>
        {product !== "" && <AddButton label="Add supplier" onClick={() => setAdding(true)} />}
      </div>
      <p className="hint" style={{ marginTop: 0 }}>
        Suppliers whose published advisories are read on the scan schedule. What arrives is evidence
        and a prefill, never a decision. Reading starts when a supplier is added — upload an older
        advisory to take one.
      </p>

      <div className="field">
        <label htmlFor="advisory-sources-product">Product</label>
        <select
          id="advisory-sources-product"
          value={product}
          onChange={(event) => setProduct(event.target.value)}
        >
          {/* An unchosen state, so the first product in the list is not the
              one a supplier is added to by default. Which product reads a
              publisher is the decision this panel exists to record. */}
          <option value="">Choose a product…</option>
          {known.map((one) => (
            <option key={one.name} value={one.name}>
              {one.display_name || one.name}
            </option>
          ))}
        </select>
      </div>

      {withdraw.error != null && (
        <Failed error={withdraw.error} what="That supplier could not be withdrawn." />
      )}
      {product === "" ? null : sources.isPending ? (
        <Loading />
      ) : sources.isError ? (
        <Failed error={sources.error} what="The suppliers could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title="No suppliers."
          detail="Nothing is fetched. A supplier advisory can still be uploaded one at a time."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Directory</th>
                <th>Last read</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.name} className="row">
                  <td className="id">{row.name}</td>
                  {/* The address as recorded, and not a link: it is somewhere
                      this deployment fetches from rather than somewhere a
                      person goes. */}
                  <td className="id">{row.url}</td>
                  <td>
                    <Read row={row} />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="linkish"
                      disabled={withdraw.isPending}
                      onClick={() => withdraw.mutate(row.name ?? "")}
                    >
                      Withdraw
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      <Declare
        title="Add supplier"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() => add.mutate({ name: name.trim(), url: url.trim() })}
        error={add.error}
        busy={name.trim() === "" || url.trim() === "" || add.isPending}
        ok="Add supplier"
        hint="https only, on the host the address names. A redirect is refused rather than followed."
      >
        <Field
          label="Name"
          value={name}
          onChange={setName}
          placeholder="example-distribution"
          hint="The name a log line and this screen use for it."
        />
        <Field
          label="Provider directory"
          value={url}
          onChange={setUrl}
          placeholder="https://example.com/.well-known/csaf/provider-metadata.json"
          hint="Where the supplier describes what they publish. It names the feeds their advisories are listed in."
        />
      </Declare>
    </div>
  );
}
