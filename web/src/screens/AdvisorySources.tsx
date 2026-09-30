// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Dropzone } from "../ui/Dropzone";
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

// Publishers whose CSAF provider directory is public, offered as a fill for
// the form rather than configured: which product reads a publisher is still
// the administrator's choice. Each address answers without a redirect, which
// the fetcher refuses.
export const KNOWN_SUPPLIERS = [
  {
    name: "redhat",
    label: "Red Hat",
    covers: "RHEL, UBI images and other Red Hat products",
    url: "https://security.access.redhat.com/data/csaf/v2/provider-metadata.json",
  },
  {
    name: "suse",
    label: "SUSE",
    covers: "SUSE Linux Enterprise, openSUSE and other SUSE products",
    url: "https://www.suse.com/.well-known/csaf/provider-metadata.json",
  },
  {
    name: "cisco",
    label: "Cisco",
    covers: "Cisco products",
    url: "https://www.cisco.com/.well-known/csaf/provider-metadata.json",
  },
  {
    name: "siemens",
    label: "Siemens",
    covers: "Siemens industrial products",
    url: "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json",
  },
  {
    name: "ncsc-nl",
    label: "NCSC-NL",
    covers: "Advisories the Dutch national CERT issues about third-party products",
    url: "https://advisories.ncsc.nl/.well-known/csaf/provider-metadata.json",
  },
] as const;

// Whether a well-known publisher is already configured on the product, by
// either the name it would be added under or the address it is read from.
function configured(known: { name: string; url: string }, rows: readonly Source[]) {
  return rows.some((row) => (row.name ?? "").toLowerCase() === known.name || row.url === known.url);
}

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
      <span className="state bad" title={row.because}>
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
        <h3>Supplier advisories</h3>
      </div>
      <p className="hint" style={{ marginTop: 0 }}>
        CSAF and VEX from the vendors whose code a product ships, shown as evidence on its findings.
      </p>

      <div className="filters">
        <select
          aria-label="Product"
          value={product}
          onChange={(event) => setProduct(event.target.value)}
          style={{ width: "auto" }}
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

      {product !== "" && (
        <div className="screen-head" style={{ marginTop: 16 }}>
          <h4 style={{ margin: 0 }} title="Read on the scan schedule">
            Fetched automatically
          </h4>
          <AddButton label="Add supplier" onClick={() => setAdding(true)} />
        </div>
      )}
      {withdraw.error != null && (
        <Failed error={withdraw.error} what="That supplier could not be withdrawn." />
      )}
      {product === "" ? (
        <Empty title="Pick a product" detail="Suppliers are set up per product." />
      ) : sources.isPending ? (
        <Loading />
      ) : sources.isError ? (
        <Failed error={sources.error} what="The suppliers could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title="No suppliers"
          detail="Add one by its CSAF provider directory, or upload a document below."
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

      {product !== "" && <Upload product={product} />}

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
        <div className="field">
          <span>Well-known</span>
          <div className="filters" style={{ margin: 0 }}>
            {KNOWN_SUPPLIERS.map((known) => {
              const added = configured(known, rows);
              return (
                <button
                  key={known.name}
                  type="button"
                  className="chip"
                  aria-pressed={name === known.name && url === known.url}
                  disabled={added}
                  title={added ? "Already added to this product" : known.covers}
                  onClick={() => {
                    setName(known.name);
                    setUrl(known.url);
                  }}
                >
                  {known.label}
                </button>
              );
            })}
          </div>
        </div>
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

// The two kinds of document a publisher issues, by what each is uploaded as.
const KINDS = {
  advisory: { label: "Security advisory (CSAF)", part: "advisory" },
  statements: { label: "VEX statement set (OpenVEX or CSAF)", part: "statements" },
} as const;

// Uploading one document a publisher issued, for this product.
//
// The same two endpoints a script uses. An advisory adds to what that
// publisher has said; a statement set replaces their whole previous set. Each
// endpoint refuses the other kind and says which one takes it.
function Upload({ product }: { product: string }) {
  const queries = useQueryClient();
  const [kind, setKind] = useState<keyof typeof KINDS>("advisory");
  const [file, setFile] = useState<File | null>(null);

  const upload = useMutation({
    mutationFn: async () => {
      const form = new FormData();
      if (file) form.append(KINDS[kind].part, file);
      // The client would otherwise serialize this as JSON; a multipart body
      // is handed to fetch as it is, which sets the boundary itself.
      const sent = { body: form as never, bodySerializer: (body: unknown) => body as BodyInit };
      if (kind === "advisory") {
        const taken = unwrap(
          await api.POST("/v1/products/{product}/supplier-advisories", {
            params: { path: { product } },
            ...sent,
          }),
        );
        return `${taken.identifier} from ${taken.publisher}: ${taken.recorded} claims taken, ${taken.superseded} set aside.`;
      }
      const taken = unwrap(
        await api.POST("/v1/products/{product}/vex-statements", {
          params: { path: { product } },
          ...sent,
        }),
      );
      return `${taken.publisher}: ${taken.recorded} statements taken, ${taken.superseded} set aside.`;
    },
    onSuccess: () => {
      setFile(null);
      void queries.invalidateQueries({ queryKey: ["finding"] });
    },
  });

  return (
    <>
      <h4 style={{ marginTop: 20 }}>Upload a document</h4>
      <div className="filters">
        <label className="field">
          <span>Kind</span>
          <select
            value={kind}
            onChange={(event) => {
              setKind(event.target.value as keyof typeof KINDS);
              upload.reset();
            }}
          >
            {Object.entries(KINDS).map(([key, one]) => (
              <option key={key} value={key}>
                {one.label}
              </option>
            ))}
          </select>
        </label>
        <div className="field" style={{ flex: "1 1 18rem" }}>
          <span>File</span>
          <Dropzone
            files={file ? [file] : []}
            accept=".json,application/json"
            small
            onChange={(chosen) => {
              setFile(chosen[0] ?? null);
              upload.reset();
            }}
          >
            A JSON document
          </Dropzone>
        </div>
        <button
          type="button"
          className="btn"
          disabled={!file || upload.isPending}
          onClick={() => upload.mutate()}
        >
          {upload.isPending ? "Uploading…" : "Upload"}
        </button>
      </div>
      <p className="hint">
        {kind === "advisory"
          ? "Adds to what this publisher has said. The same advisory uploaded again replaces its earlier claims."
          : "Replaces this publisher's whole previous statement set for the product."}
      </p>
      {upload.isSuccess && <p className="hint">{upload.data}</p>}
      {upload.isError && <Failed error={upload.error} what="That document was not taken." />}
    </>
  );
}
