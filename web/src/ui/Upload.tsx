// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useCatalog } from "../api/catalog";
import { useScope } from "../app/scope";
import { Drawer } from "./Drawer";
import { Dropzone } from "./Dropzone";
import { Failed } from "./Failed";
import { useReseed } from "./reseed";

// Uploading an inventory by hand: the same endpoint a pipeline uses, for a
// build with no automation yet, or for trying the tool on any SBOM to hand.
// Exactly the two parts the endpoint takes — one inventory and any
// number of OpenVEX suppression documents — and nothing it does not.
export function UploadDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const at = useScope();
  const navigate = useNavigate();
  const queries = useQueryClient();
  const [product, setProduct] = useState(at.product ?? "");
  const [stream, setStream] = useState(at.stream ?? "");
  const [variant, setVariant] = useState(at.variant ?? "");
  const [inventory, setInventory] = useState<File | null>(null);
  const [suppressions, setSuppressions] = useState<File[]>([]);
  // The scan an upload matched, where the build already held it. Said here
  // rather than answered with the receipts screen, because nothing new is
  // waiting there and arriving on it reads as the upload having been taken.
  const [held, setHeld] = useState<number | null>(null);

  // Prefilled from the scope each time it opens, so the common case is
  // choosing a file and nothing else. The drawer stays mounted while it is
  // shut, because closing it is an animation on the element that is there.
  useReseed(String(open), () => {
    if (!open) return;
    setProduct(at.product ?? "");
    setStream(at.stream ?? "");
    setVariant(at.variant ?? "");
    setInventory(null);
    setSuppressions([]);
    setHeld(null);
  });

  const { products, streams, variants } = useCatalog(open, product);

  const upload = useMutation({
    mutationFn: async () => {
      const form = new FormData();
      if (inventory) form.append("inventory", inventory);
      for (const each of suppressions) form.append("suppressions", each);
      return unwrap(
        await api.POST("/v1/products/{product}/streams/{stream}/variants/{variant}/scans", {
          params: { path: { product, stream, variant } },
          // The client would otherwise serialize this as JSON; a multipart
          // body is handed to fetch as it is, which sets the boundary itself.
          body: form as never,
          bodySerializer: (body) => body as unknown as BodyInit,
        }),
      );
    },
    onSuccess: (result) => {
      if (result.outcome === "already_held") {
        setHeld(result.scan_id);
        return;
      }
      void queries.invalidateQueries({ queryKey: ["scans"] });
      void queries.invalidateQueries({ queryKey: ["scanning"] });
      onClose();
      navigate(
        `/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(stream)}` +
          `/variants/${encodeURIComponent(variant)}/scans`,
      );
    },
  });

  const ready = !!product && !!stream && !!variant && !!inventory && !upload.isPending;

  return (
    <Drawer
      open={open}
      title="Upload inventory"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" disabled={!ready} onClick={() => upload.mutate()}>
            {upload.isPending ? "Uploading…" : "Upload"}
          </button>
          <button type="button" className="btn quiet" onClick={onClose}>
            Cancel
          </button>
        </>
      }
    >
      <p className="reading" style={{ margin: "0 0 14px" }}>
        The same endpoint a pipeline uses: two parts, <span className="mono">inventory</span> and{" "}
        <span className="mono">suppressions</span> — for a build with no automation, or to try any
        SBOM.
      </p>

      {upload.error != null && <Failed error={upload.error} what="That could not be uploaded." />}
      {held !== null && (
        <div className="alert info">
          <strong>Already held</strong>
          <span>
            This build already holds this inventory, as scan {held}. Nothing was queued.{" "}
            <Link
              to={
                `/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(stream)}` +
                `/variants/${encodeURIComponent(variant)}/scans`
              }
              onClick={onClose}
              className="linkish"
            >
              View inventories →
            </Link>
          </span>
        </div>
      )}

      <div className="field">
        <label htmlFor="up-product">Target</label>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <select
            id="up-product"
            aria-label="Product"
            style={{ flex: 1, minWidth: 110 }}
            value={product}
            onChange={(event) => {
              setProduct(event.target.value);
              setStream("");
              setVariant("");
            }}
          >
            <option value="">Select a product</option>
            {(products.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name}>
                {each.name}
              </option>
            ))}
          </select>
          <select
            aria-label="Branch or tag"
            style={{ flex: 1, minWidth: 110 }}
            value={stream}
            disabled={!product}
            onChange={(event) => setStream(event.target.value)}
          >
            <option value="">Select a branch or tag</option>
            {(streams.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name}>
                {each.name}
              </option>
            ))}
          </select>
          <select
            aria-label="Variant"
            style={{ flex: 1, minWidth: 110 }}
            value={variant}
            disabled={!product}
            onChange={(event) => setVariant(event.target.value)}
          >
            <option value="">Select a variant</option>
            {(variants.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name}>
                {each.name}
              </option>
            ))}
          </select>
        </div>
        <span className="hint">Must already be declared. Undeclared targets are refused.</span>
      </div>

      <div className="field">
        <label>
          Inventory{" "}
          <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--sev-high)" }}>
            required
          </span>
        </label>
        <Dropzone
          files={inventory ? [inventory] : []}
          accept=".json,.cdx.json,.spdx.json,.spdx3.json,application/json"
          onChange={(chosen) => setInventory(chosen[0] ?? null)}
        >
          <b>A CycloneDX or SPDX JSON file</b> (CycloneDX 1.4–1.7, SPDX 2.2, 2.3 and 3.x). The scan
          runs here.
        </Dropzone>
      </div>

      <div className="field">
        <label>
          Suppressions{" "}
          <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--faint)" }}>
            optional · any number
          </span>
        </label>
        <Dropzone files={suppressions} onChange={setSuppressions} multiple small>
          OpenVEX documents, usually the build&rsquo;s suppressions directory. Applied here, never
          re-decided.
        </Dropzone>
      </div>

      <div className="alert info">
        <strong>Accepted, then parsed</strong>
        <span>Answered as soon as the files land. Parsing and scanning run in the background.</span>
      </div>
    </Drawer>
  );
}
