// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useInspect, useTrust, useUpstream, type Upstream } from "../api/upstream";
import { Drawer } from "../ui/Drawer";
import { Field } from "../ui/Declare";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { since } from "../ui/when";

// The upstream a product trusts: naming one, confirming its key, trusting a
// changed key, and stopping trusting it.
//
// Two steps to trust one. Checking reads the upstream's description and shows
// whose statements they are and the key they are signed with; trusting sends
// that key back. The administrator sees which key documents will be checked
// against before anything is read.
export function UpstreamDrawer({
  product,
  open,
  onClose,
}: {
  product: string;
  open: boolean;
  onClose: () => void;
}) {
  const upstream = useUpstream(product, open);
  const inspect = useInspect(product);
  const { trust, withdraw } = useTrust(product);
  const [url, setUrl] = useState("");

  const held = upstream.data ?? null;
  const checked = inspect.data;
  const close = () => {
    setUrl("");
    inspect.reset();
    trust.reset();
    withdraw.reset();
    onClose();
  };

  return (
    <Drawer
      open={open}
      title={`Upstream of ${product}`}
      onClose={close}
      footer={
        <>
          {checked ? (
            <button
              type="button"
              className="btn"
              disabled={trust.isPending}
              onClick={() =>
                trust.mutate(
                  { url: url.trim(), fingerprint: checked.fingerprint || undefined },
                  { onSuccess: () => inspect.reset() },
                )
              }
            >
              Trust
            </button>
          ) : (
            <button
              type="button"
              className="btn"
              disabled={url.trim() === "" || inspect.isPending}
              onClick={() => inspect.mutate(url.trim())}
            >
              {inspect.isPending ? "Checking…" : "Check"}
            </button>
          )}
          <button type="button" className="btn quiet" onClick={close}>
            Close
          </button>
        </>
      }
    >
      {upstream.isPending ? (
        <Loading />
      ) : upstream.isError ? (
        <Failed error={upstream.error} what="The upstream could not be read." />
      ) : held ? (
        <Trusted held={held} onRetrust={() => setUrl(held.url ?? "")} />
      ) : (
        <p className="hint">
          None. What it says for anybody closes the same component here; the rest goes to review.
        </p>
      )}

      {held && (
        <p>
          <button
            type="button"
            className="linkish"
            style={{ color: "var(--muted)" }}
            disabled={withdraw.isPending}
            title="Nothing more is read, and everything it said stops closing findings"
            onClick={() => withdraw.mutate()}
          >
            Stop trusting
          </button>
        </p>
      )}
      {withdraw.error != null && (
        <Failed error={withdraw.error} what="That could not be stopped." />
      )}

      <h4>{held ? "Trust again, or another upstream" : "Name one"}</h4>
      <Field
        label="Provider description"
        value={url}
        onChange={(next) => {
          setUrl(next);
          inspect.reset();
        }}
        placeholder="https://psirt.example.org/.well-known/csaf/provider-metadata.json"
        hint="https only. Every request goes to this host and no other."
      />
      {inspect.error != null && (
        <Failed error={inspect.error} what="That upstream could not be read." />
      )}
      {checked && (
        <dl className="facts">
          <dt>Publisher</dt>
          <dd>{checked.publisher}</dd>
          <dt>Signing key</dt>
          <dd className="id">{checked.fingerprint || "none — checked by digest only"}</dd>
        </dl>
      )}
      {trust.error != null && (
        <Failed error={trust.error} what="That upstream could not be trusted." />
      )}
    </Drawer>
  );
}

// The upstream as trusted, and how reading it is going.
function Trusted({ held, onRetrust }: { held: Upstream; onRetrust: () => void }) {
  return (
    <>
      <dl className="facts">
        <dt>Publisher</dt>
        <dd>{held.publisher}</dd>
        <dt>Description</dt>
        <dd className="id">{held.url}</dd>
        <dt>Signing key</dt>
        <dd className="id">{held.fingerprint || "none — checked by digest only"}</dd>
        <dt>Last read</dt>
        <dd>{held.read ? since(held.read) : <span className="hint">never</span>}</dd>
        {held.because && (
          <>
            <dt>Last error</dt>
            <dd>
              <span className="state bad">{held.tried ? since(held.tried) : "failing"}</span>{" "}
              {held.because}
            </dd>
          </>
        )}
      </dl>
      {held.key_offered && (
        <div className="alert" role="status">
          <strong>
            {held.key_offered === "none"
              ? "The upstream now names no signing key."
              : `The upstream now signs with ${held.key_offered}.`}
          </strong>
          <span>Nothing is read until you trust it.</span>
          <button type="button" className="linkish" onClick={onRetrust}>
            Check it
          </button>
        </div>
      )}
    </>
  );
}
