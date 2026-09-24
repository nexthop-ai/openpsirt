// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Editor } from "../ui/Editor";
import { Failed } from "../ui/Failed";

// The act that ends an embargo: this issue, in this product, made public.
//
// It sits in the notice that says the issue is undisclosed, because that is
// the one place on the screen where somebody is thinking about who may know.
// The server decides whether a second person has to agree; this says which it
// was.
export function Disclose({ product, vulnerability }: { product: string; vulnerability: string }) {
  const queries = useQueryClient();
  const [open, setOpen] = useState(false);
  const [because, setBecause] = useState("");
  const [said, setSaid] = useState<string | null>(null);

  const disclose = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/disclosure", {
          params: { path: { product, vulnerability } },
          body: { reason: because },
        }),
      ),
    onSuccess: (asked) => {
      setSaid(
        asked.in_force ? "Disclosed." : "Asked. It stays undisclosed until a second person agrees.",
      );
      setOpen(false);
      setBecause("");
      void queries.invalidateQueries({ queryKey: ["finding"] });
      void queries.invalidateQueries({ queryKey: ["disclosing"] });
    },
  });

  if (said) {
    return <div className="hint">{said}</div>;
  }
  if (!open) {
    return (
      <button type="button" className="linkish" onClick={() => setOpen(true)}>
        Disclose…
      </button>
    );
  }
  return (
    <div style={{ marginTop: 8 }}>
      <p className="hint">
        Makes this issue public in {product}, with every comment and decision on it. Can&rsquo;t be
        undone.
      </p>
      <Editor
        value={because}
        onChange={setBecause}
        rows={3}
        label="The reason it is being disclosed"
        placeholder="What is public now, or where it was published."
      />
      <div className="actions" style={{ marginTop: 8 }}>
        <button
          type="button"
          className="btn"
          disabled={!because.trim() || disclose.isPending}
          onClick={() => disclose.mutate()}
        >
          {disclose.isPending ? "Disclosing…" : "Disclose"}
        </button>
        <button type="button" className="btn ghost" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      {disclose.isError && <Failed error={disclose.error} what="That issue was not disclosed." />}
    </div>
  );
}
