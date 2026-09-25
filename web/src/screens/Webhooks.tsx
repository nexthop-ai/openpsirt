// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Wide } from "../ui/Wide";

// The destinations this deployment posts to, and whether anything is arriving.
//
// Webhooks, not "where things are sent". One signed request rather than an
// adapter each: Slack, Teams, a tracker driven by automation and paging all
// take an HTTP POST with a JSON body, carrying a timestamp and an HMAC over it
// and the body. The kind says which notifications go to a destination, never
// how they travel, and mail is a path of its own — so the conventional word is
// accurate as well as shorter (REQ-60). The signing secret is returned by
// nothing, so changing one means recording the destination again.
//
// Two panels, because they answer to two readers. Configuring one is
// administration and belongs beside the other things a deployment is set to.
// Delivery is operations, and belongs beside the queues — a
// destination that has been refusing for a week looks exactly like a
// destination nothing has been sent to, which is the failure the system screen
// exists to make visible.
//
// For two of the services this names, the path of the address authenticates,
// so the server returns the host alone and a failure is recorded with the
// address replaced by its host. A destination is told apart by its name and
// kind.

// One row as both panels read it, from the document the server publishes
// rather than restated here: a hand-copied shape compiles perfectly while
// missing whatever the server grew since, which is the bug the readiness rows
// in this same change were carrying.
type Destination = Body<"OutboundBody">;

function useDestinations() {
  return useQuery({
    queryKey: ["outbound"],
    queryFn: async () => unwrap(await api.GET("/v1/outbound", {})),
  });
}

// A kind's own word. A destination taking everything says so in a word
// rather than in the wildcard the address is stored with.
function kindOf(kind?: string) {
  return kind === "*" ? "everything" : kind;
}

// The number failing, and the reason the last one did.
function Failing({ row }: { row: Destination }) {
  if ((row.failing ?? 0) === 0) return <span style={{ color: "var(--faint)" }}>none</span>;
  return (
    <span className="state bad" title={row.because}>
      {(row.failing ?? 0).toLocaleString()}
    </span>
  );
}

// The configuration. Administrator-only, and gated as a whole rather than
// per control: the endpoint behind it refuses anybody who is not an
// administrator, so a panel drawn for an auditor would be a panel that could
// only fail.
export function Webhooks() {
  const queries = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("*");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");

  const sent = useDestinations();
  const add = useMutation({
    mutationFn: async (body: { name: string; kind: string; url: string; secret: string }) =>
      unwrap(await api.POST("/v1/outbound", { body })),
    onSuccess: () => {
      setName("");
      setKind("*");
      setUrl("");
      setSecret("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["outbound"] });
    },
  });
  const retire = useMutation({
    mutationFn: async (where: { name: string; kind: string }) =>
      unwrap(await api.DELETE("/v1/outbound/{name}/{kind}", { params: { path: where } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["outbound"] }),
  });

  const rows = sent.data?.items ?? [];

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="screen-head">
        <h3>Webhooks</h3>
        <AddButton label="Add webhook" onClick={() => setAdding(true)} />
      </div>
      <p className="hint" style={{ marginTop: 0 }}>
        Each request carries a timestamp and an HMAC signature. Delivery status is on the System
        screen.
      </p>
      {retire.error != null && (
        <Failed error={retire.error} what="That webhook could not be retired." />
      )}
      {sent.isPending ? (
        <Loading />
      ) : sent.isError ? (
        <Failed error={sent.error} what="The webhooks could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title="No webhooks."
          detail="Notifications stay inside the application, and mail goes where an address is recorded."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Host</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.name} ${row.kind}`} className="row">
                  <td className="id">{row.name}</td>
                  <td>{kindOf(row.kind)}</td>
                  {/* Not a link: it is somewhere this deployment posts to,
                      not somewhere a person goes. */}
                  <td className="id">{row.host}</td>
                  <td>
                    <button
                      type="button"
                      className="linkish"
                      disabled={retire.isPending}
                      onClick={() => retire.mutate({ name: row.name ?? "", kind: row.kind ?? "" })}
                    >
                      Retire
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      <Declare
        title="Add webhook"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() =>
          add.mutate({
            name: name.trim(),
            kind: kind.trim() || "*",
            url: url.trim(),
            secret: secret.trim(),
          })
        }
        error={add.error}
        busy={name.trim() === "" || url.trim() === "" || secret.trim().length < 16 || add.isPending}
        ok="Add webhook"
        hint="https only. A redirect is refused rather than followed: the body is signed and not encrypted."
      >
        <Field
          label="Name"
          value={name}
          onChange={setName}
          placeholder="security-channel"
          hint="The name a log line and this screen use for it."
        />
        <Field
          label="Kind"
          value={kind}
          onChange={setKind}
          placeholder="*"
          hint="One notification kind, or * for all of them."
        />
        <Field
          label="URL"
          value={url}
          onChange={setUrl}
          placeholder="https://hooks.example.com/services/…"
        />
        <Field
          label="Signing secret"
          value={secret}
          onChange={setSecret}
          hint="At least 16 characters. It signs our requests rather than authenticating anybody to us, and no endpoint ever returns it."
        />
      </Declare>
    </div>
  );
}

// The health. Beside the queues, because it fails the same silent way they do.
//
// Named for delivery rather than for what is wrong, so an empty panel is read
// correctly: "no webhooks failing" drawn empty is good news and "webhook
// delivery" drawn empty is not, and this one is empty when nothing is
// configured.
//
// No address column, and the reason is safe to show: a failure is stored with
// the address replaced by its host, so it says which destination without
// saying what authenticates to it. What is not drawn is still in the response,
// so this panel is administrator-only because its endpoint is — see the head
// of this file.
export function WebhookDelivery() {
  const sent = useDestinations();
  const rows = sent.data?.items ?? [];

  return (
    <section className="panel">
      <h3>Webhook delivery</h3>
      <p className="hint" style={{ marginTop: 0 }}>
        Whether what this deployment posts is arriving. They are configured under Settings.
      </p>
      {sent.isPending ? (
        <Loading />
      ) : sent.isError ? (
        <Failed error={sent.error} what="Webhook delivery could not be read." />
      ) : rows.length === 0 ? (
        <Empty
          title="No webhooks."
          detail="Notifications stay inside the application, and mail goes where an address is recorded."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Sent</th>
                <th>Failing</th>
                <th>Last error</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.name} ${row.kind}`} className="row">
                  <td className="id">{row.name}</td>
                  <td>{kindOf(row.kind)}</td>
                  <td>{(row.sent ?? 0).toLocaleString()}</td>
                  <td>
                    <Failing row={row} />
                  </td>
                  <td className="hint">
                    {row.because || <span style={{ color: "var(--faint)" }}>nothing said</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}
    </section>
  );
}
