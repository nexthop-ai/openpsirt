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

// The chat channels this deployment posts to.
//
// A channel belongs to the deployment, a product or a team, and is sent what is
// about that and no narrower channel takes. The bot's credential is
// configuration, so this screen names channels and never a token.
// DESIGN-notifications.md § Channel scope holds the rules.

type Destination = Body<"OutboundBody">;

// What a platform is called on screen.
const PLATFORMS: Record<string, string> = { slack: "Slack", zulip: "Zulip" };

// What a channel belongs to, as somebody would say it.
function scopeOf(row: Destination) {
  if (row.team) return `Team ${row.team}`;
  if (row.product) return `Product ${row.product}`;
  return "Everything";
}

type Scope = "deployment" | "product" | "team";

export function ChatChannels({ platforms }: { platforms: string[] }) {
  const queries = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("*");
  const [platform, setPlatform] = useState(platforms[0] ?? "");
  const [channel, setChannel] = useState("");
  const [topic, setTopic] = useState("");
  const [scope, setScope] = useState<Scope>("deployment");
  const [owner, setOwner] = useState("");

  const listed = useQuery({
    queryKey: ["outbound"],
    queryFn: async () => unwrap(await api.GET("/v1/outbound", {})),
  });
  const add = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/outbound", {
          body: {
            name: name.trim(),
            kind: kind.trim() || "*",
            platform: platform as "slack" | "zulip",
            channel: channel.trim(),
            ...(platform === "zulip" && topic.trim() !== "" ? { topic: topic.trim() } : {}),
            ...(scope === "product" ? { product: owner.trim() } : {}),
            ...(scope === "team" ? { team: owner.trim() } : {}),
          },
        }),
      ),
    onSuccess: () => {
      setName("");
      setKind("*");
      setChannel("");
      setTopic("");
      setScope("deployment");
      setOwner("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["outbound"] });
    },
  });
  const retire = useMutation({
    mutationFn: async (where: { name: string; kind: string }) =>
      unwrap(await api.DELETE("/v1/outbound/{name}/{kind}", { params: { path: where } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["outbound"] }),
  });

  // With no platform configured the channels still stored are listed, so
  // they can be retired rather than posting again when a token returns.
  const offered = platforms.length > 0;
  const rows = (listed.data?.items ?? []).filter((row) => row.platform !== "webhook");

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="screen-head">
        <h3>Chat channels</h3>
        {offered && <AddButton label="Add channel" onClick={() => setAdding(true)} />}
      </div>
      {!offered && (
        <p className="alert" style={{ marginTop: 0 }}>
          <strong>No chat platform is configured.</strong>
          <span>Set OPENPSIRT_SLACK_TOKEN or the Zulip settings, and restart.</span>
        </p>
      )}
      <p className="hint" style={{ marginTop: 0 }}>
        Each notification goes to the narrowest channel that takes it. A product or team channel
        never hears about undisclosed work.
      </p>
      {retire.error != null && (
        <Failed error={retire.error} what="That channel could not be retired." />
      )}
      {listed.isPending ? (
        <Loading />
      ) : listed.isError ? (
        <Failed error={listed.error} what="The chat channels could not be read." />
      ) : rows.length === 0 ? (
        offered && (
          <Empty
            title="No chat channels."
            detail="People still get direct messages about their own work."
          />
        )
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Channel</th>
                <th>For</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.name} ${row.kind}`} className="row">
                  <td className="id">{row.name}</td>
                  <td>{row.kind === "*" ? "everything" : row.kind}</td>
                  <td>
                    {PLATFORMS[row.platform ?? ""] ?? row.platform} ·{" "}
                    <span className="id">{row.channel}</span>
                    {row.topic ? ` › ${row.topic}` : ""}
                  </td>
                  <td>{scopeOf(row)}</td>
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
        title="Add chat channel"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() => add.mutate()}
        error={add.error}
        busy={
          name.trim() === "" ||
          channel.trim() === "" ||
          (scope !== "deployment" && owner.trim() === "") ||
          add.isPending
        }
        ok="Add channel"
        hint="Add the bot to the channel first. Notifications addressed to one person go to them directly, never to a channel."
      >
        <Field label="Name" value={name} onChange={setName} placeholder="kernel-psirt" />
        <Field
          label="Kind"
          value={kind}
          onChange={setKind}
          placeholder="*"
          hint="One notification kind, or * for all of them."
        />
        {platforms.length > 1 && (
          <div className="field">
            <label htmlFor="chat-platform">Platform</label>
            <select
              id="chat-platform"
              value={platform}
              onChange={(event) => setPlatform(event.target.value)}
            >
              {platforms.map((each) => (
                <option key={each} value={each}>
                  {PLATFORMS[each] ?? each}
                </option>
              ))}
            </select>
          </div>
        )}
        <Field
          label="Channel"
          value={channel}
          onChange={setChannel}
          placeholder={platform === "slack" ? "C0123ABCD" : "security"}
          hint={platform === "slack" ? "The channel ID, from the channel's details." : undefined}
        />
        {platform === "zulip" && (
          <Field label="Topic" value={topic} onChange={setTopic} placeholder="OpenPSIRT" />
        )}
        <div className="field">
          <label htmlFor="chat-scope">For</label>
          <select
            id="chat-scope"
            value={scope}
            onChange={(event) => setScope(event.target.value as Scope)}
          >
            <option value="deployment">Everything</option>
            <option value="product">One product</option>
            <option value="team">One team</option>
          </select>
        </div>
        {scope !== "deployment" && (
          <Field
            label={scope === "product" ? "Product" : "Team"}
            value={owner}
            onChange={setOwner}
          />
        )}
      </Declare>
    </div>
  );
}
