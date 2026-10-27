// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { notACredential } from "../ui/noautofill";
import { useState } from "react";
import { Loading } from "../ui/Loading";
import { on, since } from "../ui/when";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Crumbs } from "../ui/Crumbs";
import { Empty } from "../ui/Empty";
import { EndOfLife } from "../ui/EndOfLife";
import { Failed } from "../ui/Failed";
import { Wide } from "../ui/Wide";
import { branchOrTagAt } from "../app/routes";

// A branch and a tag are different shapes of thing — one moves and is rebuilt,
// one never changes again — so they are labeled rather than blended into a
// single list of names. A tag names the branch it was cut from, which is what
// lets a branch be compared against its last release.
export function Branches() {
  const { product = "" } = useParams();
  const queries = useQueryClient();
  const who = useWho();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"branch" | "tag">("branch");
  const [parent, setParent] = useState("");
  // The release the edit drawer is open on, by its stored name. Empty is
  // closed, so one piece of state answers both which row and whether.
  const [editing, setEditing] = useState("");
  const [renameTo, setRenameTo] = useState("");
  const branchesAndTags = useQuery({
    // Keyed as counted, so this and the picker's uncounted read of the same
    // list are two cache entries rather than a race between them.
    queryKey: ["branches_and_tags", product, "counts"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/branches-and-tags", {
          params: { path: { product }, query: { counts: true } },
        }),
      ),
  });

  const declare = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/branches-and-tags", {
          params: { path: { product } },
          body: {
            name: name.trim(),
            kind,
            ...(kind === "tag" && parent.trim() ? { parent: parent.trim() } : {}),
          },
        }),
      ),
    onSuccess: () => {
      setName("");
      setParent("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["branches_and_tags", product] });
    },
  });

  const amend = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/v1/products/{product}/branches-and-tags/{branch_or_tag}", {
          params: { path: { product, branch_or_tag: editing } },
          body: { name: renameTo.trim() },
        }),
      ),
    onSuccess: () => {
      setEditing("");
      void queries.invalidateQueries({ queryKey: ["branches_and_tags", product] });
    },
  });

  const retire = useMutation({
    mutationFn: async (branchOrTag: string) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/branches-and-tags/{branch_or_tag}", {
          params: { path: { product, branch_or_tag: branchOrTag } },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["branches_and_tags", product] }),
  });

  const edit = (branchOrTag: { name?: string }) => {
    setEditing(branchOrTag.name ?? "");
    setRenameTo(branchOrTag.name ?? "");
    amend.reset();
  };

  const setEndOfLife = useMutation({
    mutationFn: async ({ branch_or_tag: branchOrTag, on }: { branch_or_tag: string; on: string }) =>
      unwrap(
        await api.PUT("/v1/products/{product}/branches-and-tags/{branch_or_tag}/end-of-life", {
          params: { path: { product, branch_or_tag: branchOrTag } },
          body: { on },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["branches_and_tags", product] }),
  });
  // The day a release went out, and the branch it was cut from. Both after the
  // fact, because that is when they are usually known: a tag is declared here
  // so scans can be filed against it, which happens whenever somebody gets to
  // it — and fixed at declaration, the release-over-release chart is an
  // accident of administration.
  const setRelease = useMutation({
    mutationFn: async ({
      branch_or_tag: branchOrTag,
      on,
      from,
    }: {
      branch_or_tag: string;
      on: string;
      from: string;
    }) =>
      unwrap(
        await api.PUT("/v1/products/{product}/branches-and-tags/{branch_or_tag}/release", {
          params: { path: { product, branch_or_tag: branchOrTag } },
          body: { released_on: on, ...(from ? { cut_from: from } : {}) },
        }),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["branches_and_tags", product] });
      // The release-over-release charts on the front page read the dates.
      void queries.invalidateQueries({ queryKey: ["home", "trend"] });
      void queries.invalidateQueries({ queryKey: ["home", "release-trend"] });
    },
  });

  if (branchesAndTags.isPending) return <Loading />;
  if (branchesAndTags.isError) {
    return <Failed error={branchesAndTags.error} what="The branches and tags could not be read." />;
  }

  const items = branchesAndTags.data?.items ?? [];
  const branches = items.filter((s) => s.kind !== "tag").map((s) => s.name ?? "");
  return (
    <>
      <Crumbs product={product} />
      <div className="screen-head">
        <h2>Branches and tags</h2>
        <p>The releases of {product}, past and in progress. A branch moves; a tag never does.</p>
        {who.data?.admin && <AddButton label="Add branch or tag" onClick={() => setAdding(true)} />}
      </div>

      {/* A refused write is said. Without this the select snaps back to what
          it held, the administrator reads that as their own mis-click, and
          they try the same thing again. */}
      {setEndOfLife.isError && (
        <Failed error={setEndOfLife.error} what="That support date could not be set." />
      )}
      {setRelease.isError && (
        <Failed error={setRelease.error} what="That release could not be recorded." />
      )}

      {items.length === 0 ? (
        <Empty
          title="Nothing is declared here yet."
          detail="A branch or a tag is declared before a scan can be filed against it."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Cut from</th>
                <th>Released</th>
                <th
                  className="num"
                  title="Issues open against it, counted at components rather than at every occurrence they sit"
                >
                  Open
                </th>
                <th>Out of support</th>
                <th>Last inventory</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((branchOrTag) => (
                <tr key={branchOrTag.name} className="row">
                  <td>
                    <Link to={branchOrTagAt(product, branchOrTag.name ?? "")} className="id">
                      {branchOrTag.name}
                    </Link>
                  </td>
                  <td>
                    <span className={branchOrTag.kind === "tag" ? "state agreed" : "state open"}>
                      {branchOrTag.kind === "tag" ? "Tag" : "Branch"}
                    </span>
                  </td>
                  <td>
                    {/* Filled in after the fact, never changed: a
                        pipeline that does not know declares the tag without
                        it, and saying it late is the same act arriving late.
                        A tag came from wherever it came from, so once it says
                        so the picker is gone rather than offering a change
                        the server would refuse. */}
                    {branchOrTag.kind === "tag" &&
                    !branchOrTag.parent &&
                    (who.data?.admin ?? false) ? (
                      <select
                        value={branchOrTag.parent ?? ""}
                        onChange={(event) =>
                          setRelease.mutate({
                            branch_or_tag: branchOrTag.name ?? "",
                            on: branchOrTag.released_on ?? "",
                            from: event.target.value,
                          })
                        }
                      >
                        <option value="">not said</option>
                        {branches.map((each) => (
                          <option key={each} value={each}>
                            {each}
                          </option>
                        ))}
                      </select>
                    ) : branchOrTag.parent ? (
                      <span className="id">{branchOrTag.parent}</span>
                    ) : (
                      <span style={{ color: "var(--faint)" }}>—</span>
                    )}
                  </td>
                  <td>
                    {branchOrTag.kind !== "tag" ? (
                      <span
                        style={{ color: "var(--faint)" }}
                        title="A branch is rebuilt rather than released"
                      >
                        —
                      </span>
                    ) : (who.data?.admin ?? false) ? (
                      <ReleasedOn
                        key={`${branchOrTag.name} ${branchOrTag.released_on ?? ""}`}
                        on={branchOrTag.released_on ?? ""}
                        busy={setRelease.isPending}
                        onSet={(on) =>
                          setRelease.mutate({
                            branch_or_tag: branchOrTag.name ?? "",
                            on,
                            from: branchOrTag.parent ?? "",
                          })
                        }
                      />
                    ) : branchOrTag.released_on ? (
                      on(branchOrTag.released_on)
                    ) : (
                      <span
                        className="hint"
                        title="Nobody has said, so the day it was declared here stands in"
                      >
                        not said
                      </span>
                    )}
                  </td>
                  <td className="num">{(branchOrTag.open ?? 0).toLocaleString()}</td>
                  <td>
                    <EndOfLife
                      what={`${branchOrTag.name} goes out of support`}
                      on={branchOrTag.end_of_life ?? ""}
                      inherited={branchOrTag.end_of_life_inherited}
                      admin={who.data?.admin ?? false}
                      onSet={(on) => setEndOfLife.mutate({ branch_or_tag: branchOrTag.name, on })}
                    />
                  </td>
                  <td className="hint">
                    {branchOrTag.last_scan_at ? (
                      /* When it last ran is asked as "is this stale", so the
                         relative form code findings and the exact day is on the title
                         rather than lost. */
                      <span title={on(branchOrTag.last_scan_at)}>
                        {since(branchOrTag.last_scan_at)}
                      </span>
                    ) : (
                      "never"
                    )}
                  </td>
                  <td className="rowacts">
                    <Link to={branchOrTagAt(product, branchOrTag.name ?? "")} className="linkish">
                      Variants
                    </Link>
                    {who.data?.admin && (
                      <>
                        <button
                          type="button"
                          className="linkish"
                          title="Correct what it is called."
                          onClick={() => edit(branchOrTag)}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="linkish"
                          style={{ color: "var(--muted)" }}
                          title="Take it out of use. Findings, decisions and published documents keep naming it. Not the same as an end-of-support date."
                          disabled={retire.isPending}
                          onClick={() => retire.mutate(branchOrTag.name ?? "")}
                        >
                          Retire
                        </button>
                      </>
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
        hint="Locked once a published document names it."
      >
        <Field
          label="Name"
          value={renameTo}
          onChange={setRenameTo}
          placeholder="master"
          hint="What builds and scans call it"
        />
      </Declare>

      {/* A refused retirement is said. Without it the button re-enables and
          the row stays, which reads as nothing having happened. */}
      {retire.error != null && <Failed error={retire.error} what="That could not be retired." />}

      <Declare
        title="Add branch or tag"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() => declare.mutate()}
        error={declare.error}
        busy={declare.isPending || name.trim() === ""}
        ok={kind === "tag" ? "Add tag" : "Add branch"}
        hint="Naming the branch a tag was cut from carries its decisions into the tag."
      >
        {/* The label wraps the input, as every other field here does, so a
            screen reader names the field. */}
        <label className="field">
          <span>Product</span>
          <input {...notACredential} type="text" value={product} disabled />
        </label>
        <Field
          label="Name"
          value={name}
          onChange={setName}
          placeholder="202411"
          hint="The name scans use for it"
        />
        <div className="field">
          <label htmlFor="declare-kind">Kind</label>
          <select
            id="declare-kind"
            value={kind}
            onChange={(event) => setKind(event.target.value as "branch" | "tag")}
          >
            <option value="branch">Branch — moves, scanned nightly</option>
            <option value="tag">Tag — frozen, scanned on a schedule</option>
          </select>
        </div>
        {kind === "tag" && (
          <div className="field">
            <label htmlFor="declare-cut-from">Cut from</label>
            <select
              id="declare-cut-from"
              value={parent}
              onChange={(event) => setParent(event.target.value)}
            >
              <option value="">None — a line of its own</option>
              {branches.map((branch) => (
                <option key={branch} value={branch}>
                  {branch}
                </option>
              ))}
            </select>
            {/* It decides something. Release readiness asks what was cut
                from a branch, so a tag that never says leaves the branch
                reporting that nothing has ever shipped. */}
            <p className="hint">
              An unnamed tag leaves its branch reading as never released. Declare the tag again to
              fill it in.
            </p>
          </div>
        )}
      </Declare>
    </>
  );
}

// The day a tag was released, written on Save. A date box fires a change for
// every segment typed, so a write per change records 0002, 0020 and 0202 on the
// way to 2026, each with a trail row.
function ReleasedOn({
  on,
  busy,
  onSet,
}: {
  on: string;
  busy: boolean;
  onSet: (on: string) => void;
}) {
  const [value, setValue] = useState(on);
  return (
    <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
      <input
        type="date"
        style={{ width: 150 }}
        aria-label="Released"
        value={value}
        onChange={(event) => setValue(event.target.value)}
      />
      {value !== on && (
        <button type="button" className="btn" disabled={busy} onClick={() => onSet(value)}>
          Save
        </button>
      )}
    </span>
  );
}
