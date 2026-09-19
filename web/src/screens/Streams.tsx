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

// A branch and a tag are different shapes of thing — one moves and is rebuilt,
// one never changes again — so they are labeled rather than blended into a
// single list of names. A tag names the branch it was cut from, which is what
// lets a branch be compared against its last release.
export function Streams() {
  const { product = "" } = useParams();
  const queries = useQueryClient();
  const who = useWho();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"branch" | "tag">("branch");
  const [parent, setParent] = useState("");
  const streams = useQuery({
    // Keyed as counted, so this and the picker's uncounted read of the same
    // list are two cache entries rather than a race between them.
    queryKey: ["streams", product, "counts"],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams", {
          params: { path: { product }, query: { counts: true } },
        }),
      ),
  });

  const declare = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/streams", {
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
      void queries.invalidateQueries({ queryKey: ["streams", product] });
    },
  });

  const setEndOfLife = useMutation({
    mutationFn: async ({ stream, on }: { stream: string; on: string }) =>
      unwrap(
        await api.PUT("/v1/products/{product}/streams/{stream}/end-of-life", {
          params: { path: { product, stream } },
          body: { on },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["streams", product] }),
  });
  // The day a release went out, and the branch it was cut from. Both after the
  // fact, because that is when they are usually known: a tag is declared here
  // so scans can be filed against it, which happens whenever somebody gets to
  // it — and fixed at declaration, the release-over-release chart is an
  // accident of administration.
  const setRelease = useMutation({
    mutationFn: async ({ stream, on, from }: { stream: string; on: string; from: string }) =>
      unwrap(
        await api.PUT("/v1/products/{product}/streams/{stream}/release", {
          params: { path: { product, stream } },
          body: { released_on: on, ...(from ? { cut_from: from } : {}) },
        }),
      ),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["streams", product] });
      void queries.invalidateQueries({ queryKey: ["trend"] });
    },
  });

  if (streams.isPending) return <Loading />;
  if (streams.isError) {
    return <Failed error={streams.error} what="The branches and tags could not be read." />;
  }

  const items = streams.data?.items ?? [];
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
                  title="Issues open against it, counted at components rather than at every place they sit"
                >
                  Open
                </th>
                <th>Out of support</th>
                <th>Last inventory</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((stream) => (
                <tr key={stream.name} className="row">
                  <td>
                    <Link
                      to={`/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(stream.name ?? "")}`}
                      className="id"
                    >
                      {stream.name}
                    </Link>
                  </td>
                  <td>
                    <span className={stream.kind === "tag" ? "state agreed" : "state open"}>
                      {stream.kind === "tag" ? "Tag" : "Branch"}
                    </span>
                  </td>
                  <td>
                    {/* Filled in after the fact, never changed: a
                        pipeline that does not know declares the tag without
                        it, and saying it late is the same act arriving late.
                        A tag came from wherever it came from, so once it says
                        so the picker is gone rather than offering a change
                        the server would refuse. */}
                    {stream.kind === "tag" && !stream.parent && (who.data?.admin ?? false) ? (
                      <select
                        value={stream.parent ?? ""}
                        onChange={(event) =>
                          setRelease.mutate({
                            stream: stream.name ?? "",
                            on: stream.released_on ?? "",
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
                    ) : stream.parent ? (
                      <span className="id">{stream.parent}</span>
                    ) : (
                      <span style={{ color: "var(--faint)" }}>—</span>
                    )}
                  </td>
                  <td>
                    {stream.kind !== "tag" ? (
                      <span
                        style={{ color: "var(--faint)" }}
                        title="A branch is rebuilt rather than released"
                      >
                        —
                      </span>
                    ) : (who.data?.admin ?? false) ? (
                      <input
                        type="date"
                        style={{ width: 150 }}
                        value={stream.released_on ?? ""}
                        onChange={(event) =>
                          setRelease.mutate({
                            stream: stream.name ?? "",
                            on: event.target.value,
                            from: stream.parent ?? "",
                          })
                        }
                      />
                    ) : stream.released_on ? (
                      on(stream.released_on)
                    ) : (
                      <span
                        className="hint"
                        title="Nobody has said, so the day it was declared here stands in"
                      >
                        not said
                      </span>
                    )}
                  </td>
                  <td className="num">{(stream.open ?? 0).toLocaleString()}</td>
                  <td>
                    <EndOfLife
                      what={`${stream.name} goes out of support`}
                      on={stream.end_of_life ?? ""}
                      inherited={stream.end_of_life_inherited}
                      admin={who.data?.admin ?? false}
                      onSet={(on) => setEndOfLife.mutate({ stream: stream.name, on })}
                    />
                  </td>
                  <td className="hint">
                    {stream.last_scan_at ? (
                      /* When it last ran is asked as "is this stale", so the
                         relative form leads and the exact day is on the title
                         rather than lost. */
                      <span title={on(stream.last_scan_at)}>{since(stream.last_scan_at)}</span>
                    ) : (
                      "never"
                    )}
                  </td>
                  <td>
                    <Link
                      to={`/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(stream.name ?? "")}`}
                      className="linkish"
                    >
                      Variants
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

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
          placeholder="202411"
          hint="How scans name it"
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
            {/* It looked optional and it decides something. Release readiness
                asks what was cut from a branch, so a tag that never says
                leaves the branch reporting that nothing has ever shipped. */}
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
