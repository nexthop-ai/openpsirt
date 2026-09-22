import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Paged } from "../ui/Paged";
import { Wide } from "../ui/Wide";

// The most one page asks for. Long enough that an ordinary night fits on one
// page, short enough that a build which replaced everything does not arrive as
// one screen of two thousand rows.
const PAGE = 200;

// What one upload changed about a build's inventory.
//
// The receipt says how many names moved and this says which. Removals come
// first: a build that stopped describing a dependency looks exactly like one
// that stopped shipping it, and telling those apart is somebody reading this
// page beside the build.
export function InventoryChanges() {
  const { product = "", stream = "", variant = "", scan = "" } = useParams();
  const [offset, setOffset] = useState(0);
  const [only, setOnly] = useState<"" | "removed" | "added" | "changed">("");
  const at = { product, stream, variant, scan: Number(scan) };
  const build =
    `/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}`;

  const changes = useQuery({
    queryKey: ["inventory-changes", at, only, offset],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/streams/{stream}/variants/{variant}/scans/{scan}/changes",
          {
            params: {
              path: at,
              query: { limit: PAGE, offset, ...(only ? { change: only } : {}) },
            },
          },
        ),
      ),
  });

  if (changes.isPending) return <Loading />;
  if (changes.isError)
    return <Failed error={changes.error} what="What this upload changed could not be read." />;

  const items = changes.data?.items ?? [];
  const total = changes.data?.total ?? 0;

  return (
    <div>
      <div className="screen-head">
        <span className="crumbs">
          <Link to={`${build}/scans`} className="linkish" style={{ fontWeight: 500 }}>
            Inventories
          </Link>{" "}
          › <b>upload {scan}</b>
        </span>
        <h2>What this upload changed</h2>
        <p>
          {product} · {stream} · {variant} · against the upload before it
        </p>
      </div>

      {/* One kind at a time, asked of the server so that the count in the
          footer is of that kind rather than of the page. */}
      <div className="variants" style={{ marginBottom: 10 }}>
        {(
          [
            ["", "Everything"],
            ["removed", "Removed"],
            ["added", "Added"],
            ["changed", "New version"],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value || "all"}
            type="button"
            className={`chip${only === value ? " on" : ""}`}
            aria-pressed={only === value}
            onClick={() => {
              setOnly(value);
              setOffset(0);
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {items.length === 0 ? (
        /* Two different emptinesses. Narrowed to one kind, what is empty is
           the narrowing; unnarrowed, it is the upload — and the shipped
           sentence about a first upload is wrong about the first of those. */
        only ? (
          <Empty
            title={`Nothing was ${only === "changed" ? "moved to a new version" : only}.`}
            detail="This upload changed other things."
          >
            {/* The way back, because the chips that produced this are above a
                screen somebody may have scrolled. */}
            <button
              type="button"
              className="btn"
              onClick={() => {
                setOnly("");
                setOffset(0);
              }}
            >
              Show everything
            </button>
          </Empty>
        ) : (
          <Empty
            title="Nothing changed here."
            detail="The first upload read for a build is a picture of it rather than a change to one. A rebuild that moved nothing says the same."
          />
        )
      ) : (
        <>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Change</th>
                  <th>Before</th>
                  <th>After</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={`${row.change} ${row.name}`}>
                    <td>
                      {/* The component's own page, where what is open against
                          it is. A name that went is not there any more, so it
                          is the one that is not a link. */}
                      {row.change === "removed" ? (
                        row.name
                      ) : (
                        <Link
                          to={`/products/${encodeURIComponent(product)}/components/${encodeURIComponent(row.name ?? "")}`}
                        >
                          {row.name}
                        </Link>
                      )}
                    </td>
                    <td>
                      <Moved change={row.change} />
                    </td>
                    <td className="hint">{(row.before ?? []).join(", ") || "—"}</td>
                    <td className="hint">{(row.after ?? []).join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
          <Paged
            shown={items.length}
            total={total}
            offset={offset}
            limit={PAGE}
            onGo={setOffset}
            what="listed"
          />
        </>
      )}
    </div>
  );
}

// What happened to one name, as a word.
//
// A removal is marked rather than merely named: it is the one a reader is
// looking for, and it is the one that reads as harmless.
function Moved({ change }: { change?: string }) {
  if (change === "removed") return <span className="sev high">removed</span>;
  if (change === "added") return <span className="chip">added</span>;
  return <span className="chip">new version</span>;
}
