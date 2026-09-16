import { notACredential } from "../ui/noautofill";
import { useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { useWho } from "../app/session";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { UNITS, write, type Unit } from "./duration";
import { Wide } from "../ui/Wide";

// A person's own page: what they can reach, what is sent to them, and the
// credentials they hold.
//
// **Two of these were more than an omission.** A person could not mint a token
// for a script anywhere in the interface, and could not turn the daily digest
// on at all — though the documentation says it is off until asked for, which
// leaves somebody looking for a switch that exists only in the API.
//
// The digest matters more after routing by rule: it is what tells somebody
// that work arrived for their team without anybody sending a message.
export function Me() {
  const who = useWho();
  const queries = useQueryClient();

  if (who.isPending) return <Loading />;
  if (who.isError) {
    return <Failed error={who.error} what="Your own details could not be read." />;
  }
  if (!who.data) return null;
  const me = who.data;

  return (
    <>
      <div className="screen-head">
        <h2>{me.name || me.identity}</h2>
        <p>
          <span className="id">{me.identity}</span>
          {me.admin && (
            <>
              {" "}
              · <span className="state agreed">administrator</span>
            </>
          )}
        </p>
      </div>

      <div className="card">
        <h3>Your access</h3>
        {(me.reach ?? []).length === 0 ? (
          <p className="reading">Nothing yet. An administrator grants access.</p>
        ) : (
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Product</th>
                  <th>What you may do</th>
                </tr>
              </thead>
              <tbody>
                {(me.reach ?? []).map((where) => (
                  <tr key={where.product} className="row">
                    <td>{where.name || where.product}</td>
                    <td>
                      <span className="variants">
                        {/* What they may do rather than which roles they
                            hold: the mapping from one to the other is the
                            server's, and a second copy of it here would be
                            the one that drifts. */}
                        {where.sees_all
                          ? chip("Reads everything, including undisclosed")
                          : where.may_see && chip("Reads disclosed findings")}
                        {where.may_hide
                          ? chip("Argues about undisclosed findings")
                          : where.may_triage && chip("Argues about findings")}
                        {where.may_assign && chip("Hands work to others")}
                        {where.may_agree && chip("Agrees to somebody else's claim")}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        )}
        <p className="hint" style={{ marginTop: 8 }}>
          Shown as what you may do, not the roles behind it.
        </p>
      </div>

      <Digest
        on={!!me.digest}
        unassigned={!!me.digest_unassigned}
        reachable={!!me.reachable}
        onSet={() => void queries.invalidateQueries({ queryKey: ["me"] })}
      />

      <Tokens />
    </>
  );
}

function chip(label: string) {
  return (
    <span key={label} className="vchip">
      {label}
    </span>
  );
}

// The daily digest, which is off until asked for.
//
// **Nothing is sent without an address recorded**, so where there is none the
// switch says that rather than being offered: a control that changes nothing
// is worse than a control that is not there, because pressing it looks like it
// worked.
function Digest({
  on,
  unassigned,
  reachable,
  onSet,
}: {
  on: boolean;
  unassigned: boolean;
  reachable: boolean;
  onSet: () => void;
}) {
  const set = useMutation({
    mutationFn: async (body: { digest: boolean; unassigned?: boolean }) =>
      unwrap(await api.PUT("/v1/session/me/digest", { body })),
    onSuccess: onSet,
  });

  return (
    <div className="card">
      <h3>Notifications</h3>
      <p className="reading" style={{ marginBottom: 8 }}>
        A daily digest of work that became yours without a message, and optionally new unassigned
        findings.
      </p>
      {set.error != null && <Failed error={set.error} what="That could not be changed." />}
      {!reachable ? (
        <p className="alert" style={{ margin: 0 }}>
          <strong>No address is recorded for you.</strong>
          <span>An administrator has to record one before anything can be sent.</span>
        </p>
      ) : (
        <div className="filters">
          <label style={{ display: "flex", gap: 7, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={on}
              disabled={set.isPending}
              onChange={(event) =>
                set.mutate({
                  digest: event.target.checked,
                  unassigned: unassigned && event.target.checked,
                })
              }
            />
            Send me a daily digest
          </label>
          <label style={{ display: "flex", gap: 7, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={unassigned}
              // Asking for the second without the first is refused by the
              // server, so it is not offered here either.
              disabled={!on || set.isPending}
              onChange={(event) => set.mutate({ digest: on, unassigned: event.target.checked })}
            />
            Include findings nobody owns
          </label>
        </div>
      )}
    </div>
  );
}

// Personal tokens, for scripts.
//
// **Shown once, at creation.** What is stored is a digest, so a secret nobody
// copied is a token nobody can use — and the screen says so before it is
// dismissed rather than after.
function Tokens() {
  const queries = useQueryClient();
  const [name, setName] = useState("");
  // Held as typed rather than as a number. Read through Number(), clearing
  // the box was zero, which the writer floored at one — so an empty field
  // minted a token lasting an hour rather than refusing to mint one at all.
  const [count, setCount] = useState("30");
  const [product, setProduct] = useState("");
  // Whether the token carries only the roles that read. The narrowing the
  // server takes is a list of roles; this offers the one shape somebody
  // actually asks for, which is a credential for a script that only looks.
  const [readOnly, setReadOnly] = useState(false);
  const [unit, setUnit] = useState<Unit>("days");
  const [minted, setMinted] = useState<{ name: string; secret: string } | null>(null);
  // How long it lasts, or nothing where the box says something that is not a
  // count of them. An expiry is required, so nothing is a reason to refuse
  // rather than a number to invent.
  const lasts = Number.isInteger(Number(count)) && Number(count) >= 1;

  const tokens = useQuery({
    queryKey: ["tokens"],
    queryFn: async () => unwrap(await api.GET("/v1/tokens", {})),
  });
  // What this person may narrow a token to. Only what they can already read is
  // listed, because narrowing intersects: a token pinned to something its
  // owner cannot reach is a token that reaches nothing.
  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
  const mint = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/tokens", {
          body: {
            name: name.trim(),
            lifetime: write(Number(count), unit),
            // Empty means it reaches whatever its owner reaches. Narrowing
            // intersects rather than adds, so naming a product its owner
            // cannot read reaches nothing.
            ...(product ? { product } : {}),
            // Both reading roles, because which one it lands on is whichever
            // its owner holds — the server intersects, so naming the pair
            // narrows to reading without asking the browser who holds what.
            ...(readOnly ? { holds: ["public-read", "private-read"] as const } : {}),
          },
        }),
      ),
    onSuccess: (made) => {
      setMinted({ name: made.name ?? "", secret: made.secret ?? "" });
      setName("");
      setProduct("");
      setReadOnly(false);
      void queries.invalidateQueries({ queryKey: ["tokens"] });
    },
  });
  const withdraw = useMutation({
    mutationFn: async (token: string) =>
      unwrap(await api.DELETE("/v1/tokens/{name}", { params: { path: { name: token } } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["tokens"] }),
  });

  const rows = tokens.data?.items ?? [];
  return (
    <div className="card">
      <h3>Your tokens</h3>
      <p className="reading" style={{ marginBottom: 8 }}>
        For your own scripts. A token carries your current roles and never more.
      </p>

      {minted && (
        <div className="alert info" style={{ marginBottom: 10 }}>
          <strong>Copy it now.</strong>
          <span>
            <span className="id">{minted.secret}</span> — shown once. Only a hash is stored.
          </span>
          <button
            type="button"
            className="linkish"
            style={{ marginLeft: "auto" }}
            onClick={() => setMinted(null)}
          >
            Done
          </button>
        </div>
      )}
      {mint.error != null && <Failed error={mint.error} what="That token was not made." />}
      {withdraw.error != null && (
        <Failed error={withdraw.error} what="That could not be withdrawn." />
      )}

      {rows.length === 0 ? (
        <Empty title="You hold no tokens." detail="Make one for a script that reads as you." />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Reaches</th>
                <th>Expires</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                // A withdrawn token is kept and dimmed rather than removed, so
                // what used it stays answerable — and so that withdrawing is
                // visibly something rather than a button that appears to do
                // nothing.
                <tr key={row.name} className="row" style={{ opacity: row.withdrawn ? 0.55 : 1 }}>
                  <td className="id">{row.name}</td>
                  <td>
                    {row.product ? (
                      <>
                        <span className="id">{row.product}</span> <span className="hint">only</span>
                      </>
                    ) : (
                      <span className="hint">whatever you can reach</span>
                    )}
                  </td>
                  <td className="hint">{on(row.expires_at) ?? "—"}</td>
                  <td className="hint">{on(row.last_used_at) ?? "never"}</td>
                  <td>
                    {row.withdrawn ? (
                      <span style={{ color: "var(--faint)" }}>withdrawn</span>
                    ) : (
                      <button
                        type="button"
                        className="linkish"
                        style={{ color: "var(--muted)" }}
                        disabled={withdraw.isPending}
                        onClick={() => withdraw.mutate(row.name ?? "")}
                      >
                        Withdraw
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      <div className="filters" style={{ marginTop: 10 }}>
        <label className="field" style={{ margin: 0 }}>
          <span>Called</span>
          <input
            {...notACredential}
            type="text"
            value={name}
            placeholder="nightly report"
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label className="field" style={{ margin: 0 }}>
          <span>Lasts</span>
          <div style={{ display: "flex", gap: 6 }}>
            <input
              {...notACredential}
              type="number"
              min={1}
              style={{ width: 90 }}
              value={count}
              onChange={(event) => setCount(event.target.value)}
            />
            <select
              aria-label="Lifetime unit"
              {...notACredential}
              style={{ width: "auto" }}
              value={unit}
              onChange={(event) => setUnit(event.target.value as Unit)}
            >
              {UNITS.map((each) => (
                <option key={each.unit} value={each.unit}>
                  {each.unit}
                </option>
              ))}
            </select>
          </div>
        </label>
        <label className="field" style={{ margin: 0 }}>
          <span>Reaches</span>
          <select
            aria-label="What the token may reach"
            {...notACredential}
            style={{ width: "auto" }}
            value={product}
            onChange={(event) => setProduct(event.target.value)}
          >
            <option value="">Whatever you can reach</option>
            {(products.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name ?? ""}>
                {each.display_name || each.name} only
              </option>
            ))}
          </select>
        </label>
        <label className="field" style={{ margin: 0 }}>
          <span>Carries</span>
          <select
            aria-label="What the token may do"
            {...notACredential}
            style={{ width: "auto" }}
            value={readOnly ? "read" : "all"}
            onChange={(event) => setReadOnly(event.target.value === "read")}
          >
            <option value="all">Whatever you can do</option>
            <option value="read">Reading only</option>
          </select>
        </label>
        <button
          type="button"
          className="btn"
          style={{ alignSelf: "end" }}
          disabled={name.trim() === "" || !lasts || mint.isPending}
          onClick={() => mint.mutate()}
        >
          Make a token
        </button>
      </div>
      <p className="hint" style={{ marginTop: 8 }}>
        Expiry is required, up to a ceiling an administrator sets.
      </p>
    </div>
  );
}
