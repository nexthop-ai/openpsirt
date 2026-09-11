import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { called, ROLES, type Role } from "../ui/roles";
import { Access } from "./Access";

// Users and roles: who can see what, and who can decide about it.
//
// Nobody appears here by having authenticated. Access is granted in advance,
// so this is what an administrator decided rather than who has turned up — and
// being recorded grants a role, it does not let anybody in. They still sign in
// through a configured provider.
export function People() {
  const queries = useQueryClient();
  const [adding, setAdding] = useState(false);
  // Whose grid is open. One at a time: the grid is as wide as the table and
  // two of them stacked is a screen nobody can read a row out of.
  const [openFor, setOpenFor] = useState("");
  const [identity, setIdentity] = useState("");

  const people = useQuery({
    queryKey: ["people"],
    queryFn: async () => unwrap(await api.GET("/v1/people", {})),
  });
  const mode = useQuery({
    queryKey: ["role-mode"],
    queryFn: async () => unwrap(await api.GET("/v1/roles/mode", {})),
  });
  const bindings = useQuery({
    queryKey: ["role-bindings"],
    queryFn: async () => unwrap(await api.GET("/v1/roles/bindings", {})),
  });

  const record = useMutation({
    mutationFn: async (body: { identity: string }) =>
      unwrap(await api.POST("/v1/people", { body })),
    onSuccess: () => {
      setIdentity("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["people"] });
    },
  });

  const grant = useMutation({
    mutationFn: async (who: { identity: string; product: string; role: string }) =>
      unwrap(
        await api.POST("/v1/people", {
          body: {
            identity: who.identity,
            holds: [{ product: who.product, role: who.role as Role }],
          },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
  });

  const withdraw = useMutation({
    mutationFn: async (who: { identity: string; product: string; role: string }) =>
      unwrap(
        await api.DELETE("/v1/people/{identity}/roles/{product}/{role}", { params: { path: who } }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
  });

  // A role held across every product, including ones declared later. One
  // standing grant rather than a copy per product, so what it covers is
  // worked out when somebody asks rather than frozen when it was made.
  const grantEverywhere = useMutation({
    mutationFn: async (who: { identity: string; role: string }) =>
      unwrap(
        await api.POST("/v1/people", {
          body: {
            identity: who.identity,
            holds: [{ role: who.role as Role, everywhere: true }],
          },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
  });

  const withdrawEverywhere = useMutation({
    mutationFn: async (who: { identity: string; role: string }) =>
      unwrap(await api.DELETE("/v1/people/{identity}/roles/{role}", { params: { path: who } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
  });

  // Administration is global rather than granted against a product, so it sits
  // beside the grid rather than in it (REQ-42). It had no control at all: the
  // API took it, the screens only ever displayed it, and the only ways to
  // grant it were the configuration file, a group binding, or calling the API
  // by hand.
  const administer = useMutation({
    mutationFn: async (who: { identity: string; admin: boolean }) =>
      unwrap(await api.POST("/v1/people", { body: { identity: who.identity, admin: who.admin } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
  });

  const endSessions = useMutation({
    mutationFn: async (who: { identity: string }) =>
      unwrap(await api.DELETE("/v1/people/{identity}/sessions", { params: { path: who } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
  });

  if (people.isPending) return <Loading />;
  if (people.isError) {
    return <Failed error={people.error} what="The users could not be read." />;
  }

  const rows = people.data?.items ?? [];
  const derived = mode.data?.mode === "group-bound";

  return (
    <>
      <div className="screen-head">
        <h2>Users and roles</h2>
        <p>Who can see what, and who can decide about it</p>
        <AddButton label="Add user" onClick={() => setAdding(true)} />
      </div>

      {grant.error != null && <Failed error={grant.error} what="That role could not be granted." />}
      {withdraw.error != null && (
        <Failed error={withdraw.error} what="That role could not be withdrawn." />
      )}
      {endSessions.error != null && (
        <Failed error={endSessions.error} what="Their sessions could not be ended." />
      )}

      {rows.length === 0 ? (
        <Empty title="Nobody is recorded yet." detail="Add somebody to give them a way in." />
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Identity</th>
                <th>Roles</th>
                <th style={{ width: 150 }}>Access</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((person) => (
                <Fragment key={person.identity}>
                  <tr className="row">
                    <td>
                      {/* The name opens the person, the way a component's name
                          opens the component. What this row shows is what they
                          hold; what they were told and what they did to the
                          record is a screen. */}
                      <Link
                        className="id"
                        to={`/people/${encodeURIComponent(person.identity ?? "")}`}
                      >
                        {person.display_name || person.identity}
                      </Link>
                      {person.admin && (
                        <>
                          {" "}
                          <span className="state agreed">administrator</span>
                        </>
                      )}
                    </td>
                    <td>
                      {(person.signs_in_by ?? []).length === 0 ? (
                        <span style={{ color: "var(--faint)" }}>—</span>
                      ) : (
                        (person.signs_in_by ?? []).map((door) => (
                          <div key={door.username}>
                            <span className="id">{door.username}</span>
                          </div>
                        ))
                      )}
                    </td>
                    <td>
                      {(person.holds ?? []).length === 0 ? (
                        <span style={{ color: "var(--faint)" }}>none</span>
                      ) : (
                        <span className="variants">
                          {/* Every role they hold is a capability, so they reach
                            no product at all. It was accepted in silence,
                            which reads as working until they sign in to an
                            empty tool. */}
                          {person.sees_nothing && (
                            <span
                              className="vchip warn"
                              title="A capability is bounded by what its holder may read, so on its own it grants nothing. Grant a read role as well."
                            >
                              sees nothing
                            </span>
                          )}
                          {(person.holds ?? []).map((held) => (
                            <span
                              key={`${held.product} ${held.role}`}
                              className="vchip"
                              style={{ opacity: held.effective ? 1 : 0.55 }}
                              title={
                                (held.source === "derived"
                                  ? "Derived from a group; withdrawn by changing the group. "
                                  : "Assigned by an administrator. ") +
                                (ROLES.find((each) => each.role === held.role)?.means ?? held.role)
                              }
                            >
                              {held.product} · {called(held.role)}
                              {held.source === "assigned" && (
                                <>
                                  {" "}
                                  <button
                                    type="button"
                                    className="linkish"
                                    style={{ fontSize: "inherit" }}
                                    title="Withdraw this role"
                                    onClick={() =>
                                      withdraw.mutate({
                                        identity: person.identity ?? "",
                                        product: held.product ?? "",
                                        role: held.role ?? "",
                                      })
                                    }
                                  >
                                    ×
                                  </button>
                                </>
                              )}
                            </span>
                          ))}
                        </span>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="linkish"
                        aria-expanded={openFor === person.identity}
                        disabled={derived}
                        title={
                          derived
                            ? "Roles come from groups in this deployment, so granting one here would be overwritten"
                            : "Every product against every capability, as a grid"
                        }
                        onClick={() =>
                          setOpenFor(openFor === person.identity ? "" : (person.identity ?? ""))
                        }
                      >
                        {openFor === person.identity ? "Hide" : "Manage"}
                      </button>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="linkish"
                        style={{ color: "var(--muted)" }}
                        title="Sign them out everywhere"
                        onClick={() => endSessions.mutate({ identity: person.identity ?? "" })}
                      >
                        End sessions
                      </button>
                    </td>
                  </tr>
                  {openFor === person.identity && (
                    <tr>
                      <td colSpan={5}>
                        <label
                          className="hint"
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 6,
                            margin: "2px 0 8px",
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={Boolean(person.admin)}
                            disabled={administer.isPending}
                            onChange={(event) =>
                              administer.mutate({
                                identity: person.identity ?? "",
                                admin: event.target.checked,
                              })
                            }
                          />
                          Administers this deployment — people, roles, credentials, settings and the
                          catalog. Reading and triaging a product are granted below like anybody
                          else&apos;s.
                        </label>
                        {administer.error != null && (
                          <Failed error={administer.error} what="That could not be changed." />
                        )}
                        <Access
                          holds={person.holds ?? []}
                          busy={
                            grant.isPending ||
                            withdraw.isPending ||
                            grantEverywhere.isPending ||
                            withdrawEverywhere.isPending
                          }
                          onGrant={(product, role) =>
                            grant.mutate({ identity: person.identity ?? "", product, role })
                          }
                          onWithdraw={(product, role) =>
                            withdraw.mutate({ identity: person.identity ?? "", product, role })
                          }
                          onGrantEverywhere={(role) =>
                            grantEverywhere.mutate({ identity: person.identity ?? "", role })
                          }
                          onWithdrawEverywhere={(role) =>
                            withdrawEverywhere.mutate({ identity: person.identity ?? "", role })
                          }
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {derived && (
        <div className="alert" style={{ marginTop: 12 }}>
          <strong>Roles come from groups in this deployment</strong>
          <span>
            What somebody holds is derived from the groups their provider reports, so granting one
            here would be overwritten. Change the bindings below instead.
          </span>
        </div>
      )}

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Role source</h3>
        <p className="hint" style={{ margin: 0 }}>
          <b>{mode.data?.mode ?? "reading"}</b>
          {(bindings.data?.items ?? []).length > 0 && (
            <>
              {" "}
              · {(bindings.data?.items ?? []).length} group{" "}
              {(bindings.data?.items ?? []).length === 1 ? "binding" : "bindings"}
            </>
          )}
          . Either an administrator assigns roles directly, or they are derived from the groups a
          sign-in provider reports. Never both.
        </p>
        {(bindings.data?.items ?? []).length > 0 && (
          <div className="tablewrap" style={{ marginTop: 10 }}>
            <table>
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Product</th>
                  <th>Role</th>
                </tr>
              </thead>
              <tbody>
                {(bindings.data?.items ?? []).map((binding) => (
                  <tr key={`${binding.group} ${binding.product} ${binding.role}`}>
                    <td>
                      <span className="id">{binding.group}</span>
                    </td>
                    <td>
                      <span className="id">{binding.product}</span>
                    </td>
                    <td>{binding.role}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Credentials />

      <Declare
        title="Add user"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() => record.mutate({ identity: identity.trim() })}
        error={record.error}
        busy={identity.trim() === "" || record.isPending}
        ok="Add user"
        hint="No account is ever created automatically. Being named here grants a role — they still sign in through a configured provider like anybody else."
      >
        <Field
          label="Identity from the sign-in provider"
          value={identity}
          onChange={setIdentity}
          placeholder="ashwin@example.com"
          hint="Exactly as your provider gives it. Capitals matter here. A trusted proxy asserting the same name is the same person."
        />
      </Declare>
    </>
  );
}

// Credentials that are not people. A pipeline uploads with a key scoped to
// what it may send to; a person holds tokens for their own scripts, which
// never carry more than the person does.
function Credentials() {
  const queries = useQueryClient();
  const [issuing, setIssuing] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [keyProduct, setKeyProduct] = useState("");
  const [keyStream, setKeyStream] = useState("");
  const [keyVariant, setKeyVariant] = useState("");
  const [issued, setIssued] = useState<{ name: string; secret: string } | null>(null);

  const keys = useQuery({
    queryKey: ["keys"],
    queryFn: async () => unwrap(await api.GET("/v1/keys", {})),
  });
  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
  const tokens = useQuery({
    queryKey: ["tokens"],
    queryFn: async () => unwrap(await api.GET("/v1/people/tokens", {})),
  });

  // A pipeline's credential. Its own noun and its own lifetime: it belongs to
  // no person, so nothing about it is withdrawn when somebody leaves.
  //
  // The product is required and the release and variant are independent, so
  // either, both or neither may pin it. A key covering a whole product cannot
  // imply which release an upload is for, which is why an upload always states
  // its full target and this only authorizes it.
  const issueKey = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/keys", {
          body: {
            name: keyName.trim(),
            product: keyProduct,
            ...(keyStream.trim() ? { stream: keyStream.trim() } : {}),
            ...(keyVariant.trim() ? { variant: keyVariant.trim() } : {}),
          },
        }),
      ),
    onSuccess: (made) => {
      setIssued({ name: made.item.name ?? "", secret: made.item.secret ?? "" });
      setKeyName("");
      setKeyStream("");
      setKeyVariant("");
      setIssuing(false);
      void queries.invalidateQueries({ queryKey: ["keys"] });
    },
  });

  const withdrawKey = useMutation({
    mutationFn: async (name: string) =>
      unwrap(await api.DELETE("/v1/keys/{name}", { params: { path: { name } } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["keys"] }),
  });
  const withdrawToken = useMutation({
    mutationFn: async (held: { identity: string; name: string }) =>
      unwrap(await api.DELETE("/v1/people/{identity}/tokens/{name}", { params: { path: held } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["tokens"] }),
  });

  const keyRows = keys.data?.items ?? [];
  const tokenRows = tokens.data?.items ?? [];

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>API keys and tokens</h3>
      <p className="reading" style={{ margin: "0 0 12px" }}>
        A build pipeline uploads with a key scoped to what it may send to. A person can hold tokens
        for their own scripts, which never carry more than the person does.
      </p>

      {withdrawKey.error != null && (
        <Failed error={withdrawKey.error} what="That key could not be withdrawn." />
      )}
      {withdrawToken.error != null && (
        <Failed error={withdrawToken.error} what="That token could not be withdrawn." />
      )}

      {keyRows.length === 0 && tokenRows.length === 0 ? (
        <p className="hint" style={{ margin: 0 }}>
          Nothing is issued.
        </p>
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Scope</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keyRows.map((key) => (
                <tr
                  key={`key ${key.name}`}
                  className="row"
                  style={{ opacity: key.withdrawn ? 0.55 : 1 }}
                >
                  <td>
                    <span className="id">{key.name}</span>
                  </td>
                  <td>Pipeline key</td>
                  <td>
                    <span className="id">{key.product}</span>
                    <span className="hint">
                      {" "}
                      · {key.stream ? key.stream : "any branch"},{" "}
                      {key.variant ? key.variant : "any variant"}
                    </span>
                  </td>
                  <td className="hint">{key.last_used_at || "never"}</td>
                  <td>
                    {key.withdrawn ? (
                      <span style={{ color: "var(--faint)" }}>withdrawn</span>
                    ) : (
                      <button
                        type="button"
                        className="linkish"
                        onClick={() => withdrawKey.mutate(key.name ?? "")}
                      >
                        Withdraw
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {tokenRows.map((token) => (
                <tr
                  key={`token ${token.owner} ${token.name}`}
                  className="row"
                  style={{ opacity: token.withdrawn ? 0.55 : 1 }}
                >
                  <td>
                    <span className="id">{token.name}</span>
                  </td>
                  <td>Personal token</td>
                  <td>
                    Whatever <b>{token.owner}</b> can reach
                    {token.product && (
                      <span className="hint">
                        {" "}
                        · <span className="id">{token.product}</span> only
                      </span>
                    )}
                  </td>
                  <td className="hint">{token.last_used_at || "never"}</td>
                  <td>
                    {token.withdrawn ? (
                      <span style={{ color: "var(--faint)" }}>withdrawn</span>
                    ) : (
                      <button
                        type="button"
                        className="linkish"
                        onClick={() =>
                          withdrawToken.mutate({
                            identity: token.owner ?? "",
                            name: token.name ?? "",
                          })
                        }
                      >
                        Withdraw
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {issued && (
        <div className="alert info" style={{ marginTop: 10 }}>
          <strong>Copy it now.</strong>
          <span>
            <span className="id">{issued.secret}</span> — this is the only time it is shown. What is
            stored is a digest, so a secret nobody copied is a key nobody can use.
          </span>
          <button
            type="button"
            className="linkish"
            style={{ marginLeft: "auto" }}
            onClick={() => setIssued(null)}
          >
            Done
          </button>
        </div>
      )}

      <p className="reading" style={{ marginTop: 10 }}>
        A secret is shown once when it is made and never again. What is stored is a hash.
      </p>

      <button type="button" className="btn" onClick={() => setIssuing(true)}>
        Create an API key
      </button>

      <Declare
        title="Create an API key"
        open={issuing}
        onClose={() => setIssuing(false)}
        onSubmit={() => issueKey.mutate()}
        error={issueKey.error}
        busy={keyName.trim() === "" || keyProduct === "" || issueKey.isPending}
        ok="Create key"
        hint="For a build pipeline to upload with. It belongs to no person, may only send scans, and can read back only what it sent."
      >
        <Field
          label="Called"
          value={keyName}
          onChange={setKeyName}
          placeholder="nightly-sonic"
          hint="What an upload records as its sender, and what you withdraw by. It has to be unique."
        />
        <label className="field">
          <span>Product</span>
          <select value={keyProduct} onChange={(event) => setKeyProduct(event.target.value)}>
            <option value="">Choose a product</option>
            {(products.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name ?? ""}>
                {each.display_name || each.name}
              </option>
            ))}
          </select>
          <span className="hint">Always required. A key is scoped to one product.</span>
        </label>
        <Field
          label="Branch or tag"
          value={keyStream}
          onChange={setKeyStream}
          placeholder="master"
          hint="Optional. Leave it empty and the key may send for any branch or tag."
        />
        <Field
          label="Variant"
          value={keyVariant}
          onChange={setKeyVariant}
          placeholder="broadcom"
          hint="Optional. Leave it empty and the key may send for any variant."
        />
      </Declare>
    </div>
  );
}
