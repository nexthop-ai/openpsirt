import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { Loading } from "../ui/Loading";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { AddButton, Declare, Field } from "../ui/Declare";
import { Suggest } from "../ui/Suggest";
import { useCatalog } from "../api/catalog";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { called, ROLES, type Role } from "../ui/roles";
import { Access } from "./Access";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import type { Who } from "../app/session";

// Access: who can see what, who can decide about it, and the credentials
// that carry either.
//
// Nobody appears here by having authenticated. Access is granted in advance,
// so this is what an administrator decided rather than who has turned up — and
// being recorded grants a role, it does not let anybody in. They still sign in
// through a configured provider.
export function People({ who: me }: { who: Who }) {
  const queries = useQueryClient();
  const [adding, setAdding] = useState(false);
  // Whose grid is open. One at a time: the grid is as wide as the table and
  // two of them stacked is a screen nobody can read a row out of.
  const [openFor, setOpenFor] = useState("");
  const [identity, setIdentity] = useState("");
  // The label shown instead of the identity, and the address to reach them
  // outside the application. Both are on the record and neither could be typed
  // here: the whole mail path could never deliver to anybody recorded through
  // this screen, and "an administrator has to record one" is what the person
  // was told when they went looking.
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");

  // The grants in force, narrowed. The approvers on one product are what an
  // access review asks, and reading it off a list of everybody is reading the
  // grid sideways — so the narrowing is a control rather than a scan.
  const [onProduct, setOnProduct] = useState("");
  const [withRole, setWithRole] = useState("");

  const people = useQuery({
    queryKey: ["people", onProduct, withRole],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/people", {
          params: {
            query: {
              ...(onProduct ? { product: onProduct } : {}),
              ...(withRole ? { role: withRole as Role } : {}),
            },
          },
        }),
      ),
  });
  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
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
    mutationFn: async (body: { identity: string; display_name?: string; email?: string }) =>
      unwrap(await api.POST("/v1/people", { body })),
    onSuccess: () => {
      setIdentity("");
      setDisplayName("");
      setEmail("");
      setAdding(false);
      void queries.invalidateQueries({ queryKey: ["people"] });
    },
  });

  // The label shown instead of the identity, for somebody already recorded. An
  // identity is what a provider hands over and a name is what people read, so
  // a deployment where every row is an address is one nobody scans.
  const rename = useMutation({
    mutationFn: async (who: { identity: string; name: string }) =>
      unwrap(
        await api.POST("/v1/people", {
          body: { identity: who.identity, display_name: who.name },
        }),
      ),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
  });

  // The address to reach somebody already recorded. Sent on its own so that an
  // address cleared here is cleared rather than left alone: the endpoint
  // distinguishes an empty address from an absent field, and the difference is
  // coming off mail without coming off the tool.
  const reach = useMutation({
    mutationFn: async (who: { identity: string; email: string }) =>
      unwrap(await api.POST("/v1/people", { body: { identity: who.identity, email: who.email } })),
    onSuccess: () => void queries.invalidateQueries({ queryKey: ["people"] }),
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

  // The other thing held over the deployment rather than against a product,
  // and the one an auditor is given: the records, and none of the products.
  const audit = useMutation({
    mutationFn: async (who: { identity: string; audits: boolean }) =>
      unwrap(
        await api.POST("/v1/people", { body: { identity: who.identity, audits: who.audits } }),
      ),
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
  // A role source that could not be read is not a role source that assigns
  // roles here. Reading it as "not group-bound" re-enabled every Manage button
  // in a deployment where a direct grant is overwritten by the next sign-in,
  // so an administrator's work is undone with nothing said.
  const unreadMode = mode.isPending || mode.isError;
  const cannotManage = derived || unreadMode;

  return (
    <>
      <div className="screen-head">
        <h2>Access</h2>
        <p>Who can read and decide what</p>
        {/* Offered only to somebody the server will take it from. A control
            that changes nothing is worse than a control that is not there,
            because pressing it looks like it worked. */}
        {me.admin && <AddButton label="Add user" onClick={() => setAdding(true)} />}
      </div>

      <div className="controls noprint">
        <label>
          On{" "}
          <select value={onProduct} onChange={(event) => setOnProduct(event.target.value)}>
            <option value="">any product</option>
            {(products.data?.items ?? []).map((product) => (
              <option key={product.name} value={product.name ?? ""}>
                {product.display_name || product.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Holding{" "}
          <select value={withRole} onChange={(event) => setWithRole(event.target.value)}>
            <option value="">any role</option>
            {ROLES.map((each) => (
              <option key={each.role} value={each.role}>
                {called(each.role)}
              </option>
            ))}
          </select>
        </label>
        {(onProduct !== "" || withRole !== "") && (
          <button
            type="button"
            className="btn quiet"
            onClick={() => {
              setOnProduct("");
              setWithRole("");
            }}
          >
            Clear
          </button>
        )}
      </div>

      {grant.error != null && <Failed error={grant.error} what="That role could not be granted." />}
      {withdraw.error != null && (
        <Failed error={withdraw.error} what="That role could not be withdrawn." />
      )}
      {endSessions.error != null && (
        <Failed error={endSessions.error} what="Their sessions could not be ended." />
      )}
      {reach.error != null && (
        <Failed error={reach.error} what="Where to reach them could not be recorded." />
      )}

      {rows.length === 0 ? (
        onProduct !== "" || withRole !== "" ? (
          <Empty
            title="Nobody holds that."
            detail="Nobody in force holds this role here. A grant a change of mode set aside is not one somebody holds."
          />
        ) : (
          <Empty title="Nobody is recorded yet." detail="Add somebody to give them a way in." />
        )
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Identity</th>
                <th>Email</th>
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
                      {person.audits && (
                        <>
                          {" "}
                          <span className="state" title="Reads this deployment's own records">
                            auditor
                          </span>
                        </>
                      )}
                      {/* Who still has access is a question about the list.
                          The date was on the person's own screen alone, so
                          answering it meant opening every row. */}
                      {person.deactivated_at && (
                        <>
                          {" "}
                          <span className="state closed" title={person.deactivated_at}>
                            left {on(person.deactivated_at)}
                          </span>
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
                      <Reachable
                        person={person}
                        busy={reach.isPending}
                        onSet={(address) =>
                          reach.mutate({ identity: person.identity ?? "", email: address })
                        }
                      />
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
                              className="vchip nothing"
                              title="A capability grants nothing on its own. Grant a read role as well."
                            >
                              sees nothing
                            </span>
                          )}
                          {(person.holds ?? []).map((held) => (
                            <span
                              key={`${held.everywhere ? "*" : held.product} ${held.role}`}
                              className="vchip"
                              style={{ opacity: held.effective ? 1 : 0.55 }}
                              title={
                                (held.source === "derived"
                                  ? "Derived from a group; withdrawn by changing the group. "
                                  : "Assigned by an administrator. ") +
                                (ROLES.find((each) => each.role === held.role)?.means ?? held.role)
                              }
                            >
                              {held.everywhere
                                ? "every product"
                                : (held.product_display_name ?? held.product)}{" "}
                              · {called(held.role)}
                              {held.source === "assigned" && (
                                <>
                                  {" "}
                                  <button
                                    type="button"
                                    className="linkish"
                                    style={{ fontSize: "inherit" }}
                                    title="Withdraw this role"
                                    onClick={() =>
                                      held.everywhere
                                        ? withdrawEverywhere.mutate({
                                            identity: person.identity ?? "",
                                            role: held.role ?? "",
                                          })
                                        : withdraw.mutate({
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
                        disabled={!me.admin || cannotManage}
                        title={
                          !me.admin
                            ? "Only an administrator grants and withdraws roles"
                            : derived
                              ? "Roles come from provider groups and would be overwritten"
                              : unreadMode
                                ? "Where roles come from could not be read"
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
                        disabled={!me.admin}
                        title={
                          me.admin
                            ? "Sign them out everywhere"
                            : "Only an administrator ends somebody else's sessions"
                        }
                        onClick={() => endSessions.mutate({ identity: person.identity ?? "" })}
                      >
                        End sessions
                      </button>
                    </td>
                  </tr>
                  {openFor === person.identity && (
                    <tr>
                      <td colSpan={6}>
                        <p className="hint" style={{ margin: "2px 0 8px" }}>
                          Name{" "}
                          <Named
                            person={person}
                            busy={rename.isPending}
                            onSet={(name) =>
                              rename.mutate({ identity: person.identity ?? "", name })
                            }
                          />
                        </p>
                        {rename.error != null && (
                          <Failed error={rename.error} what="That name could not be recorded." />
                        )}
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
                          Administers people, roles, credentials, settings and the catalog. Product
                          access is granted below.
                        </label>
                        {administer.error != null && (
                          <Failed error={administer.error} what="That could not be changed." />
                        )}
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
                            checked={Boolean(person.audits)}
                            disabled={audit.isPending}
                            onChange={(event) =>
                              audit.mutate({
                                identity: person.identity ?? "",
                                audits: event.target.checked,
                              })
                            }
                          />
                          Reads the settings, who holds what, and the record of administrative
                          changes. Changes none of them, and reaches no product.
                        </label>
                        {audit.error != null && (
                          <Failed error={audit.error} what="That could not be changed." />
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
        </Wide>
      )}

      {derived && (
        <div className="alert" style={{ marginTop: 12 }}>
          <strong>Roles come from groups in this deployment</strong>
          <span>Roles come from provider groups. Change the bindings below instead.</span>
        </div>
      )}

      {mode.isError && (
        <div className="alert" style={{ marginTop: 12 }}>
          <strong>Where roles come from could not be read</strong>
          <span>
            Granting one here would be overwritten at the next sign-in if this deployment takes
            roles from provider groups, so the grids stay closed until it answers.
          </span>
        </div>
      )}

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Role source</h3>
        <p className="hint" style={{ margin: 0 }}>
          <b>{mode.isError ? "could not be read" : (mode.data?.mode ?? "reading")}</b>
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
          <Wide style={{ marginTop: 10 }}>
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
          </Wide>
        )}
      </div>

      {/* Administrators only, and the panel as a whole. Both of its reads are
          administrator-only, so an auditor — whom the rail admits here — got a
          403 for each and the only empty branch below drew "Nothing is issued."
          against a deployment holding twelve keys. A silent wrong answer, to
          the one reader whose job is reviewing them. The same shape the
          webhooks panel is gated for. */}
      {me.admin && <Credentials me={me} />}

      <Declare
        title="Add user"
        open={adding}
        onClose={() => setAdding(false)}
        onSubmit={() =>
          record.mutate({
            identity: identity.trim(),
            ...(displayName.trim() ? { display_name: displayName.trim() } : {}),
            ...(email.trim() ? { email: email.trim() } : {}),
          })
        }
        error={record.error}
        busy={identity.trim() === "" || record.isPending}
        ok="Add user"
        hint="Accounts are never created automatically. They still sign in through a provider."
      >
        <Field
          label="Identity from the sign-in provider"
          value={identity}
          onChange={setIdentity}
          placeholder="ashwin@example.com"
          hint="Exactly as your provider gives it. Capitals matter."
        />
        <Field
          label="Name"
          value={displayName}
          onChange={setDisplayName}
          placeholder="Ashwin Rao"
          hint="Shown instead of the identity. Optional."
        />
        <Field
          label="Email"
          value={email}
          onChange={setEmail}
          placeholder="ashwin@example.com"
          hint="Where they are reached outside the application. Without one they get the notifications inside it and no mail. A provider that verifies an address fills this in where nobody has."
        />
      </Declare>
    </>
  );
}

// Credentials that are not people. A pipeline uploads with a key scoped to
// what it may send to; a person holds tokens for their own scripts, which
// never carry more than the person does.
function Credentials({ me }: { me: Who }) {
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
  // The three catalog reads as one, so this form shares the picker's cache
  // rather than keeping a fourth copy of the same query keys. Asked only while
  // the form is open: nothing below is drawn until then.
  const { products, streams, variants } = useCatalog(issuing, keyProduct);
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
      setKeyProduct("");
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
        Pipeline keys are scoped to what they may send. Personal tokens never carry more than the
        person does.
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
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Scope</th>
                <th>Made</th>
                <th>Expires</th>
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
                  <td className="hint">{on(key.created_at) || "—"}</td>
                  {/* A pipeline key has no expiry to show. Saying so is the
                      point: a credential that never runs out is one nobody
                      revokes, and those are found when somebody leaves and
                      nobody knows what breaks if it is turned off. */}
                  <td className="hint" title="A pipeline key does not expire">
                    never
                  </td>
                  <td className="hint">{key.last_used_at || "never"}</td>
                  <td>
                    {key.withdrawn ? (
                      <span style={{ color: "var(--faint)" }}>withdrawn</span>
                    ) : (
                      <button
                        type="button"
                        className="linkish"
                        disabled={!me.admin}
                        title={
                          me.admin ? undefined : "Only an administrator withdraws a credential"
                        }
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
                  <td className="hint">{on(token.created_at) || "—"}</td>
                  <td className="hint">{on(token.expires_at) || "—"}</td>
                  <td className="hint">{token.last_used_at || "never"}</td>
                  <td>
                    {token.withdrawn ? (
                      <span style={{ color: "var(--faint)" }}>withdrawn</span>
                    ) : (
                      <button
                        type="button"
                        className="linkish"
                        disabled={!me.admin}
                        title={
                          me.admin ? undefined : "Only an administrator withdraws a credential"
                        }
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
        </Wide>
      )}

      {issued && (
        <div className="alert info" style={{ marginTop: 10 }}>
          <strong>Copy it now.</strong>
          <span>
            <span className="id">{issued.secret}</span> — shown once. Only a hash is stored.
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
        Shown once. Only a hash is stored.
      </p>

      {/* Only a signed-in administrator may mint one — a credential cannot
          create another — so the refusal belongs here rather than after the
          form has been filled in. The belt rather than the braces while the
          panel itself is gated: it is what keeps this honest if the reads
          behind it are ever widened to the auditor whose job this is. */}
      <button
        type="button"
        className="btn"
        disabled={!me.admin}
        title={me.admin ? undefined : "Only an administrator creates an API key"}
        onClick={() => setIssuing(true)}
      >
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
        hint="For a build pipeline. Sends scans, reads back only what it sent."
      >
        <Field
          label="Called"
          value={keyName}
          onChange={setKeyName}
          placeholder="nightly-sonic"
          hint="Recorded as the sender. Must be unique."
        />
        <label className="field">
          <span>Product</span>
          {/* Choosing a product clears the two below it, the way the scope
              panel does: a branch belongs to one product, so a branch picked
              against the last one survives into a key naming a build the new
              product never declared. */}
          <select
            value={keyProduct}
            onChange={(event) => {
              setKeyProduct(event.target.value);
              setKeyStream("");
              setKeyVariant("");
            }}
          >
            <option value="">Choose a product</option>
            {(products.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name ?? ""}>
                {each.display_name || each.name}
              </option>
            ))}
          </select>
          <span className="hint">Required. A key covers one product.</span>
        </label>
        {/* Offered rather than typed from memory. Both are refused unless the
            product already holds them — a key names a branch that exists, not
            one a build will declare later — so the list is what the server
            will accept. It still does not restrict: the server is what
            refuses, and a name declared between the two requests is not one
            this control should decline. Opens on focus, because a product has
            a handful of these and all of them are worth seeing. */}
        <div className="field">
          <label htmlFor="key-stream">Branch or tag</label>
          <Suggest
            id="key-stream"
            label="Branch or tag"
            value={keyStream}
            onChange={setKeyStream}
            options={(streams.data?.items ?? []).map((each) => each.name ?? "")}
            loading={streams.isFetching}
            disabled={keyProduct === ""}
            placeholder={keyProduct === "" ? "pick a product first" : "master"}
            from={0}
          />
          <span className="hint">Optional. Empty means any branch or tag.</span>
        </div>
        <div className="field">
          <label htmlFor="key-variant">Variant</label>
          <Suggest
            id="key-variant"
            label="Variant"
            value={keyVariant}
            onChange={setKeyVariant}
            options={(variants.data?.items ?? []).map((each) => each.name ?? "")}
            loading={variants.isFetching}
            disabled={keyProduct === ""}
            placeholder={keyProduct === "" ? "pick a product first" : "broadcom"}
            from={0}
          />
          <span className="hint">Optional. Empty means any variant.</span>
        </div>
      </Declare>
    </div>
  );
}

// The label shown instead of somebody's identity, and the control that records
// it. Cleared by saving it empty, which is what leaves the identity showing.
function Named({
  person,
  busy,
  onSet,
}: {
  person: { display_name?: string };
  busy: boolean;
  onSet: (name: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(person.display_name ?? "");

  if (!editing) {
    return (
      <>
        {person.display_name ? (
          person.display_name
        ) : (
          <span style={{ color: "var(--faint)" }} title="The identity is shown instead">
            none
          </span>
        )}{" "}
        <button
          type="button"
          className="linkish noprint"
          onClick={() => {
            setDraft(person.display_name ?? "");
            setEditing(true);
          }}
        >
          {person.display_name ? "Change" : "Add"}
        </button>
      </>
    );
  }
  return (
    <span className="controls">
      <input
        type="text"
        value={draft}
        placeholder="Ashwin Rao"
        onChange={(event) => setDraft(event.target.value)}
      />
      <button
        type="button"
        className="btn"
        disabled={busy}
        onClick={() => {
          onSet(draft.trim());
          setEditing(false);
        }}
      >
        Save
      </button>
      <button type="button" className="btn quiet" onClick={() => setEditing(false)}>
        Cancel
      </button>
    </span>
  );
}

// The address somebody is reached at outside the application, and the control
// that records it.
//
// An address is optional and the two states either side of it are different
// acts: nobody having said, and somebody having cleared it. The source is
// shown because a provider's may be replaced by a later sign-in and one
// recorded here never is — which is the difference between an address that
// holds and one that drifts back.
function Reachable({
  person,
  busy,
  onSet,
}: {
  person: { email?: string; email_source?: string };
  busy: boolean;
  onSet: (email: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(person.email ?? "");

  if (!editing) {
    return (
      <>
        {person.email ? (
          <span className="id">{person.email}</span>
        ) : (
          <span style={{ color: "var(--faint)" }} title="They get no mail from this deployment">
            none
          </span>
        )}
        {person.email_source === "provider" && (
          <>
            {" "}
            <span className="hint" title="A later sign-in may replace it">
              from the provider
            </span>
          </>
        )}{" "}
        <button
          type="button"
          className="linkish noprint"
          onClick={() => {
            setDraft(person.email ?? "");
            setEditing(true);
          }}
        >
          {person.email ? "Change" : "Add"}
        </button>
      </>
    );
  }
  return (
    <span className="controls">
      <input
        type="email"
        value={draft}
        placeholder="ashwin@example.com"
        onChange={(event) => setDraft(event.target.value)}
      />
      <button
        type="button"
        className="btn"
        disabled={busy}
        onClick={() => {
          onSet(draft.trim());
          setEditing(false);
        }}
      >
        Save
      </button>
      <button type="button" className="btn quiet" onClick={() => setEditing(false)}>
        Cancel
      </button>
    </span>
  );
}
