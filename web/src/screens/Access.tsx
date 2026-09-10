import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { ROLES, reaches } from "../ui/roles";

// Who holds what, as a grid of products against capabilities.
//
// **It was a list of chips and a three-control form.** Granting meant picking a
// product, picking a role, pressing Grant, and reading the result back out of a
// run of chips shaped "product · role" — so answering "who can approve on
// sonic" meant reading every chip on every row, and granting the same thing on
// eight products meant twenty-four gestures. A grid answers both by being
// looked at: a column is a capability across the estate, a row is a product,
// and a cell is one gesture.
//
// **The row across the top is the same grant applied to every product.** It is
// checked where they hold it everywhere and partial where they hold it
// somewhere, and pressing it grants or withdraws the difference — which is the
// thing people were doing by hand, one product at a time, and stopping halfway
// through.
//
// **A role derived from a group is shown and not editable here.** It comes from
// the identity provider's group and is withdrawn by changing the group; a
// checkbox that silently did nothing would be worse than one that explains.

type Held = { product?: string; role?: string; effective?: boolean; source?: string };

export function Access({
  holds,
  busy,
  onGrant,
  onWithdraw,
}: {
  holds: Held[];
  busy: boolean;
  onGrant: (product: string, role: string) => void;
  onWithdraw: (product: string, role: string) => void;
}) {
  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });

  // A held role names its product as it is shown; a grant names it as the API
  // takes it. Both are mapped to the second, or every grant looks like the
  // first one on that product.
  const canon = new Map<string, string>();
  for (const each of products.data?.items ?? []) {
    canon.set((each.name ?? "").toLowerCase(), each.name ?? "");
    if (each.display_name) canon.set(each.display_name.toLowerCase(), each.name ?? "");
  }
  const names = (products.data?.items ?? []).map((each) => each.name ?? "").filter(Boolean);

  function held(product: string, role: string): Held | undefined {
    return holds.find(
      (each) =>
        canon.get((each.product ?? "").toLowerCase()) === product &&
        each.role === role &&
        each.effective !== false,
    );
  }

  // What this person can actually reach on a product, so a capability granted
  // where nothing is readable can be said to reach nothing at the moment it is
  // granted rather than when they sign in to an empty tool.
  function readsAnything(product: string): boolean {
    return holds.some(
      (each) =>
        canon.get((each.product ?? "").toLowerCase()) === product &&
        each.effective !== false &&
        reaches(each.role),
    );
  }

  return (
    <div className="tablewrap" style={{ margin: "4px 0 10px" }}>
      {products.isPending ? (
        <p className="hint">Reading the products…</p>
      ) : names.length === 0 ? (
        <p className="hint">No products are declared yet, so there is nothing to grant on.</p>
      ) : (
        <table className="permgrid">
          <thead>
            <tr>
              <th>Product</th>
              {ROLES.map((each) => (
                <th key={each.role} title={each.means}>
                  {each.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr className="every">
              <th scope="row">All products</th>
              {ROLES.map((each) => {
                const on = names.filter((name) => held(name, each.role));
                const all = on.length === names.length;
                const some = on.length > 0 && !all;
                return (
                  <td key={each.role}>
                    <input
                      type="checkbox"
                      aria-label={`${each.label} on every product`}
                      checked={all}
                      ref={(box) => {
                        if (box) box.indeterminate = some;
                      }}
                      disabled={busy}
                      onChange={() => {
                        for (const name of names) {
                          const has = Boolean(held(name, each.role));
                          if (all && has) onWithdraw(name, each.role);
                          else if (!all && !has) onGrant(name, each.role);
                        }
                      }}
                    />
                  </td>
                );
              })}
            </tr>
            {names.map((name) => (
              <tr key={name}>
                <th scope="row">{name}</th>
                {ROLES.map((each) => {
                  const has = held(name, each.role);
                  const derived = has?.source === "derived";
                  const empty = !has && !each.grants && !readsAnything(name);
                  return (
                    <td key={each.role}>
                      <input
                        type="checkbox"
                        aria-label={`${each.label} on ${name}`}
                        checked={Boolean(has)}
                        disabled={busy || derived}
                        title={
                          derived
                            ? "Comes from a group in the identity provider. Withdraw it by changing the group"
                            : empty
                              ? "On its own this reaches nothing — it is bounded by what they may read. Grant a read or triage role here as well"
                              : each.means
                        }
                        onChange={() =>
                          has ? onWithdraw(name, each.role) : onGrant(name, each.role)
                        }
                      />
                      {empty && (
                        <span className="hint" aria-hidden>
                          {" "}
                          !
                        </span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="hint" style={{ marginTop: 6 }}>
        A capability — approver, assigner — is bounded by what its holder may read, so granted on a
        product where they hold no read or triage role it reaches nothing. Those cells are marked.
      </p>
    </div>
  );
}
