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
// **The row across the top is a grant, not a shortcut.** It was a button that
// issued one ordinary grant per product that existed at that moment, so a
// product declared afterwards was silently not covered and the box quietly
// fell back to partial. It is now one standing grant that covers the estate,
// including what is declared later — which is why it is offered before any
// product is declared at all.
//
// **A role derived from a group is shown and not editable here.** It comes from
// the identity provider's group and is withdrawn by changing the group; a
// checkbox that silently did nothing would be worse than one that explains. A
// product row covered by the estate grant is drawn the same way, for the same
// reason: it is withdrawn where it was granted.

type Held = {
  product?: string;
  role?: string;
  effective?: boolean;
  source?: string;
  everywhere?: boolean;
};

export function Access({
  holds,
  busy,
  onGrant,
  onWithdraw,
  onGrantEverywhere,
  onWithdrawEverywhere,
}: {
  holds: Held[];
  busy: boolean;
  onGrant: (product: string, role: string) => void;
  onWithdraw: (product: string, role: string) => void;
  onGrantEverywhere: (role: string) => void;
  onWithdrawEverywhere: (role: string) => void;
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

  // Held across every product. A standing fact rather than a summary of the
  // per-product grants, so it says what it says even where the two agree.
  function everywhere(role: string): Held | undefined {
    return holds.find((each) => each.everywhere && each.role === role && each.effective !== false);
  }

  function held(product: string, role: string): Held | undefined {
    return holds.find(
      (each) =>
        !each.everywhere &&
        canon.get((each.product ?? "").toLowerCase()) === product &&
        each.role === role &&
        each.effective !== false,
    );
  }

  // What this person can actually reach on a product, so a capability granted
  // where nothing is readable can be said to reach nothing at the moment it is
  // granted rather than when they sign in to an empty tool. The estate grant
  // counts: a read held everywhere is a read held here.
  function readsAnything(product: string): boolean {
    return holds.some(
      (each) =>
        (each.everywhere || canon.get((each.product ?? "").toLowerCase()) === product) &&
        each.effective !== false &&
        reaches(each.role),
    );
  }

  return (
    <div className="tablewrap" style={{ margin: "4px 0 10px" }}>
      {products.isPending ? (
        <p className="hint">Reading the products…</p>
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
                const standing = everywhere(each.role);
                // Checked means one standing grant. Indeterminate means they
                // hold it on some products and not across the estate — a
                // different fact, and conflating the two is what made "on all
                // eight" indistinguishable from "on six of eight".
                const on = names.filter((name) => held(name, each.role));
                const some = !standing && on.length > 0;
                return (
                  <td key={each.role}>
                    <input
                      type="checkbox"
                      aria-label={`${each.label} on every product`}
                      checked={Boolean(standing)}
                      ref={(box) => {
                        if (box) box.indeterminate = some;
                      }}
                      disabled={busy || standing?.source === "derived"}
                      title={
                        standing
                          ? "Held across every product, including products declared later"
                          : some
                            ? "Held on some products, but not across the estate"
                            : "Hold this across every product, including products declared later"
                      }
                      onChange={() =>
                        standing ? onWithdrawEverywhere(each.role) : onGrantEverywhere(each.role)
                      }
                    />
                  </td>
                );
              })}
            </tr>
            {names.length === 0 && (
              <tr>
                <td colSpan={ROLES.length + 1} className="hint">
                  No products are declared yet. A role held across every product covers the ones
                  declared later, so it can be granted now.
                </td>
              </tr>
            )}
            {names.map((name) => (
              <tr key={name}>
                <th scope="row">{name}</th>
                {ROLES.map((each) => {
                  const standing = everywhere(each.role);
                  const has = held(name, each.role);
                  const derived = has?.source === "derived";
                  const covered = Boolean(standing);
                  const empty = !has && !covered && !each.grants && !readsAnything(name);
                  return (
                    <td key={each.role}>
                      <input
                        type="checkbox"
                        aria-label={`${each.label} on ${name}`}
                        checked={covered || Boolean(has)}
                        disabled={busy || derived || covered}
                        title={
                          covered
                            ? has
                              ? "Granted here and also across every product. Withdraw the estate grant first, then this one"
                              : "Comes from the grant across every product. Withdraw it there"
                            : derived
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
        product where they hold no read or triage role it reaches nothing. Those cells are marked. A
        role held across every product covers products declared later, and is withdrawn as one.
      </p>
    </div>
  );
}
