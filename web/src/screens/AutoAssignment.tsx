import { notACredential } from "../ui/noautofill";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Suggest } from "../ui/Suggest";
import { Wide } from "../ui/Wide";

// The standing rules that hand work nobody holds to a team.
//
// First match wins, and the order is the whole of the precedence, so the
// screen shows it as a numbered list rather than as a set.
//
// Called auto-assignment rather than routing, and kept beside the other things
// an administrator sets up. "Routing" says where something goes and this says
// who it becomes: the act it automates is assignment, and it is the only place
// in the tool where something is assigned without a person doing it.
export function AutoAssignment() {
  const [params, setParams] = useSearchParams();
  const product = params.get("product") ?? "";
  const queries = useQueryClient();
  const [name, setName] = useState("");
  const [team, setTeam] = useState("");
  const [upstream, setUpstream] = useState("");
  const [beneath, setBeneath] = useState("");

  const [said, setSaid] = useState<string | null>(null);

  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
  const teams = useQuery({
    queryKey: ["teams"],
    queryFn: async () => unwrap(await api.GET("/v1/teams", {})),
    retry: false,
  });
  // The components the product actually holds, to offer back as somebody types.
  // A rule keyed on a name nothing is called places nothing, silently — which
  // is the worst way for a rule to be wrong, because it looks like a rule.
  //
  // One read per field rather than one shared between them. Sharing looked
  // tidier and was wrong: the two fields are filled one after the other, so a
  // list keyed on "whichever has something in it" showed the first field's
  // matches under the second — names that would be refused, offered as though
  // they were the answer.
  //
  // A source-package rule matches on what a component was cut from where that
  // is recorded and on its own name where it is not, which is exactly what is
  // offered for it; a place-in-the-tree rule matches on the component's own
  // name.
  //
  // Read with no term as well as with one, so that opening the field shows
  // what is there. Unnarrowed the endpoint answers most-carrying first, which
  // is the right order for this: the packages a routing rule is worth writing
  // about are the ones carrying the work.
  // The star is the rule's syntax, not the lookup's: `q` is a substring
  // search, so sending `linux-image*` through it asks for a literal asterisk
  // and finds nothing. Stripped here, which also means the list stays useful
  // while somebody is typing a pattern rather than emptying at the star.
  const literal = (term: string) => term.replaceAll("*", "").trim();
  const search = (term: string) =>
    ({
      enabled: product !== "",
      queryKey: ["finding-components", product, literal(term)],
      queryFn: async () =>
        unwrap(
          await api.GET("/v1/products/{product}/findings/components", {
            params: {
              path: { product },
              query: { ...(literal(term) ? { q: literal(term) } : {}), limit: 50 },
            },
          }),
        ),
    }) as const;
  const bySource = useQuery(search(upstream));
  const byName = useQuery(search(beneath));
  // The names a rule can use here: the source package where one is recorded,
  // and the component's own name where it is not — which is exactly what a
  // source-package rule matches on.
  const sources = [
    ...new Set(
      (bySource.data?.items ?? []).map((each) => each.source_package || each.component || ""),
    ),
  ].filter(Boolean);
  const names = [...new Set((byName.data?.items ?? []).map((each) => each.component ?? ""))].filter(
    Boolean,
  );

  // The findings the keys as typed would catch, before anything is saved. A
  // rule that sweeps thousands of findings on a guess is only found out
  // afterwards, by which time they are on somebody's queue.
  const asked = upstream.trim() !== "" || beneath.trim() !== "";
  const catches = useQuery({
    enabled: product !== "" && asked,
    queryKey: ["rule-preview", product, upstream.trim(), beneath.trim()],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/routing-rules/preview", {
          params: {
            path: { product },
            query: {
              ...(upstream.trim() ? { upstream: upstream.trim() } : {}),
              ...(beneath.trim() ? { beneath: beneath.trim() } : {}),
            },
          },
        }),
      ),
  });
  // A rule matching nothing places nothing. The preview has always said so;
  // until this, saving it anyway was still allowed, and the resulting rule's
  // only symptom is work quietly never being placed.
  const catchesNothing = asked && catches.isSuccess && (catches.data?.total ?? 0) === 0;
  // With a source-package term matching no source package, what it does match
  // is often component names — and those name a source package of their own,
  // which is the thing the person meant. Read off the lookup that is already
  // running for the field's own list, so this costs no extra request.
  const cutFrom = [
    ...new Set(
      (bySource.data?.items ?? [])
        .filter((each) => (each.source_package ?? "") !== "")
        .map((each) => each.source_package as string),
    ),
  ].filter((from) => from.toLowerCase() !== literal(upstream).toLowerCase());

  const rules = useQuery({
    enabled: product !== "",
    queryKey: ["routing-rules", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/routing-rules", {
          params: { path: { product } },
        }),
      ),
  });

  const add = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/products/{product}/routing-rules", {
          params: { path: { product } },
          body: {
            name,
            team,
            ...(upstream.trim() ? { upstream: upstream.trim() } : {}),
            ...(beneath.trim() ? { beneath: beneath.trim() } : {}),
          },
        }),
      ),
    onSuccess: () => {
      setSaid(
        "Recorded. Applying to what is already open" +
          " — one rule can place thousands of findings.",
      );
      setName("");
      setUpstream("");
      setBeneath("");
      void queries.invalidateQueries({ queryKey: ["routing-rules"] });
    },
  });

  const retire = useMutation({
    mutationFn: async (id: number) =>
      unwrap(
        await api.DELETE("/v1/products/{product}/routing-rules/{id}", {
          params: { path: { product, id } },
        }),
      ),
    onSuccess: () => {
      setSaid("Retired. What it placed stays assigned.");
      void queries.invalidateQueries({ queryKey: ["routing-rules"] });
    },
  });

  const items = rules.data?.items ?? [];

  return (
    <>
      <div className="screen-head">
        <h2>Auto-assignment</h2>
        <p>Assigns unassigned work to a team. First match wins, and a rule never reassigns.</p>
        <label className="field" style={{ marginLeft: "auto" }}>
          <span>Product</span>
          <select
            value={product}
            onChange={(event) => {
              const next = new URLSearchParams(params);
              if (event.target.value) next.set("product", event.target.value);
              else next.delete("product");
              setParams(next);
            }}
          >
            <option value="">Pick a product</option>
            {(products.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name}>
                {each.display_name || each.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      {said && (
        <div className="alert info" style={{ marginBottom: 12 }}>
          <strong>Done</strong>
          <span>{said}</span>
        </div>
      )}

      {/* A refused retirement is said. Without it the button re-enables, the
          row stays, and the rule goes on placing work. */}
      {retire.isError && <Failed error={retire.error} what="That rule could not be retired." />}

      {product === "" ? (
        <Empty
          title="Pick a product."
          detail="Rules belong to a product, because the components they name do."
        />
      ) : (
        <>
          {rules.isError ? (
            <Failed error={rules.error} what="The rules could not be read." />
          ) : items.length === 0 ? (
            <Empty
              title="Nothing is routed automatically."
              detail="Without a rule, work nobody holds stays in the unassigned list until somebody picks it up."
            />
          ) : (
            <Wide>
              <table>
                <thead>
                  <tr>
                    <th className="num">Order</th>
                    <th>Rule</th>
                    <th>Matches</th>
                    <th>Goes to</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {items.map((rule) => (
                    <tr key={rule.id} className="row">
                      <td className="num">{rule.order}</td>
                      <td>{rule.name}</td>
                      <td className="hint">
                        {rule.upstream && (
                          <>
                            source package <span className="id">{rule.upstream}</span>
                          </>
                        )}
                        {rule.upstream && rule.beneath && " · "}
                        {rule.beneath && (
                          <>
                            at or under <span className="id">{rule.beneath}</span>
                          </>
                        )}
                      </td>
                      <td>{rule.team}</td>
                      <td>
                        {/* A rule with no identifier is a row the server did
                            not fully answer for, and asking to retire rule
                            zero is a 404 dressed as an act. */}
                        <button
                          type="button"
                          className="linkish"
                          disabled={retire.isPending || rule.id == null}
                          onClick={() => rule.id != null && retire.mutate(rule.id)}
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

          <div className="card" style={{ marginTop: 16 }}>
            <h3>Add a rule</h3>
            <p className="reading" style={{ marginBottom: 8 }}>
              Naming a <b>source package</b> catches every binary package built from it, wherever
              they sit — one line for a kernel rather than one per place. Naming a{" "}
              <b>place in the tree</b> catches that component and everything under it, in every
              build. At least one is needed; giving both narrows the rule to what satisfies{" "}
              <em>both</em>, rather than either. <span className="id">*</span> matches any run of
              characters. Matches are shown before you save.
            </p>
            <div className="filters">
              <label className="field">
                <span>Called</span>
                <input
                  {...notACredential}
                  type="text"
                  value={name}
                  placeholder="kernel to the platform team"
                  onChange={(event) => setName(event.target.value)}
                />
              </label>
              <label className="field">
                <span>Goes to</span>
                <select value={team} onChange={(event) => setTeam(event.target.value)}>
                  <option value="">Pick a team</option>
                  {(teams.data?.items ?? []).map((each) => (
                    <option key={each.name} value={each.name}>
                      {each.display_name || each.name}
                    </option>
                  ))}
                </select>
              </label>
              <Key
                id="rule-upstream"
                label="Source package"
                value={upstream}
                onChange={setUpstream}
                options={sources}
                loading={bySource.isFetching}
                placeholder="linux, or libcurl* for a set"
              />
              <Key
                id="rule-beneath"
                label="At or under"
                value={beneath}
                onChange={setBeneath}
                options={names}
                loading={byName.isFetching}
                placeholder="a component, or busybox* for a set"
              />
              <button
                type="button"
                className="btn"
                style={{ marginLeft: "auto" }}
                disabled={
                  !name.trim() ||
                  !team ||
                  (!upstream.trim() && !beneath.trim()) ||
                  add.isPending ||
                  // The preview already worked out that this matches nothing.
                  // Saving it anyway records a rule whose only symptom is
                  // work never being placed, which is the hardest kind of
                  // wrong to notice.
                  catchesNothing ||
                  // Still being worked out: saving now would be saving before
                  // the question "does this catch anything" has an answer.
                  catches.isFetching
                }
                onClick={() => add.mutate()}
              >
                {add.isPending ? "Recording…" : "Add"}
              </button>
            </div>
            {/* What it would catch, before it is saved. A star matches any run
                of characters, which is what makes one rule cover a kernel's
                four binary packages — and what makes seeing the reach before
                saving necessary rather than nice. */}
            {asked && (
              <div className="tier auto" style={{ marginTop: 10 }}>
                {catches.isError ? (
                  <Failed error={catches.error} what="The findings that would catch could not be read." />
                ) : catches.isFetching ? (
                  <p className="said">Working out what that catches…</p>
                ) : (catches.data?.total ?? 0) === 0 ? (
                  <p className="said">
                    <b>Nothing is called that.</b> A rule matching nothing places nothing, and says
                    so only by never doing anything.
                    {/* Why it matched nothing, where the answer is knowable.
                        A source-package rule matches what a component was cut
                        from, so typing the component name you see everywhere
                        — linux-image-6.12.41+deb13-… — matches no source
                        package at all, because that one is cut from `linux`.
                        Saying "nothing is called that" and stopping is true
                        and useless. */}
                    {cutFrom.length > 0 ? (
                      <>
                        {" "}
                        That is a component name rather than a source package.{" "}
                        {cutFrom.length === 1 ? "It is" : "Those are"} built from{" "}
                        {cutFrom.map((from, i) => (
                          <span key={from}>
                            {i > 0 && ", "}
                            <button
                              type="button"
                              className="linkish id"
                              onClick={() => setUpstream(from)}
                            >
                              {from}
                            </button>
                          </span>
                        ))}
                        {" — use that above, or name it under "}
                        <b>At or under</b> instead.
                      </>
                    ) : (
                      <>
                        {" "}
                        Use <span className="id">*</span> for any run of characters —{" "}
                        <span className="id">libcurl*</span> catches every one of them.
                      </>
                    )}
                  </p>
                ) : (
                  <p className="said">
                    Catches <b>{(catches.data?.total ?? 0).toLocaleString()}</b>{" "}
                    {(catches.data?.total ?? 0) === 1 ? "component" : "components"} —{" "}
                    {(catches.data?.components ?? []).slice(0, 8).map((name, i) => (
                      <span key={name}>
                        {i > 0 && ", "}
                        <span className="id">{name}</span>
                      </span>
                    ))}
                    {(catches.data?.total ?? 0) > (catches.data?.components ?? []).length && (
                      <> and more</>
                    )}
                    . <b>{(catches.data?.unheld ?? 0).toLocaleString()}</b> of{" "}
                    {(catches.data?.work ?? 0).toLocaleString()} pieces of work there are held by
                    nobody, and those are what it would place — where no rule above it claims them
                    first.
                  </p>
                )}
              </div>
            )}
            {add.isError && <Failed error={add.error} what="That rule was not recorded." />}
          </div>
        </>
      )}
    </>
  );
}

// One of a rule's two keys: a name, or a pattern for a set of them.
//
// One field, with the list of what exists on focus. It was a text box
// whose lookup waited for two characters, so nothing said a list existed or
// what was in it; then it was a mode selector, which was worse — the default
// mode rejected patterns, so typing `linux-image*` into it matched nothing for
// a second reason on top of the first.
//
// The list is searchable rather than a bare select: a real image carries
// several thousand components, and a select of several thousand is a worse
// control than the text box it replaced. Unnarrowed it offers the ones
// carrying the most work, which is what a routing rule gets written about.
function Key({
  id,
  label,
  value,
  onChange,
  options,
  loading,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
  loading: boolean;
  placeholder: string;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <Suggest
        id={id}
        label={label}
        value={value}
        placeholder={placeholder}
        loading={loading}
        options={options}
        // Opens on focus rather than after two characters, which is the whole
        // of what made it read as a plain text box.
        from={0}
        onChange={onChange}
      />
    </div>
  );
}
