import { Link } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Empty } from "../ui/Empty";
import { BANDS } from "../ui/severities";

// One release, gathered.
//
// **A release is a hand-off, not a fifth summary page.** What belongs here is
// everything handed over when a tag is cut — what changed since the last one,
// what was said publicly, what a customer's own scanner reads, and the record
// somebody audits — which until now sat in four places reached four ways.
// Navigating to a tag landed on a build's findings list, as though a tag were a
// branch.
//
// **No overdue section.** A tag never changes, so nothing on it has a deadline
// to miss.
export function Release({ product, stream }: { product: string; stream: string }) {
  const streams = useQuery({
    queryKey: ["streams", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/streams", { params: { path: { product } } })),
  });
  const built = useQuery({
    queryKey: ["release-variants", product, stream],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants", {
          params: { path: { product, stream } },
        }),
      ),
  });

  const rows = streams.data?.items ?? [];
  const here = rows.find((row) => row.name === stream);
  const variants = built.data?.items ?? [];

  // What each variant of this release holds, by severity. Asked per variant
  // rather than added as an endpoint: a release is built two or three ways,
  // and an answer worked out when it is asked for beats a total kept somewhere
  // that can go stale.
  const counts = useQueries({
    queries: variants.map((variant) => ({
      queryKey: ["release-counts", product, stream, variant.name],
      queryFn: async () =>
        unwrap(
          await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/readiness", {
            params: { path: { product, stream, variant: variant.name ?? "" } },
          }),
        ),
    })),
  });

  // The release before this one: the newest tag that went out earlier. Cut
  // from the same branch where both say, because a comparison across two
  // branches is two pieces of software rather than one moving.
  const previous = beforeThis(rows, here);

  if (streams.isPending || built.isPending) return <Loading />;
  if (streams.isError) {
    return <Failed error={streams.error} what="This release could not be read." />;
  }
  if (!here) {
    return (
      <Empty
        title="No such release"
        detail="Nothing by that name is declared under this product."
      />
    );
  }

  const bands = totalled(counts.map((one) => one.data?.now));
  const settled = counts.every((one) => !one.isPending);

  return (
    <>
      <div className="screen-head">
        <h2>{stream}</h2>
        <p>
          {product}
          {here.released_on ? (
            <> · released {here.released_on}</>
          ) : (
            // "released" followed by nothing reads as a claim about the
            // release rather than as a date nobody has recorded.
            <> · no release date recorded</>
          )}
          {here.parent && (
            <>
              {" "}
              · cut from{" "}
              <Link to={`/products/${encodeURIComponent(product)}/streams`}>{here.parent}</Link>
            </>
          )}
          {here.end_of_life && <> · support ends {here.end_of_life}</>}
        </p>
      </div>

      <section className="panel">
        <h3>What this is</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          The variants this release was actually built as — a subset of what the product declares,
          because one introduced later has never been filed against it.
        </p>
        {variants.length === 0 ? (
          <Empty
            title="Nothing has been filed against it"
            detail="No scan has ever named a build of this release, so there is nothing here to say what it shipped."
          />
        ) : (
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>Variant</th>
                  <th>Open</th>
                  <th>Reaches customers</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {variants.map((variant, at_) => {
                  const at =
                    `/products/${encodeURIComponent(product)}` +
                    `/streams/${encodeURIComponent(stream)}` +
                    `/variants/${encodeURIComponent(variant.name ?? "")}`;
                  // Off the same answer the severity split below is added
                  // from, rather than off the variant list: that endpoint
                  // lists what a release was built as and never fills the
                  // count in, so reading it here drew a column of zeroes
                  // under a section reporting twenty-six.
                  const mine = counts[at_]?.data?.now;
                  return (
                    <tr key={variant.name}>
                      <td className="id">
                        <Link to={`${at}/findings`}>{variant.name}</Link>
                      </td>
                      <td>
                        {counts[at_]?.isPending ? (
                          <span className="hint">…</span>
                        ) : (
                          (mine?.total ?? 0).toLocaleString()
                        )}
                      </td>
                      <td>{variant.customer_facing === false ? "No" : "Yes"}</td>
                      <td>
                        <Link className="linkish" to={`${at}/components`}>
                          Dependencies
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>What is true of it now</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Open across every variant, by severity. A tag never changes, so none of this carries a
          deadline and none of it is overdue — what is here is what shipped and is still open.
        </p>
        {!settled ? (
          <p className="hint">…</p>
        ) : (
          <ul className="files catalog">
            {BANDS.map((band) => (
              <li key={band}>
                <div>
                  <b>{bands[band].toLocaleString()}</b> {band}
                </div>
              </li>
            ))}
            <li>
              <div>
                <b>{bands.total.toLocaleString()}</b> open in all
              </div>
              <div className="hint">
                Counted as issues at components, the unit every count here uses, added across the
                variants above — so one flaw in two variants is two.
              </div>
            </li>
          </ul>
        )}
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>What changed</h3>
        {previous ? (
          <>
            <p className="hint" style={{ marginTop: 0 }}>
              Against <b>{previous.name}</b>, the release before this one. What was fixed is what a
              release note carries; what is newly present and what is still there are statements
              about what the build contains, and the document for those is the VEX below.
            </p>
            <Link
              to={
                `/products/${encodeURIComponent(product)}/comparison` +
                `?from=${encodeURIComponent(previous.name ?? "")}` +
                `&to=${encodeURIComponent(stream)}`
              }
            >
              Compare {previous.name} with {stream}
            </Link>
          </>
        ) : (
          <p className="hint" style={{ marginTop: 0 }}>
            Nothing to compare against: no earlier release of this product has a day recorded, so
            there is no "the one before this". Recording when a release went out is what orders
            them.
          </p>
        )}
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>What we told customers</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          What goes out with a release, in the order it is usually needed.
        </p>
        <ul className="files catalog">
          <li>
            <div>
              {previous ? (
                <Link
                  to={
                    `/products/${encodeURIComponent(product)}/comparison` +
                    `?from=${encodeURIComponent(previous.name ?? "")}` +
                    `&to=${encodeURIComponent(stream)}`
                  }
                >
                  The release note
                </Link>
              ) : (
                <b>The release note</b>
              )}
            </div>
            <div className="hint">
              Every issue this release fixed since the one before it, worst first, as markdown that
              goes straight in. Built on the comparison screen, where the pair is picked.
            </div>
          </li>
          <li>
            <div>
              <Link to="/reports/advisories-issued">Advisories issued</Link>
            </div>
            <div className="hint">
              What has been published about flaws in our own product.{" "}
              {/* Deliberately not narrowed to this release. An advisory is
                  about a flaw and is published once, so tying it to whichever
                  release happened to be cut nearby would invent a
                  relationship the record does not hold. */}
              Not narrowed to this release: an advisory is about a flaw rather than about a release,
              and it goes out once however many releases carry the flaw.
            </div>
          </li>
          {variants.map((variant) => (
            <li key={`vex-${variant.name}`}>
              <div>
                <a
                  href={
                    `/v1/products/${encodeURIComponent(product)}` +
                    `/streams/${encodeURIComponent(stream)}` +
                    `/variants/${encodeURIComponent(variant.name ?? "")}/vex`
                  }
                >
                  VEX document · {variant.name}
                </a>
              </div>
              <div className="hint">
                What stands about the components this variant ships, as a customer&rsquo;s own
                scanner reads it. Approved dismissals only, public findings only, and a deferral is
                absent rather than published as anything.
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <h3>The record</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Every vulnerability known in a build of this release and what became of it, decided or
          not, with no triage line applied. The complement of what was told to customers: that says
          what we published, this says what was known.
        </p>
        <ul className="files catalog">
          {variants.map((variant) => (
            <li key={`register-${variant.name}`}>
              <div>
                <Link
                  to={
                    `/reports/disposition-register?product=${encodeURIComponent(product)}` +
                    `&stream=${encodeURIComponent(stream)}` +
                    `&variant=${encodeURIComponent(variant.name ?? "")}`
                  }
                >
                  Disposition register · {variant.name}
                </Link>
              </div>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}

// The release before this one, by the day it went out.
//
// A day nobody recorded cannot be ordered against one that was, so a release
// with no date is not a candidate — reading its declaration date as its
// release date is what makes a release recorded months late sort wrongly.
function beforeThis(
  rows: { name?: string; kind?: string; released_on?: string; parent?: string }[],
  here?: { name?: string; released_on?: string; parent?: string },
) {
  if (!here?.released_on) return undefined;
  return rows
    .filter(
      (row) =>
        row.kind === "tag" &&
        row.name !== here.name &&
        !!row.released_on &&
        row.released_on < (here.released_on ?? "") &&
        // Cut from the same branch where both say so. Two branches are two
        // pieces of software, and comparing them reads as a regression
        // somebody then goes looking for.
        (!row.parent || !here.parent || row.parent === here.parent),
    )
    .sort((a, b) => (b.released_on ?? "").localeCompare(a.released_on ?? ""))[0];
}

// The severity counts of every variant, added up.
function totalled(
  each: (
    { critical?: number; high?: number; medium?: number; low?: number; total?: number } | undefined
  )[],
) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  for (const one of each) {
    if (!one) continue;
    out.critical += one.critical ?? 0;
    out.high += one.high ?? 0;
    out.medium += one.medium ?? 0;
    out.low += one.low ?? 0;
    out.total += one.total ?? 0;
  }
  return out;
}
