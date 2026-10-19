// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { useOffers } from "../api/upstream";
import { findingAt } from "../app/routes";
import { mayOf, useWho } from "../app/session";
import { Failed } from "../ui/Failed";
import { UpstreamSaid } from "../ui/UpstreamSaid";

// What upstreams say about open findings here that depends on their own build.
//
// Never applied by itself. Opening one lands on the finding, where the
// statement starts a claim that goes through approval as any other; declining
// one takes it off this list. Drawn only where something is offered.
export function UpstreamOffers({ product }: { product?: string }) {
  const offers = useOffers(product ?? "");
  const who = useWho();
  const rows = offers.data?.items ?? [];
  if (offers.isError) {
    return (
      <Failed error={offers.error} what="What upstreams offer for review could not be read." />
    );
  }
  if (rows.length === 0) return null;
  return (
    <section id="upstream-offers" className="card" style={{ marginTop: 18 }}>
      <h3>Offered by an upstream</h3>
      <p className="hint">
        Depends on the upstream&rsquo;s own build. Review before it applies here.
      </p>
      {rows.map((one) => (
        <div key={`${one.statement} ${one.finding}`} className="prior">
          <header>
            <Link
              to={findingAt(
                { product: one.product, stream: one.stream, variant: one.variant },
                { vulnerability: one.issue, component: one.component, version: one.version },
              )}
              className="id"
            >
              {one.issue} · {one.component} {one.version}
            </Link>{" "}
            <span className="hint">
              {one.product} {one.stream}/{one.variant} · {one.publisher} says{" "}
              <b>{one.status.replace("_", " ")}</b>
              {one.justification && <> · {one.justification.replaceAll("_", " ")}</>}
              {one.within && <> · in {one.within}</>}
            </span>{" "}
            <UpstreamSaid
              statement={one.statement}
              forAnybody={false}
              declined={false}
              document={one.document}
              mayTriage={!!mayOf(who.data, one.product)?.triages_public}
            />
          </header>
          {one.reasoning && (
            <div className="why">
              <p style={{ whiteSpace: "pre-wrap" }}>{one.reasoning}</p>
            </div>
          )}
        </div>
      ))}
    </section>
  );
}
