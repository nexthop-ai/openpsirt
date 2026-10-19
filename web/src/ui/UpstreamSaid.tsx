// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useDecline } from "../api/upstream";
import { linkable } from "./addressable";
import { Failed } from "./Failed";

// What an upstream's statement is here, beside the statement: whether it
// closes what it speaks for by itself or waits for review, whether somebody
// declined it, where the upstream published it, and the control that declines
// it or takes that back.
//
// The document's address arrived from outside, so it is a link only where it
// is one this deployment sends a reader to, and shown as text otherwise.
export function UpstreamSaid({
  statement,
  forAnybody,
  declined,
  document,
  mayTriage,
}: {
  statement: number;
  forAnybody: boolean;
  declined: boolean;
  document: string;
  mayTriage: boolean;
}) {
  const decline = useDecline();
  const href = linkable(document);
  return (
    <span>
      {declined ? (
        <span className="state" title="Declined here: it closes nothing and is offered to nobody">
          upstream · declined
        </span>
      ) : forAnybody ? (
        <span
          className="state open"
          title="Holds for anybody shipping this component. Closes this issue here at the version it names"
        >
          upstream · applies here
        </span>
      ) : (
        <span
          className="state"
          title="Depends on the upstream's own build. Offered for review only"
        >
          upstream · for review
        </span>
      )}{" "}
      {href ? (
        <a href={href} target="_blank" rel="noreferrer noopener" className="linkish">
          source
        </a>
      ) : (
        <span className="id">{document}</span>
      )}
      {mayTriage && (
        <>
          {" "}
          <button
            type="button"
            className="linkish"
            disabled={decline.isPending}
            title={
              declined
                ? "Take the decline back, so it closes and is offered again"
                : "Stop it closing anything here or being offered"
            }
            onClick={() => decline.mutate({ statement, declined: !declined })}
          >
            {declined ? "Restore" : "Decline"}
          </button>
        </>
      )}
      {decline.error != null && <Failed error={decline.error} what="That could not be changed." />}
    </span>
  );
}
