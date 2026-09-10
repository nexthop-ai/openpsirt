import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap, Refused } from "../api/queries";

export type Can = {
  product: string;
  name: string;
  may_see: boolean;
  sees_all: boolean;
  may_triage: boolean;
  // Giving work to somebody else, or taking what they hold. Taking work
  // nobody owns and handing back your own are triage and need only may_triage.
  may_assign: boolean;
  may_hide: boolean;
  may_agree: boolean;
};

export type Who = {
  identity: string;
  name: string;
  admin: boolean;
  kind: "person" | "key";
  reach: Can[];
  // What they asked to be sent, and whether anything can be: a screen offering
  // the switches has to know their state, and a switch that changes nothing is
  // worse than no switch.
  digest?: boolean;
  digest_unassigned?: boolean;
  reachable?: boolean;
  // The deployment's deferral threshold, in days. A screen taking a date
  // needs it while the date is being chosen: which side of it a date falls on
  // decides whether a second person has to agree, and reading that off the
  // response is reading it after the fact.
  deferral_days?: number;
};

// Who is asking, and what they may do. Asked once and shared, because every
// screen needs it to decide what to draw and asking per screen would put a
// round trip in front of every navigation.
//
// A 401 is an answer, not a failure: it means nobody is signed in, which is
// the ordinary state of a fresh browser. It resolves to null rather than
// throwing so the shell can send somebody to sign in instead of showing them
// an error about their own not being signed in.
export function useWho() {
  return useQuery<Who | null>({
    queryKey: ["whoami"],
    retry: false,
    staleTime: 5 * 60_000,
    queryFn: async () => {
      try {
        return unwrap(await api.GET("/v1/session/me", {})) as Who;
      } catch (error) {
        if (error instanceof Refused && error.status === 401) return null;
        throw error;
      }
    },
  });
}

// mayOf finds what somebody can do in one product. Absent means they cannot
// reach it at all, which a screen should treat as not-there rather than as
// forbidden — the same answer the server gives.
export function mayOf(who: Who | null | undefined, product: string): Can | undefined {
  return who?.reach.find((each) => each.product === product);
}
