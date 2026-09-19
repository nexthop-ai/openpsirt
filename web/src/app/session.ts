import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap, Refused } from "../api/queries";
import { forgetAll, forgetSession } from "./drafts";
import { rememberForward, signedOutHere } from "../screens/SignIn";

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
  // Whether they may read this deployment's own records and write none of
  // them. A separate answer from admin: one of them changes things.
  audits?: boolean;
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
  // How many rows one action may write here. A screen acting on a selection
  // bounds it by this and says so, rather than turning one click into as many
  // round trips as a filter matched — a page nobody can use and nothing can
  // cancel.
  bulk_cap?: number;
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

// Signing out, as a sequence rather than as a click handler.
//
// Here rather than in the click handler because the ordering is the whole of
// it, and an anonymous async function on a button is not somewhere a test can
// reach.
//
// Drafts are cleared first, before anything is awaited and outside the try.
// They hold triage text, private findings included, and text that survived a
// sign-out would be exposed in a way the application itself is not. A sign-out
// that never reached the server is exactly the case where clearing matters
// most, so it cannot sit inside the part that can fail.
//
// The session's own state goes with them, and for the same reason. This is
// a same-tab navigation, so what the tab remembers survives it by
// construction: without this the next person to sign in here is handed the
// previous person's scope in the bar — a product name they may hold no grant
// on — and their last outcome and reasoning in the decision form.
//
// Forwarding is marked in this tab as well as in the address. Where there
// is one provider the sign-in screen forwards straight to it, and the provider
// still holds its own session — so an unmarked arrival would sign them back in
// and make signing out impossible. The address alone is lost the moment
// somebody presses Back, which would forward from any other screen.
//
// A full load rather than a route change, because signing out has to drop
// every cached answer and starting again is the way to be sure.
//
// It does not fail. A server that never heard is not something a caller
// can act on — the drafts are gone, the forward is marked, and the page is
// already being replaced — and the caller is a click handler, so a rejection
// there is an unhandled one in the browser console rather than anything
// anybody sees. The one thing left of the session is a row on the server that
// expires on its own.
export async function signOut(
  end: () => Promise<unknown>,
  go: (where: string) => void,
): Promise<void> {
  forgetAll();
  forgetSession();
  try {
    await end();
  } catch {
    // Said above: there is nothing to do with it and nowhere to say it.
  } finally {
    rememberForward();
    go(signedOutHere);
  }
}
