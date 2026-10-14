// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Body } from "../api/client";
import { unwrap, Refused } from "../api/queries";
import { forgetAll, forgetSession } from "./drafts";
import { sessionEnded } from "./ended";
import { rememberForward, signedOutHere } from "../screens/SignIn";

// The caller and their reach, in the server's own shape: a field the server
// renames or makes nullable is a compile error at every reader.
export type Who = Body<"WhoBody">;

// What somebody can do in one product.
type Can = Body<"CanBody">;

// The caller, and their reach. Asked once and shared, because every
// screen needs it to decide what to draw and asking per screen would put a
// round trip in front of every navigation.
//
// A 401 is an answer, not a failure: it means nobody is signed in, which is
// the ordinary state of a fresh browser. It resolves to null rather than
// throwing so the shell can send somebody to sign in instead of showing them
// an error about their own not being signed in.
//
// Where somebody was already signed in, a 401 is their session ending under
// them rather than a fresh browser: the identity they had is kept, and the
// ended session is raised, so the way back in is offered over the screen they
// were on rather than a sign-in page replacing it.
export function useWho() {
  const client = useQueryClient();
  return useQuery<Who | null>({
    queryKey: ["whoami"],
    retry: false,
    staleTime: 5 * 60_000,
    queryFn: async () => {
      try {
        return unwrap(await api.GET("/v1/session/me", {}));
      } catch (error) {
        if (error instanceof Refused && error.status === 401) {
          const held = client.getQueryData<Who | null>(["whoami"]);
          if (held) {
            sessionEnded();
            return held;
          }
          return null;
        }
        throw error;
      }
    },
  });
}

// mayOf finds what somebody can do in one product. Absent means they cannot
// reach it at all, which a screen should treat as not-there rather than as
// forbidden — the same answer the server gives.
//
// Matched without regard to capitals, as the server matches a product name
// somebody typed: an address typed with other capitals names the same product.
// Every screen asks this one question through here.
export function mayOf(who: Who | null | undefined, product: string): Can | undefined {
  const named = product.toLowerCase();
  return (who?.reach ?? []).find((each) => each.product.toLowerCase() === named);
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
// It leaves only once the server has ended the session. The server clears the
// cookie only when it ends the session, so a sign-out it refused or never
// heard leaves the browser signed in, and on a shared machine the next person
// to open it would be the last. The answer is whether it ended, and the caller
// stays and offers it again where it did not. It never rejects: the caller is
// a click handler, where a rejection is one nobody sees.
export async function signOut(
  end: () => Promise<boolean>,
  go: (where: string) => void,
): Promise<boolean> {
  forgetAll();
  forgetSession();
  let ended: boolean;
  try {
    ended = await end();
  } catch {
    ended = false;
  }
  if (!ended) return false;
  rememberForward();
  go(signedOutHere);
  return true;
}

// Whether a sign-out's answer means nobody is signed in on this browser any
// more: the session ended, or there was none to end.
export function signedOutBy(status: number): boolean {
  return (status >= 200 && status < 300) || status === 400 || status === 401;
}
