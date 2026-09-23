// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Loading } from "../ui/Loading";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";

type Provider = { name: string; path: string };

// where a sign-in should come back to.
//
// The address the browser is on, path and query, so somebody halfway through
// writing lands back on what they were writing rather than on the home page .
// The server takes it only if it is a path on this deployment, which is where
// the open-redirect defense lives — a page cannot make a sign-in vouch for
// somewhere else by asking nicely.
//
// The home page is not worth returning to, so a sign-in that begins there
// carries nothing and the server's own default applies.
export function returningHere(): string {
  const here = window.location.pathname + window.location.search;
  if (here === "/" || here === "") return "";
  return "?return=" + encodeURIComponent(here);
}

// A forward to the provider already tried in this tab.
//
// One provider means the button is the only thing on the screen, so the screen
// is a stop on the way rather than a choice — but a forward that repeats is a
// person who can never read why they were refused. Somebody who authenticates
// and was granted nothing is refused by design, and the refusal is an API
// answer rather than a screen; coming back to the application afterwards has to
// show the way in rather than send them round again.
//
// Per tab, and cleared once somebody is actually signed in. Storage can be
// unavailable or throw, and the honest answer then is to draw the button: a
// screen with a button works, and a forward that cannot be remembered loops.
const triedKey = "signin-forwarded";

// The address signing out lands on, and the marker the sign-in screen reads
// there.
//
// One value, exported, so that the screen and the sign-out button cannot drift
// apart: a test asserting the address sign-out actually goes to is what catches
// one of them changing.
export const signedOut = "signed-out";
export const signedOutHere = "/?" + signedOut;

function alreadyTried(): boolean {
  try {
    return window.sessionStorage.getItem(triedKey) !== null;
  } catch {
    return true;
  }
}

export function rememberForward() {
  try {
    window.sessionStorage.setItem(triedKey, "1");
  } catch {
    // Nothing to do. The forward happens anyway and the next arrival draws
    // the button, which is the safe direction.
  }
}

// Forgotten once somebody holds a session, so the next sign-in forwards again.
export function forgetForward() {
  try {
    window.sessionStorage.removeItem(triedKey);
  } catch {
    // Nothing stored, nothing to clear.
  }
}

// An arrival to send straight on to the provider.
//
// Deliberately narrow. It is a stop on the way only where there is nothing to
// decide and nothing to read.
export function forwardable(count: number, resuming: boolean | undefined): boolean {
  if (count !== 1) return false;
  // Drawn over the screen somebody was already on, so forwarding would take
  // them away from work they can still see.
  if (resuming) return false;
  // Signing out lands here, and the provider still holds its own session — so
  // forwarding would sign them straight back in and make signing out
  // impossible.
  if (new URLSearchParams(window.location.search).has(signedOut)) return false;
  return !alreadyTried();
}

// The one screen somebody sees before they hold anything. It offers the ways
// in this deployment has configured and says nothing else — which of them a
// given person can use is not knowable until they have used it, and guessing
// out loud would tell a stranger who has an account here.
//
// `resuming` is the same offer made over the screen somebody was already on,
// after a session ended under them. The words differ because the situation
// does: one is arriving, the other is being interrupted.
// The dark wordmark, named once. It is committed and symlinked into the web
// root and was referenced by nothing at all.
const LOOKS = "/brand/logo-dark.svg";

export function SignIn({ resuming }: { resuming?: boolean }) {
  const providers = useQuery({
    queryKey: ["providers"],
    retry: false,
    queryFn: async () => unwrap(await api.GET("/v1/sign-in", {})),
  });

  const offered = providers.data?.items ?? [];
  const only = offered.length === 1 ? offered[0] : undefined;
  const forwarding = Boolean(only) && forwardable(offered.length, resuming);

  useEffect(() => {
    if (!forwarding || !only) return;
    rememberForward();
    window.location.assign(only.path + returningHere());
  }, [forwarding, only]);

  // Nothing is drawn while the browser is on its way out. Drawing the button
  // first would show a screen that vanishes under whoever reached for it.
  if (forwarding) return <Loading />;

  return (
    <div className="flex min-h-dvh items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          {/* The artwork the look calls for. The light wordmark's ink is a
              near-black blue, which on the dark look's canvas is all but
              invisible — on the one screen somebody meets before they know
              what the tool is. The stored choice wins over the system's,
              because a person who picked a look picked it here too; where
              nothing is stored, `prefers-color-scheme` answers. */}
          <picture>
            <source srcSet={LOOKS} media="(prefers-color-scheme: dark)" />
            <img
              src="/brand/logo.svg"
              alt="OpenPSIRT — Product Security Incident Response & Triage"
              className="signin-mark h-10"
            />
          </picture>
          {/* The mark carries no words, so the wordmark's second line is said
              here: this is the one screen somebody meets before they know what
              the tool is. */}
          <p className="text-xs uppercase tracking-wide text-[var(--faint)]">
            Product Security Incident Response &amp; Triage
          </p>
          <p className="text-sm text-[var(--muted)]">
            {resuming ? "Your session ended. Sign in to carry on." : "Sign in to continue"}
          </p>
          {resuming && (
            <p className="text-center text-sm text-[var(--muted)]">Anything you typed is kept.</p>
          )}
        </div>

        {providers.isPending && <Loading />}

        {providers.isError && (
          <Failed error={providers.error} what="The ways in could not be read." />
        )}

        {providers.data && (providers.data.items ?? []).length === 0 && (
          <div className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-4 py-6 text-center">
            <p className="text-sm font-medium">No way in is configured.</p>
            <p className="mt-1 text-sm text-[var(--muted)]">
              An operator configures a sign-in provider before anybody can sign in.
            </p>
          </div>
        )}

        <div className="flex flex-col gap-2">
          {(providers.data?.items ?? []).map((each: Provider) => (
            <a
              key={each.name}
              href={each.path + returningHere()}
              className="rounded-lg bg-[var(--accent)] px-4 py-2.5 text-center text-sm font-medium text-[var(--accent-ink)] hover:opacity-90"
            >
              Continue with {each.name}
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
