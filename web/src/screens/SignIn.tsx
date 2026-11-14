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
  if (landedAt(signedOut) || landedAt(refused) || landedAt(failed)) return "";
  return "?return=" + encodeURIComponent(here);
}

// A forward to the provider already tried in this tab.
//
// One provider means the button is the only thing on the screen, so the screen
// is a stop on the way rather than a choice — but a forward that repeats is a
// person who can never read that they were refused. Coming back to the
// application after a refusal shows the way in.
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
const signedOut = "signed-out";
export const signedOutHere = "/?" + signedOut;

// The marker on the address a refused sign-in lands on. The server redirects
// every refused sign-in to "/?no-access", whatever the reason, so the screen
// says no more than that the sign-in gave no access.
const refused = "no-access";

// The marker on the address a sign-in that failed on this side lands on
// ("/?sign-in-failed"). It marks a fault on this side, so the screen says to
// try again.
const failed = "sign-in-failed";

// Whether the address carries one of the markers above.
function marked(marker: string): boolean {
  return new URLSearchParams(window.location.search).has(marker);
}

// Whether the browser is on the home page carrying a marker, which is the
// address the server or a sign-out sends it to.
function landedAt(marker: string): boolean {
  return window.location.pathname === "/" && marked(marker);
}

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
  if (marked(signedOut)) return false;
  // A refused sign-in lands here, and the provider still holds the account it
  // refused, so forwarding would refuse it again in a loop.
  if (landedAt(refused)) return false;
  // A failed sign-in lands here, and forwarding would repeat the fault in a
  // loop.
  if (landedAt(failed)) return false;
  return !alreadyTried();
}

// The one screen somebody sees before they hold anything. It offers the ways
// in this deployment has configured; at a refused or failed landing, or for a
// browser the proxy named, it also says what happened, and never why, since
// a reason would tell a stranger who has an account here.
//
// `resuming` is the same offer made over the screen somebody was already on,
// after a session ended under them. The words differ because the situation
// does: one is arriving, the other is being interrupted.
// The dark wordmark, named once. It is committed and symlinked into the web
// root.
const LOOKS = "/brand/logo-dark.svg";

export function SignIn({ resuming }: { resuming?: boolean }) {
  const providers = useQuery({
    queryKey: ["providers"],
    retry: false,
    queryFn: async () => unwrap(await api.GET("/v1/sign-in", {})),
  });

  const offered = providers.data?.items ?? [];
  // A browser the trusted proxy named and this deployment refused. The proxy
  // signs it in on every request, so the ways in below are no way in for it,
  // whether or not a session ended first.
  const proxied = Boolean(providers.data?.named_by_proxy);
  const only = offered.length === 1 ? offered[0] : undefined;
  const forwarding = Boolean(only) && !proxied && forwardable(offered.length, resuming);
  // At an address a refused or failed sign-in lands on, what happened is said
  // once a way in is offered and nothing else is: while the ways in load, where
  // reading them fails, or where none is configured, the panel below speaks
  // alone.
  const landed = !resuming && (landedAt(refused) || landedAt(failed));
  const turnedAway = proxied || (!resuming && landedAt(refused) && offered.length > 0);
  const toRetry = !proxied && !resuming && landedAt(failed) && offered.length > 0;
  // The invitation waits for the ways in, which may say the proxy named them.
  const invited = !turnedAway && !toRetry && !landed && !providers.isPending;

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
      {/* Over the page it is a panel of its own, drawn like every other sheet:
          text straight on the blurred screen behind it reads grey on grey. */}
      <div
        className={
          resuming
            ? "w-full max-w-sm rounded-[var(--radius-lg)] border border-[var(--line-strong)] bg-[var(--surface)] px-6 py-8 text-[var(--ink)] shadow-[var(--shadow-lg)]"
            : "w-full max-w-sm"
        }
      >
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
          {turnedAway && (
            <div className="text-center">
              <p className="text-sm font-medium">No access here</p>
              <p className="mt-1 text-sm text-[var(--muted)]">Ask an administrator for access.</p>
            </div>
          )}
          {toRetry && (
            <div className="text-center">
              <p className="text-sm font-medium">Sign-in didn&rsquo;t finish</p>
              <p className="mt-1 text-sm text-[var(--muted)]">Try again shortly.</p>
            </div>
          )}
          {invited && (
            <p className="text-sm text-[var(--muted)]">
              {resuming ? "Your session ended. Sign in to carry on." : "Sign in to continue"}
            </p>
          )}
          {resuming && !proxied && !providers.isPending && (
            <p className="text-center text-sm text-[var(--muted)]">Anything you typed is kept.</p>
          )}
        </div>

        {providers.isPending && <Loading />}

        {providers.isError && (
          <Failed error={providers.error} what="The ways in could not be read." />
        )}

        {providers.data && !proxied && (providers.data.items ?? []).length === 0 && (
          <div className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-4 py-6 text-center">
            <p className="text-sm font-medium">No way in is configured.</p>
            <p className="mt-1 text-sm text-[var(--muted)]">
              An operator configures a sign-in provider before anybody can sign in.
            </p>
          </div>
        )}

        <div className="flex flex-col gap-2">
          {(proxied ? [] : offered).map((each: Provider) => (
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
