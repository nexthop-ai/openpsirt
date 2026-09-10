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

// The one screen somebody sees before they hold anything. It offers the ways
// in this deployment has configured and says nothing else — which of them a
// given person can use is not knowable until they have used it, and guessing
// out loud would tell a stranger who has an account here.
//
// `resuming` is the same offer made over the screen somebody was already on,
// after a session ended under them. The words differ because the situation
// does: one is arriving, the other is being interrupted.
export function SignIn({ resuming }: { resuming?: boolean }) {
  const providers = useQuery({
    queryKey: ["providers"],
    retry: false,
    queryFn: async () => unwrap(await api.GET("/v1/sign-in", {})),
  });

  return (
    <div className="flex min-h-dvh items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <img
            src="/brand/logo.svg"
            alt="OpenPSIRT — Product Security Incident Response & Triage"
            className="h-10"
          />
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
            <p className="text-center text-sm text-[var(--muted)]">
              Anything you had typed is kept, and you will come back to it.
            </p>
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
