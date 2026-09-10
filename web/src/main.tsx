import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MutationCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { App } from "./app/App";
import { sessionEnded } from "./app/ended";
import "./index.css";

const queries = new QueryClient({
  // A write refused for want of a session is noticed once, here, rather than
  // by every screen that writes. Recognizing it at each call site is how the
  // one that forgets shows "not authorized" against a button somebody just
  // pressed and leaves them to work out that their session ended.
  mutationCache: new MutationCache({
    onError: (error) => {
      if (isUnauthorized(error)) sessionEnded();
    },
  }),
  defaultOptions: {
    queries: {
      // A finding list read a second ago is still the finding list. What
      // changes underneath a reader is a nightly scan, not a keystroke.
      staleTime: 30_000,
      // A 401 means the session ended, and retrying cannot fix that — it just
      // delays the sign-in prompt by three round trips.
      retry: (count, error) => !isUnauthorized(error) && count < 2,
      refetchOnWindowFocus: false,
    },
  },
});

function isUnauthorized(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    (error as { status: number }).status === 401
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queries}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
