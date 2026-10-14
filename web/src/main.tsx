// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { App } from "./app/App";
import { Boundary } from "./app/Boundary";
import { sessionEnded } from "./app/ended";
import { retryable, statusOf } from "./api/queries";
import "./index.css";

const queries = new QueryClient({
  // A read refused for want of a session is noticed here too. A session that
  // ends while somebody is reading gives every screen empty data and no
  // reason, and nothing asks who is signed in again — the identity read is
  // held for five minutes and is not refetched on focus. Without this the
  // first sign that the session is gone is a write.
  //
  // The identity read itself resolves its own 401 rather than throwing — to
  // "nobody is signed in", or to the identity already held after raising the
  // ended session itself — so it never reaches this and this cannot start a
  // loop through it.
  queryCache: new QueryCache({
    onError: (error) => {
      if (statusOf(error) === 401) sessionEnded();
    },
  }),
  // A write refused for want of a session is noticed once, here, rather than
  // by every screen that writes. Recognizing it at each call site is how the
  // one that forgets shows "not authorized" against a button somebody just
  // pressed and leaves them to work out that their session ended.
  mutationCache: new MutationCache({
    onError: (error) => {
      if (statusOf(error) === 401) sessionEnded();
    },
  }),
  defaultOptions: {
    queries: {
      // A finding list read a second ago is still the finding list. What
      // changes underneath a reader is a nightly scan, not a keystroke.
      staleTime: 30_000,
      retry: (count, error) => count < 2 && retryable(error),
      refetchOnWindowFocus: false,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queries}>
      <BrowserRouter>
        {/* The last one. Everything below has its own, closer to what it
            draws; this catches what the frame itself throws, which without it
            unmounts the page to nothing. */}
        <Boundary what="OpenPSIRT could not be drawn." where="the application">
          <App />
        </Boundary>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
