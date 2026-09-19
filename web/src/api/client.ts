import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

// A response shape, by the name the OpenAPI document gives it.
//
// Screens use this rather than restating the fields, which is the same rule as
// the client itself applied one level in. A hand-copied row type compiles
// perfectly while quietly missing whatever the server grew since it was
// written — that is not hypothetical: the running-out rows gained the version
// a link needs, three screens kept their own copies without it, and every link
// they drew to a component shipped at two versions dead-ended.
export type Body<K extends keyof components["schemas"]> = components["schemas"][K];

// One client for the whole application, generated from the same OpenAPI
// document the server publishes. Nothing here hand-writes a path or a response
// shape, so an endpoint that changes shape is a compile error rather than a
// screen that renders undefined.
export const api = createClient<paths>({
  baseUrl: "/",
  // The session is a cookie the browser holds; nothing in this application
  // ever sees the token. Sending credentials is therefore the whole of
  // authentication here.
  credentials: "same-origin",
});

// csrfCookie is the value a page has to echo on a write.
//
// Exported so the preference below can be pinned: it is a control, and a
// control nobody has watched fail is a control nobody has tested. It is
// deliberately readable by script, where the session cookie is not — that
// asymmetry is what makes echoing it evidence the request came from a page
// rather than from a form somebody else's site submitted.
//
// Held under two names: over TLS the server sets it with the `__Host-` prefix,
// which is what stops a sibling host writing one for this deployment to read,
// and without TLS a browser refuses that prefix at all. Both are looked for,
// because which one is there is a property of the deployment rather than of
// the page.
export function csrfCookie(): string {
  let prefixed = "";
  let bare = "";
  for (const part of document.cookie.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === "__Host-openpsirt_csrf") prefixed = rest.join("=");
    else if (name === "openpsirt_csrf") bare = rest.join("=");
  }
  // The prefixed one wins where both are there. Returning whichever came
  // first gave the control away: a sibling host under the same registrable
  // domain can set the unprefixed name for this deployment to read, and
  // browsers order two cookies of equal path length by when they were
  // created — so one planted first was the one sent, every write was refused
  // against the value bound to the session, and nothing in the page said why.
  //
  // The fallback stays: a deployment served without TLS holds only the bare
  // name, because a browser refuses the prefix over plain HTTP.
  return decoded(prefixed || bare);
}

// A cookie value the browser handed back, decoded where it can be.
//
// `decodeURIComponent` throws on a malformed percent escape, and this runs
// inside the middleware every write goes through — so an unthrowing decode is
// what stops one bad cookie, set by anything on this host, from failing every
// write in the application with a message no screen can render. A value that
// will not decode is passed on as it stands: the server compares it against
// what it set, and a token that does not match is refused there.
function decoded(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

// Every unsafe request carries the token. Registered as middleware rather than
// passed per call, because the one call somebody forgets is the one that
// breaks in production and not in review.
api.use({
  onRequest({ request }) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      const token = csrfCookie();
      if (token) request.headers.set("X-CSRF-Token", token);
    }
    return request;
  },
});
