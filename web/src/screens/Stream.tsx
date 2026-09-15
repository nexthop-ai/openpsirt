import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Loading } from "../ui/Loading";
import { Failed } from "../ui/Failed";
import { Variants } from "./Variants";
import { Release } from "./Release";

// One stream, at the address a branch and a tag share.
//
// A branch and a tag are the same kind of thing to the catalog and very
// different things to a reader: a branch is rebuilt nightly and what matters is
// what it is built as, and a tag never changes and what matters is what was
// handed over when it was cut. So the address resolves to whichever screen
// answers the question that line poses, rather than a tag being drawn as a
// branch with the interesting parts missing.
//
// **Resolved rather than guessed from the name.** A tag is a tag because the
// catalog says so, and a naming convention is a rule nobody agreed to.
export function Stream() {
  const { product = "", stream = "" } = useParams();
  const streams = useQuery({
    queryKey: ["streams", product],
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/streams", { params: { path: { product } } })),
  });

  if (streams.isPending) return <Loading />;
  // Nothing is dispatched on a read that failed. This screen exists to stop a
  // tag being drawn as a branch with the interesting parts missing, and the
  // fallback is the branch view — so falling through on a failure does the one
  // thing the screen is for preventing. That the variants list reports its own
  // failure is true and is not the question: the choice has already been made
  // wrongly by then.
  if (streams.isError) {
    return <Failed error={streams.error} what="This could not be resolved to a branch or a tag." />;
  }
  // A name matching no row is a 404 the variants screen reports for itself,
  // so the fallback stays for that.
  const here = streams.data?.items?.find((row) => row.name === stream);
  if (here?.kind === "tag") return <Release product={product} stream={stream} />;
  return <Variants />;
}
