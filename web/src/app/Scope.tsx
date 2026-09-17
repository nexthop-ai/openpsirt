import { useRef, useState } from "react";
import { useClickAway } from "../ui/away";
import { useReseed } from "../ui/reseed";
import { useLocation, useNavigate } from "react-router-dom";
import { useCatalog, useReleaseVariants } from "../api/catalog";
import {
  findingsPath,
  needsBuild,
  onFindings,
  remember,
  rescoped,
  useScope,
  type Scoped,
} from "./scope";

// What you are looking at, and how to change it.
//
// The choosing happens inside the panel rather than by walking through
// listing screens: picking a product narrows the branches beside it, picking a
// branch narrows the variants, and only the last choice moves you. Sending
// somebody to a page of products to pick one makes changing scope a
// navigation, when it is a property of the screen they are already on.
export function Scope() {
  const at = useScope();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const { pathname } = useLocation();

  // What has been picked in here but not yet gone anywhere. Seeded from the
  // address so opening the panel starts where you are.
  const [product, setProduct] = useState(at.product ?? "");
  const [stream, setStream] = useState(at.stream ?? "");
  // A build is required here, so "all" is not on offer at any level.
  const whole = needsBuild(pathname);

  // Applying a partial pick remembers it and comes back through the address,
  // so the pending pick follows what was applied. The panel stays open across
  // it — which is why this re-seeds the two fields rather than remounting the
  // panel, since a remount would close it on the first of the three choices.
  useReseed(`${at.product ?? ""}\u001f${at.stream ?? ""}`, () => {
    setProduct(at.product ?? "");
    setStream(at.stream ?? "");
  });

  useClickAway(box, open, () => setOpen(false));

  const { products, streams, variants: declared } = useCatalog(open, product);
  // What one release was built as. With a branch or tag chosen this is the set
  // to offer; with every branch selected it is the product's own, which is
  // what `declared` holds — the per-release list would be an arbitrary one of
  // them.
  const variants = useReleaseVariants(open, product, stream);
  // What the variant column draws, which is not simply whichever of the two
  // the branch selects.
  //
  // The two are different questions and different cache entries, so choosing a
  // branch switched the column to a query holding nothing and it emptied and
  // refilled — on a selection that usually does not change the names at all.
  // The product's own list stands in for that gap: it is a superset of any one
  // release's, so the column offers nothing the release does not have for
  // longer than the read takes, and it stops going blank in front of somebody
  // halfway through choosing.
  //
  // **The stand-in has to be this list and no other.** Holding the previous
  // branch's answer would fill the same gap with a set that is not a superset
  // of anything — a variant picked from it is a build this release was never
  // built as, which is the selection this panel is not allowed to send. Both
  // reads are left to arrive empty for that reason.
  const offered = stream ? (variants.data?.items ?? declared.data?.items) : declared.data?.items;

  // Applied as soon as it is chosen, at whatever level. A partial selection is
  // a real answer now — every level offers "all" — so there is nothing to wait
  // for. The panel stays open through the product and the branch, so that all
  // three can be chosen in one visit; it closes on the last level, on Escape,
  // or on a click elsewhere. Closing after every pick made choosing a build
  // three openings of the same panel.
  function apply(chosen: Scoped, close = false) {
    if (close) setOpen(false);
    remember(chosen);
    // Stay where you are. A screen that names a build swaps its build and
    // keeps doing whatever it was doing; anything else simply remembers the
    // choice, because changing scope is not a reason to move somebody.
    //
    // Partial selections go through the same question, because an address
    // that names a product is the authority for that product: remembering
    // another one and staying put lets the path put the old one back.
    const next = rescoped(pathname, chosen);
    if (next) {
      navigate(next);
      return;
    }
    // The findings list answers for whatever is selected rather than declining
    // a partial one, and its address carries the selection — so it moves to
    // the wider list rather than leaving the narrower one on screen. This is
    // not the jump refusing a partial scope refused: it is the same screen,
    // answering the question that was just asked of it.
    if (onFindings(pathname)) {
      navigate(findingsPath(chosen));
      return;
    }
    // A re-render is needed for the bar to catch up with what was remembered.
    navigate(pathname, { replace: true });
  }

  // Choosing a level clears the ones below it that can no longer stand. A
  // branch belongs to a product, and so does a variant, so "all products"
  // cannot leave either beside it.
  function pickProduct(name: string) {
    setProduct(name);
    setStream("");
    if (!name) {
      apply({});
      return;
    }
    if (!whole) apply({ product: name });
  }

  return (
    <div className="scopebar" ref={box}>
      {/* All three, always. Which one is pressed does not matter — they open
          the same panel — but a control that appears only once its parent is
          chosen hides that there is a choice to make at all. */}
      <button type="button" className="scope" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="label">Scope</span>
        {at.product || (whole ? "pick one" : "all")}
        <span className="caret">▾</span>
      </button>
      <span className="sep">/</span>
      <button
        type="button"
        className={at.product ? "scope" : "scope only"}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {at.stream || (at.product ? "all" : "—")}
        <span className="caret">▾</span>
      </button>
      <span className="sep">/</span>
      <button
        type="button"
        className={at.stream ? "scope" : "scope only"}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {at.variant || (at.product ? "all" : "—")}
        <span className="caret">▾</span>
      </button>

      <div className={open ? "picker open" : "picker"}>
        <div>
          <h5>Product</h5>
          <button
            type="button"
            className="opt"
            aria-current={!product ? "true" : undefined}
            disabled={whole}
            title={whole ? "Pick all three" : undefined}
            onClick={() => pickProduct("")}
          >
            Every product
          </button>
          {(products.data?.items ?? []).map((each) => (
            <button
              key={each.name}
              type="button"
              className="opt"
              aria-current={each.name === product ? "true" : undefined}
              onClick={() => pickProduct(each.name ?? "")}
            >
              {each.display_name || each.name}
            </button>
          ))}
          {products.data && (products.data.items ?? []).length === 0 && (
            <p className="hint">You can reach no product yet.</p>
          )}
        </div>

        <div>
          <h5>Branch or tag</h5>
          {/* Unselectable without a product, because neither a branch nor a
              variant means anything without one to belong to. */}
          {!product && <p className="hint">Pick a product first.</p>}
          {product && (
            <button
              type="button"
              className="opt"
              aria-current={!stream ? "true" : undefined}
              disabled={whole}
              title={whole ? "This screen is about one build, so it needs all three" : undefined}
              onClick={() => {
                setStream("");
                if (!whole) apply({ product });
              }}
            >
              Every branch and tag
            </button>
          )}
          {(streams.data?.items ?? []).map((each) => (
            <button
              key={each.name}
              type="button"
              className="opt"
              aria-current={each.name === stream ? "true" : undefined}
              onClick={() => {
                setStream(each.name ?? "");
                if (!whole) apply({ product, stream: each.name });
              }}
            >
              {each.name} <span className="hint">{each.kind}</span>
            </button>
          ))}
          {product && streams.data && (streams.data.items ?? []).length === 0 && (
            <p className="hint">Nothing is declared under this product yet.</p>
          )}
        </div>

        <div>
          <h5>Variant</h5>
          {!product && <p className="hint">Pick a product first.</p>}
          {product && (
            <button
              type="button"
              className="opt"
              aria-current={!at.variant ? "true" : undefined}
              disabled={whole}
              title={whole ? "This screen is about one build, so it needs all three" : undefined}
              onClick={() => apply({ product, stream }, true)}
            >
              Every variant
            </button>
          )}
          {(offered ?? []).map((each) => (
            <button
              key={each.name}
              type="button"
              className="opt"
              aria-current={each.name === at.variant ? "true" : undefined}
              onClick={() => apply({ product, stream, variant: each.name }, true)}
            >
              {each.name}
            </button>
          ))}
          {stream && variants.data && (variants.data.items ?? []).length === 0 && (
            <p className="hint">Nothing has been scanned on this line yet.</p>
          )}
        </div>

        <p className="hint" style={{ gridColumn: "1 / -1" }}>
          Variants appear once a scan is filed against them.
        </p>
      </div>
    </div>
  );
}
