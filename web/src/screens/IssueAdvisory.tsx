import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { on } from "../ui/when";

// Generating an advisory, and recording that one went out.
//
// Both endpoints answered and nothing called them. The document a customer
// receives could be produced by the API and by nothing a person can reach, so
// the one output of this tool that leaves the company was the one output
// nobody here could make.
//
// Drafted per product, because that is the grain of the document: an
// advisory is a statement by a vendor about a product they ship, and this
// issue may sit in several. Refused for a flaw in somebody else's component,
// which is dependency hygiene a consumer reads out of the inventory — the
// refusal says so, so it is shown rather than swallowed.
//
// Recording that it went out is a separate act, and deliberately so: what
// was published on a date cannot be worked out again once a release is added
// or a decision is revised. It is also what lets a second document be a
// revision rather than a duplicate, which CSAF validators check.

type Issued = { version?: number; digest?: string; issued_at?: string };

export function IssueAdvisory({
  vulnerability,
  products,
}: {
  vulnerability: string;
  // The products carrying this issue, as the rows give them: the name to ask
  // with, and what to call it on screen.
  products: { name: string; called: string }[];
}) {
  const [product, setProduct] = useState(products[0]?.name ?? "");
  const [summary, setSummary] = useState("");
  const [issued, setIssued] = useState<Issued | null>(null);
  // Folded until somebody asks. An advisory is about a flaw in something this
  // deployment ships, and most issues on this screen are a scanner's report
  // about somebody else's component — so asking about every one of them on
  // every visit is a refused request per page load, which is noise in a
  // console and work nobody wanted done.
  const [open, setOpen] = useState(false);

  // The advisories already out, without generating anything. Somebody deciding
  // whether to publish a revision is asking before they draft one.
  const gone = useQuery({
    enabled: open && product !== "",
    queryKey: ["issuances", product, vulnerability],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{vulnerability}/advisory/issuance", {
          params: { path: { product, vulnerability } },
        }),
      ),
    retry: false,
  });

  const draft = useMutation({
    mutationFn: async (of: string) =>
      unwrap(
        await api.GET("/v1/products/{product}/issues/{vulnerability}/advisory", {
          params: { path: { product: of, vulnerability } },
        }),
      ),
  });
  const record = useMutation({
    mutationFn: async (of: string) =>
      unwrap(
        await api.POST("/v1/products/{product}/issues/{vulnerability}/advisory/issuance", {
          params: { path: { product: of, vulnerability } },
          body: { ...(summary.trim() ? { summary: summary.trim() } : {}) },
        }),
      ),
    onSuccess: (done) => {
      setIssued(done);
      setSummary("");
      void gone.refetch();
    },
  });

  const document = draft.data;
  const written = useMemo(() => (document ? JSON.stringify(document, null, 2) : ""), [document]);
  if (products.length === 0) return null;

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <header>
        <h3>
          <button
            type="button"
            className="linkish"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            {open ? "▾" : "▸"} Advisory
          </button>
        </h3>
      </header>
      <p className="reading">
        A CSAF 2.0 document: what the flaw is, and which releases hold it. Generated, never
        published. Flaws in third-party components are refused.
      </p>
      {/* On the screen whose purpose is publishing, "never published" and
          "could not be asked" are the two answers that must not look alike:
          the first is a reason to publish and the second is a reason not to
          until it is known. */}
      {gone.isError && (
        <p className="hint" style={{ color: "var(--sev-high)" }}>
          What has already gone out could not be read, so this cannot say whether it has been
          published before.
        </p>
      )}
      {(gone.data?.items ?? []).length > 0 && (
        <p className="hint">
          Published {(gone.data?.items ?? []).length}{" "}
          {(gone.data?.items ?? []).length === 1 ? "time" : "times"} for{" "}
          <span className="id">{product}</span> — last version{" "}
          {(gone.data?.items ?? [])[0]?.version} on {on((gone.data?.items ?? [])[0]?.issued_at)}. A
          draft that differs from the digest recorded then is how &ldquo;is what is published still
          what we generate&rdquo; gets an answer.
        </p>
      )}
      {open && (
        <>
          <div className="filters">
            <label className="field">
              <span>For</span>
              <select
                value={product}
                onChange={(event) => {
                  setProduct(event.target.value);
                  draft.reset();
                  record.reset();
                  setIssued(null);
                }}
              >
                {products.map((each) => (
                  <option key={each.name} value={each.name}>
                    {each.called}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="btn"
              disabled={!product || draft.isPending}
              onClick={() => draft.mutate(product)}
            >
              {draft.isPending ? "Drafting…" : "Draft the document"}
            </button>
            {document && (
              <a
                className="btn quiet"
                href={
                  `/v1/products/${encodeURIComponent(product)}` +
                  `/issues/${encodeURIComponent(vulnerability)}/advisory`
                }
              >
                JSON
              </a>
            )}
          </div>

          {draft.error != null && (
            <Failed error={draft.error} what="No advisory could be drafted for that." />
          )}

          {document && (
            <>
              {/* The tracking block is what a reader checks first: a document
              about an undisclosed flaw is a draft and says so, and reaching a
              disclosure date discloses nothing. */}
              <p className="hint">
                <span className="id">{document.document?.tracking?.id}</span> · version{" "}
                {document.document?.tracking?.version} · {document.document?.tracking?.status}
              </p>
              <pre className="asis" style={{ maxHeight: 320, overflow: "auto" }}>
                {written}
              </pre>
              <div className="filters" style={{ marginTop: 10 }}>
                <label className="field" style={{ flex: 1, minWidth: 240 }}>
                  <span>What this revision says</span>
                  <input
                    type="text"
                    value={summary}
                    placeholder="for the revision history"
                    onChange={(event) => setSummary(event.target.value)}
                  />
                </label>
                <button
                  type="button"
                  className="btn quiet"
                  disabled={record.isPending}
                  onClick={() => record.mutate(product)}
                >
                  {record.isPending ? "Recording…" : "Record that it went out"}
                </button>
              </div>
              <p className="hint">
                Recorded here, published elsewhere. What went out cannot be rebuilt later, and a
                revision needs the record of the first.
              </p>
              {record.error != null && (
                <Failed error={record.error} what="That could not be recorded." />
              )}
              {issued && (
                <div className="alert info">
                  <strong>Recorded as version {issued.version}</strong>
                  <span>
                    Digest <span className="id">{issued.digest}</span>. A later draft that differs
                    shows the published document has gone stale.
                  </span>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
