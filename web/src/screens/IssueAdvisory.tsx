import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";

// Starting an advisory about this flaw, generating it, and recording that it
// went out.
//
// Both endpoints answered and nothing called them. The document a customer
// receives could be produced by the API and by nothing a person can reach, so
// the one output of this tool that leaves the company was the one output
// nobody here could make.
//
// An advisory is a record of its own under a name this deployment mints, and
// it covers issues rather than being derived from one. What this screen does
// is the narrow case that starts from a flaw: start one, name this flaw in
// this product on it, and it is an ordinary advisory from there. Which is why
// it lists the ones that already cover this flaw — the question before
// starting another is whether one already says it.
//
// Refused for a flaw in somebody else's component, which is dependency
// hygiene a consumer reads out of the inventory — and refused when the issue
// is named rather than when the document is generated, so the refusal names
// what somebody chose.
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
  // The advisory being worked on. Held here because an advisory is started
  // and then filled in, and the two are separate acts against separate names.
  const [advisory, setAdvisory] = useState("");
  // Folded until somebody asks. An advisory is about a flaw in something this
  // deployment ships, and most issues on this screen are a scanner's report
  // about somebody else's component — so asking about every one of them on
  // every visit is a refused request per page load, which is noise in a
  // console and work nobody wanted done.
  const [open, setOpen] = useState(false);

  // The advisories that already cover this flaw here, without generating
  // anything. The question before starting another is whether one already
  // says it.
  const already = useQuery({
    enabled: open && product !== "",
    queryKey: ["advisories", product, vulnerability],
    queryFn: async () =>
      unwrap(await api.GET("/v1/advisories", { params: { query: { product, vulnerability } } })),
    retry: false,
  });

  // Two requests, because they are two acts: a name is minted, and then what
  // it covers is stated. Folded into one, starting an advisory and deciding
  // what it is about would be the same moment — which is the key this is
  // keyed away from.
  const draft = useMutation({
    mutationFn: async (of: string) => {
      // The one already started, where a previous attempt got that far. A
      // name is minted before anything knows the flaw may be named on it, and
      // most issues on this screen are a scanner's report about somebody
      // else's component — which the add refuses. Minting again on each
      // attempt spends a number out of the year's sequence that nothing
      // removes, and the sequence is visible in the identifiers that do go
      // out.
      //
      // No title. What an advisory is called is a decision somebody makes
      // about a document, and the flaw's identifier is not one — sent here it
      // would title a two-flaw document after whichever flaw started it,
      // which is what the server's fallback exists to avoid.
      let name = advisory;
      if (name === "") {
        const started = await unwrap(await api.POST("/v1/advisories", { body: {} }));
        name = started.advisory;
      }
      try {
        await unwrap(
          await api.POST("/v1/advisories/{advisory}/issues", {
            params: { path: { advisory: name } },
            body: { product: of, vulnerability },
          }),
        );
      } catch (failed) {
        setAdvisory(name);
        throw failed;
      }
      const document = await unwrap(
        await api.GET("/v1/advisories/{advisory}/document", {
          params: { path: { advisory: name } },
        }),
      );
      return { name, document };
    },
    onSuccess: (made) => {
      setAdvisory(made.name);
      void already.refetch();
    },
  });
  // Agreeing to what the advisory says, which is what publishing asks for.
  // Whoever started it may not, and neither may whoever wrote the words
  // standing, so the refusal is the ordinary answer here rather than a fault.
  const agree = useMutation({
    mutationFn: async (of: string) =>
      unwrap(
        await api.POST("/v1/advisories/{advisory}/approval", {
          params: { path: { advisory: of } },
        }),
      ),
  });
  const record = useMutation({
    mutationFn: async (of: string) =>
      unwrap(
        await api.POST("/v1/advisories/{advisory}/issuance", {
          params: { path: { advisory: of } },
          body: { ...(summary.trim() ? { summary: summary.trim() } : {}) },
        }),
      ),
    onSuccess: (done) => {
      setIssued(done);
      setSummary("");
      void already.refetch();
    },
  });

  const document = draft.data?.document;
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
      {already.isError && (
        <p className="hint" style={{ color: "var(--sev-high)" }}>
          The advisories covering this could not be read, so this cannot say whether one already
          says it.
        </p>
      )}
      {(already.data?.items ?? []).length > 0 && (
        <p className="hint">
          Already covered by{" "}
          {(already.data?.items ?? []).map((one, at) => (
            <span key={one.advisory}>
              {at > 0 && ", "}
              <span className="id">{one.advisory}</span>
              {` (${one.status})`}
              {(one.issuances ?? 0) > 0 && ` · out ${one.issuances}\u00d7`}
            </span>
          ))}
          . Starting another says it twice.
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
                  setAdvisory("");
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
              {draft.isPending ? "Starting…" : "Start an advisory"}
            </button>
            {document && advisory !== "" && (
              <a
                className="btn quiet"
                href={`/v1/advisories/${encodeURIComponent(advisory)}/document`}
              >
                JSON
              </a>
            )}
          </div>

          {draft.error != null && (
            <Failed error={draft.error} what="No advisory could be started for that." />
          )}

          {document && (
            <>
              {/* The tracking block is what a reader checks first. The status
              says where the document is in its life; how far it may travel is
              the distribution label, which is red while anything it covers is
              still held back. */}
              <p className="hint">
                <span className="id">{document.document?.tracking?.id}</span> · version{" "}
                {document.document?.tracking?.version} · {document.document?.tracking?.status}
              </p>
              <pre className="asis" style={{ maxHeight: 320, overflow: "auto" }}>
                {written}
              </pre>
              <div className="filters" style={{ marginTop: 10 }}>
                <label className="field" style={{ flex: 1, minWidth: 240 }}>
                  <span>This revision</span>
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
                  disabled={agree.isPending}
                  onClick={() => agree.mutate(advisory)}
                >
                  {agree.isPending ? "Agreeing…" : "Agree to what it says"}
                </button>
                <button
                  type="button"
                  className="btn quiet"
                  disabled={record.isPending}
                  onClick={() => record.mutate(advisory)}
                >
                  {record.isPending ? "Recording…" : "Record that it went out"}
                </button>
              </div>
              <p className="hint">
                A second person agrees to what it says before it goes out. You cannot agree to one
                you started or whose words you wrote.
              </p>
              {agree.error != null && (
                <Failed error={agree.error} what="That could not be agreed to." />
              )}
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
