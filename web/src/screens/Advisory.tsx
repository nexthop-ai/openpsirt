import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  type Covered,
  useAdvisory,
  useAdvisoryDocument,
  useAgree,
  useIssuances,
  useNameAFlaw,
  useRecordIssued,
  useRetitle,
  useTakeAFlawOff,
  useTakeAgreementBack,
} from "../api/advisories";
import { useCatalog } from "../api/catalog";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { notACredential } from "../ui/noautofill";
import { useReseed } from "../ui/reseed";
import { Wide } from "../ui/Wide";
import { on } from "../ui/when";
import { agreeing, missing, nameable, standing, statusLabel } from "./advisory";

// One advisory, whole: what it is called, what it covers, the document it
// generates, who agrees to it, and what has gone out.
//
// The four panels are the four acts in the order they happen — compose,
// review, approve, publish — because an advisory is the rare, deliberate
// document and the screen is for care rather than throughput. No bulk
// anything, and the review step is a person reading text.
//
// Who may agree is the store's rule and is enforced there. This screen knows
// how many people agree and not which, so the control is offered to whoever
// reaches it and the refusal is the server's own sentence.

export function Advisory() {
  const { advisory = "" } = useParams();
  const one = useAdvisory(advisory);
  const covers = one.data?.covers ?? [];
  const document = useAdvisoryDocument(advisory, covers.length);
  const issuances = useIssuances(advisory);

  if (one.isPending) return <Loading />;
  if (one.isError) return <Failed error={one.error} what="That advisory could not be read." />;

  const it = one.data;
  const agreed = it?.agreed ?? 0;
  const next = missing(covers.length, agreed);

  return (
    <>
      <nav aria-label="Breadcrumb" className="hint" style={{ marginBottom: 8 }}>
        <Link to="/advisories">Advisories</Link> / {advisory}
      </nav>

      <div className="screen-head">
        <h2>
          <span className="id">{advisory}</span>{" "}
          <span
            className={`state ${standing(it?.status)?.tone ?? ""}`}
            title={standing(it?.status)?.means}
          >
            {statusLabel(it?.status)}
          </span>
        </h2>
        <p>
          {it?.title || "Untitled"} · started {on(it?.minted_at)}
        </p>
      </div>

      {/* What is left before it can go out. Said once, at the top, rather
          than as a warning on each panel that is waiting on something. */}
      {next === "flaws" && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>Names no flaw</strong>
          <span>It generates no document until one is named.</span>
        </div>
      )}
      {next === "agreement" && (
        <div className="alert" style={{ marginBottom: 12 }}>
          <strong>Nobody has agreed to what it says</strong>
          <span>A second person agrees before it goes out.</span>
        </div>
      )}

      <Says advisory={advisory} title={it?.title ?? ""} covers={covers} />
      <Document advisory={advisory} covers={covers.length} read={document} />
      <Agreement advisory={advisory} agreed={agreed} />
      <Issued advisory={advisory} read={issuances} agreed={agreed} />
    </>
  );
}

// The title, as a row of the compose panel. Left empty the document names the
// flaws it covers.
function Title({ advisory, title }: { advisory: string; title: string }) {
  const [words, setWords] = useState(title);
  // Seeded once, the field keeps the old text with Save live, and pressing
  // Save writes the old title back — which opens an edition and takes back
  // every agreement standing.
  useReseed(title, () => setWords(title));
  const retitle = useRetitle();

  return (
    <>
      <div className="filters">
        <label className="field" style={{ flex: 1, minWidth: 260 }}>
          <span>Title</span>
          <input
            type="text"
            value={words}
            placeholder="Left empty, the document names the flaws it covers"
            onChange={(event) => setWords(event.target.value)}
            {...notACredential}
          />
        </label>
        <button
          type="button"
          className="btn quiet"
          disabled={words === title || retitle.isPending}
          onClick={() => retitle.mutate({ advisory, title: words })}
        >
          {retitle.isPending ? "Saving…" : "Save"}
        </button>
      </div>
      <p className="hint">Saving takes back every agreement standing.</p>
      {retitle.isError && <Failed error={retitle.error} what="The title was not changed." />}
    </>
  );
}

// What the advisory says: the title, the flaws it names, and naming another.
//
// One panel, because the three are one act. Split, the title's own label sat
// under a heading of the same word.
function Says({ advisory, title, covers }: { title: string; advisory: string; covers: Covered[] }) {
  const [product, setProduct] = useState("");
  const [flaw, setFlaw] = useState("");
  const name = useNameAFlaw();
  const takeOff = useTakeAFlawOff();
  const catalog = useCatalog(true);

  // The flaws recorded in the chosen product. One row per issue and
  // component, so the list is folded to distinct issues, and what this
  // advisory already names there is left out.
  //
  // Asked across every branch and tag and both states of support: a flaw is
  // recorded against whichever build somebody found it in, and the list's own
  // defaults would hide one recorded against a tag or a release past its end
  // of life.
  const recorded = useQuery({
    enabled: product !== "",
    queryKey: ["advisory-flaws", product],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/findings", {
          params: {
            path: { product },
            query: {
              origin: "manual",
              on: ["branch", "tag"],
              support: ["in-support", "past-eol"],
              below_floor: true,
              limit: 200,
            },
          },
        }),
      ),
  });
  const offered = useMemo(
    () => nameable(recorded.data?.items ?? [], covers, product),
    [recorded.data, covers, product],
  );

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3>What it says</h3>
      <Title advisory={advisory} title={title} />
      {covers.length === 0 ? (
        <p className="hint">None named yet.</p>
      ) : (
        <Wide style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Flaw</th>
                <th>Product</th>
                <th>Named</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {covers.map((row) => (
                <tr key={`${row.product} ${row.vulnerability}`} className="row">
                  <td>
                    <Link className="id" to={`/issues/${encodeURIComponent(row.vulnerability)}`}>
                      {row.vulnerability}
                    </Link>
                    {row.summary && <div className="hint">{row.summary}</div>}
                  </td>
                  <td>{row.product_name || row.product}</td>
                  <td className="hint">{on(row.added_at)}</td>
                  <td>
                    <button
                      type="button"
                      className="linkish"
                      // The same cost the title carries, on the thing it is
                      // about: taking a flaw off opens an edition.
                      title="Takes back every agreement standing"
                      disabled={takeOff.isPending}
                      onClick={() =>
                        takeOff.mutate({
                          advisory,
                          product: row.product,
                          vulnerability: row.vulnerability,
                        })
                      }
                    >
                      Take off
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}
      {takeOff.isError && <Failed error={takeOff.error} what="That flaw was not taken off." />}

      <div className="filters" style={{ marginTop: 10 }}>
        <label className="field">
          <span>Product</span>
          <select
            value={product}
            onChange={(event) => {
              setProduct(event.target.value);
              setFlaw("");
              name.reset();
            }}
          >
            {/* A read that failed says so in the one place somebody is
                looking. A select holding nothing but "Pick a product" reads
                as a deployment with no products in it. */}
            <option value="">
              {catalog.products.isError ? "The products could not be read" : "Pick a product"}
            </option>
            {(catalog.products.data?.items ?? []).map((each) => (
              <option key={each.name} value={each.name}>
                {each.display_name || each.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field" style={{ flex: 1, minWidth: 220 }}>
          <span>Flaw</span>
          {/* Typed as well as picked. The list is what this deployment has
              recorded in that product, and an identifier that is not in it —
              because the read failed, or because it sits somewhere the list
              does not reach — is still what the server decides about. */}
          <input
            type="text"
            list="advisory-flaws"
            value={flaw}
            placeholder="CVE-2026-0001"
            onChange={(event) => setFlaw(event.target.value)}
            {...notACredential}
          />
          <datalist id="advisory-flaws">
            {offered.map((each) => (
              <option key={each.vulnerability} value={each.vulnerability}>
                {each.summary}
              </option>
            ))}
          </datalist>
        </label>
        <button
          type="button"
          className="btn"
          disabled={!product || !flaw.trim() || name.isPending}
          onClick={() =>
            name.mutate(
              { advisory, product, vulnerability: flaw.trim() },
              { onSuccess: () => setFlaw("") },
            )
          }
        >
          {name.isPending ? "Naming…" : "Name it"}
        </button>
      </div>
      {/* The read stops at the endpoint's own maximum, and folding to
          distinct issues hides how close it came — so a truncated list reads
          as the whole of what is recorded there. Typing reaches the rest. */}
      {(recorded.data?.total ?? 0) > (recorded.data?.items ?? []).length && (
        <p className="hint">
          More is recorded in that product than this list holds. Type the identifier in full.
        </p>
      )}
      {/* A failed read is not an answer about what is recorded here. Drawn as
          an empty list it reads as "this product has none", which is the one
          thing the read did not say. */}
      {catalog.products.isError && (
        <Failed
          error={catalog.products.error}
          what="The products could not be read, so there is none to pick."
        />
      )}
      {recorded.isError && (
        <Failed
          error={recorded.error}
          what="What is recorded in that product could not be read, so there is nothing to pick from. An identifier typed in full still works."
        />
      )}
      <p className="hint">
        Only a flaw recorded here. Naming one, and taking one off, each take back every agreement
        standing.
      </p>
      {name.isError && (
        <Failed error={name.error} what="That flaw was not named on this advisory." />
      )}
    </div>
  );
}

// The CSAF document, shown as text and never rendered.
function Document({
  advisory,
  covers,
  read,
}: {
  advisory: string;
  covers: number;
  read: ReturnType<typeof useAdvisoryDocument>;
}) {
  const written = useMemo(() => (read.data ? JSON.stringify(read.data, null, 2) : ""), [read.data]);
  const tracking = read.data?.document?.tracking;

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3>Document</h3>
      {covers === 0 ? (
        <p className="hint">Name a flaw and the document appears here.</p>
      ) : read.isPending ? (
        <Loading inline />
      ) : read.isError ? (
        <Failed error={read.error} what="The document could not be generated." />
      ) : (
        <>
          {/* What a reader checks first. The status says where the document
              is in its life; how far it may travel is the distribution
              label, red while anything it covers is still held back. */}
          <p className="hint">
            <span className="id">{tracking?.id}</span> · version {tracking?.version} ·{" "}
            {tracking?.status} ·{" "}
            <span title="How far the document may travel. Red while anything it covers is still held back">
              {read.data?.document?.distribution?.tlp?.label}
            </span>{" "}
            · <a href={`/v1/advisories/${encodeURIComponent(advisory)}/document`}>JSON</a>
          </p>
          <pre className="asis" style={{ maxHeight: 420, overflow: "auto", marginBottom: 10 }}>
            {written}
          </pre>
          <p className="hint">Generated, never sent.</p>
        </>
      )}
    </div>
  );
}

// Who agrees to what it says now.
function Agreement({ advisory, agreed }: { advisory: string; agreed: number }) {
  const agree = useAgree();
  const back = useTakeAgreementBack();

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3>Agreement</h3>
      <p>{agreeing(agreed)} to what it says now.</p>
      <div className="actions">
        <button
          type="button"
          className="btn"
          title="Not the person who started it, and not whoever wrote what it says now. There is no override"
          disabled={agree.isPending}
          onClick={() => agree.mutate({ advisory })}
        >
          {agree.isPending ? "Agreeing…" : "Agree to what it says"}
        </button>
        <button
          type="button"
          className="btn quiet"
          title="Everybody's, not only your own"
          disabled={agreed === 0 || back.isPending}
          onClick={() => back.mutate({ advisory })}
        >
          {back.isPending ? "Taking back…" : "Take every agreement back"}
        </button>
      </div>
      {agree.isError && <Failed error={agree.error} what="That was not agreed to." />}
      {back.isError && <Failed error={back.error} what="Nothing was taken back." />}
    </div>
  );
}

// What has gone out, and recording another.
function Issued({
  advisory,
  read,
  agreed,
}: {
  advisory: string;
  read: ReturnType<typeof useIssuances>;
  agreed: number;
}) {
  const [summary, setSummary] = useState("");
  const record = useRecordIssued();
  const gone = read.data?.items ?? [];

  return (
    <div className="card">
      <h3>What has gone out</h3>
      {read.isPending ? (
        <Loading inline />
      ) : read.isError ? (
        <Failed error={read.error} what="What has gone out could not be read." />
      ) : gone.length === 0 ? (
        <p className="hint">It has not gone out.</p>
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th className="num">Version</th>
                <th>Published</th>
                <th>This revision</th>
                <th>Digest</th>
              </tr>
            </thead>
            <tbody>
              {gone.map((row) => (
                <tr key={row.version} className="row">
                  <td className="num">{row.version}</td>
                  <td className="hint">{on(row.issued_at)}</td>
                  <td>{row.summary}</td>
                  <td className="id">{row.digest}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      <div className="filters" style={{ marginTop: 10 }}>
        <label className="field" style={{ flex: 1, minWidth: 240 }}>
          <span>This revision</span>
          <input
            type="text"
            value={summary}
            placeholder="What changed, for the revision history"
            onChange={(event) => setSummary(event.target.value)}
            {...notACredential}
          />
        </label>
        <button
          type="button"
          className="btn"
          disabled={agreed === 0 || record.isPending}
          onClick={() =>
            record.mutate(
              { advisory, summary: summary.trim() },
              { onSuccess: () => setSummary("") },
            )
          }
        >
          {record.isPending ? "Recording…" : "Record that it went out"}
        </button>
      </div>
      <p className="hint">Recorded here, published elsewhere.</p>
      {record.isError && <Failed error={record.error} what="That was not recorded." />}
    </div>
  );
}
