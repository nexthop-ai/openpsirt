import { notACredential } from "../ui/noautofill";
import { RECORDABLE } from "../ui/severities";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { at as choicesAt, unwrap } from "../api/queries";
import { useScope } from "../app/scope";
import { mayOf, useWho } from "../app/session";
import { Editor, mentioning } from "../ui/Editor";
import { Suggest } from "../ui/Suggest";
import { Failed } from "../ui/Failed";
import { useReseed } from "../ui/reseed";
import { Scoring } from "../ui/Scoring";
import { Weaknesses } from "../ui/Weaknesses";

// Recording a flaw in what we ship: a vulnerability no scanner reported,
// usually because nobody outside knows about it yet.
//
// A screen of its own rather than an action on a list. What is being
// recorded is precisely what is *not* in the findings list, so opening it from
// there asks somebody to start where the answer is absent. It also needs more
// asked of it than a control beside a table has room for — which build, which
// component, how bad, and who knows — and each of those is a question somebody
// can get wrong quietly.
//
// The scope prefills it and does not constrain it: somebody arriving from a
// build they were reading should not retype it, and somebody arriving from the
// rail should not have to go and pick one first.

// The severities a person may record. The same words a report carries, so a
// finding somebody typed ranks and expires beside the ones a scanner found
// rather than in a scheme of its own.
const SEVERITIES = RECORDABLE;

export function Record() {
  const scope = useScope();
  const who = useWho();
  const navigate = useNavigate();
  const queries = useQueryClient();

  const [product, setProduct] = useState(scope.product ?? "");
  // The lines, and the ways they are built. Both are sets: the same code
  // goes out on several lines and as several variants at once, and a flaw in
  // it is one issue in every build that ships it. The builds are the product
  // of the two, and the ones that do not exist are simply not offered.
  const [streams, setStreams] = useState<string[]>(scope.stream ? [scope.stream] : []);
  const [variants, setVariants] = useState<string[]>(scope.variant ? [scope.variant] : []);
  const [summary, setSummary] = useState("");
  const [severity, setSeverity] = useState("");
  const [component, setComponent] = useState("");
  // Only ever set by picking one of the choices a refusal offered. Asking for
  // a version up front would ask everybody to answer a question that arises
  // for a handful of names in a build.
  const [version, setVersion] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  // The button somebody pressed, and nothing until they press one. The
  // value that is read is worked out below, because what is on offer depends
  // on a right that is not known until the session is.
  const [chose, setChose] = useState<boolean | null>(null);
  const [vector, setVector] = useState("");
  // Files that prove it — a test case, a capture, a screenshot. Held until the
  // finding exists, because an attachment hangs off an issue and there is no
  // issue until this is recorded. Who told us, where somebody did. All
  // optional: a flaw found by whoever is typing has no reporter, and a form
  // demanding one asks them to invent an answer.
  const [reportedBy, setReportedBy] = useState("");
  const [contact, setContact] = useState("");
  const [credit, setCredit] = useState("");
  const [received, setReceived] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [refused, setRefused] = useState<string[]>([]);
  // The address of the finding just recorded, held while somebody reads
  // which of their files did not attach.
  const [onward, setOnward] = useState("");
  const [weaknesses, setWeaknesses] = useState<string[]>([]);

  const may = mayOf(who.data, product);
  // Recording something nobody has announced is triage work on undisclosed
  // findings, and that is the right it asks for. Somebody who may argue about
  // known issues in shipped components has not been given the undisclosed
  // ones, and may still record one that is already public.
  const mayHide = !!may?.may_hide;
  const mayRecord = mayHide || !!may?.may_triage;
  const whole = product !== "" && streams.length > 0 && variants.length > 0;

  // Defaulting to undisclosed unless the person cannot record one, which is
  // the case this exists for. Defaulting the other way makes the dangerous
  // mistake the quiet one.
  //
  // Worked out rather than stored, so there is no frame in which the form is
  // drawn one way and corrected to the other once the session has loaded: for
  // somebody who may not hide a flaw, disclosed is the only answer there is,
  // and the control that would say otherwise is disabled.
  const disclosed = mayHide ? (chose ?? false) : true;
  // The choice is about a flaw in this product, so changing the product unmakes
  // it and the default falls back to whatever the new one's rights allow. A
  // choice that carried across would carry "public" onto a product where
  // undisclosed is the default, which is the quiet dangerous mistake again.
  useReseed(product, () => setChose(null));

  const products = useQuery({
    queryKey: ["products"],
    queryFn: async () => unwrap(await api.GET("/v1/products", {})),
  });
  const lines = useQuery({
    queryKey: ["streams", product],
    enabled: product !== "",
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/streams", { params: { path: { product } } })),
  });
  // The variants the product is built as, rather than one line's own. A variant
  // belongs to the product, so with several lines chosen this is the set to
  // pick from — a per-line list would be an arbitrary one of them.
  const builtAs = useQuery({
    queryKey: ["variants", product],
    enabled: product !== "",
    queryFn: async () =>
      unwrap(await api.GET("/v1/products/{product}/variants", { params: { path: { product } } })),
  });

  // The components the build holds, to offer back as they type. A name typed
  // from memory is a name the server refuses, and a build holds thousands of
  // components, so the list is searched rather than loaded.
  const holding = useQuery({
    queryKey: ["components", product, streams[0], variants[0], component],
    enabled: whole && component.trim().length >= 2,
    // Offered from the first build chosen. The name has to exist in every one
    // of them — the server refuses otherwise, naming the build that does not
    // hold it — and offering the union would suggest names that will be
    // refused.
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/components", {
          params: {
            path: { product, stream: streams[0] ?? "", variant: variants[0] ?? "" },
            query: { q: component.trim(), limit: 20 },
          },
        }),
      ),
  });

  const record = useMutation({
    mutationFn: async () => {
      const made = unwrap(
        await api.POST("/v1/products/{product}/findings", {
          params: { path: { product } },
          body: {
            builds: streams.flatMap((s) => variants.map((v) => ({ stream: s, variant: v }))),
            summary: summary.trim(),
            // Left out rather than sent empty. "Not worked out yet" is the
            // absence of the field, and an empty string is a value the
            // endpoint's list of severities does not contain.
            ...(severity ? { severity: severity as (typeof SEVERITIES)[number] } : {}),
            ...(component.trim() ? { component: component.trim() } : {}),
            ...(reportedBy.trim() ? { reported_by: reportedBy.trim() } : {}),
            ...(contact.trim() ? { contact: contact.trim() } : {}),
            ...(credit.trim() ? { credit: credit.trim() } : {}),
            ...(received ? { received } : {}),
            ...(version ? { version } : {}),
            ...(ecosystem ? { ecosystem } : {}),
            ...(vector ? { vector } : {}),
            ...(weaknesses.length > 0 ? { weaknesses } : {}),
            ...(disclosed ? { disclosed: true } : {}),
          },
        }),
      );
      // The files after the finding, because an attachment hangs off an issue
      // and the issue is what was just minted. A file that will not store does
      // not undo the record: the words are the finding and the attachment is
      // evidence for them, so what is reported is which file failed.
      const failed: string[] = [];
      for (const file of files) {
        const form = new FormData();
        form.append("file", file);
        // It hangs off the issue rather than off text somebody is about to
        // write, so it is listed at once and never swept.
        form.append("evidence", "true");
        try {
          unwrap(
            await api.POST("/v1/products/{product}/issues/{vulnerability}/attachments", {
              params: { path: { product, vulnerability: made.identifier } },
              body: form as never,
              bodySerializer: (body: unknown) => body as FormData,
            }),
          );
        } catch {
          failed.push(file.name);
        }
      }
      return { made, failed };
    },
    onSuccess: ({ made, failed }) => {
      void queries.invalidateQueries({ queryKey: ["findings"] });
      void queries.invalidateQueries({ queryKey: ["disclosing"] });
      setRefused(failed);
      // Onto the first build it landed in. From here it behaves like any
      // other finding, and the next thing somebody does with a flaw they have
      // just recorded is work on it. They are the same finding whichever build
      // is opened, and the screen says how many builds hold it.
      const onward =
        `/products/${encodeURIComponent(product)}/streams/${encodeURIComponent(streams[0] ?? "")}` +
        `/variants/${encodeURIComponent(variants[0] ?? "")}/findings/` +
        `${encodeURIComponent(made.identifier)}/components/` +
        `${encodeURIComponent(made.component)}` +
        (version ? `?version=${encodeURIComponent(version)}` : "");
      // Unless a file was refused. Navigating in the same commit that writes
      // the warning puts it on a screen that is already unmounting, so the
      // files that did not attach are lost in silence. Staying put is what
      // makes it readable, and the way onward is offered beside it.
      if (failed.length > 0) {
        setOnward(onward);
        return;
      }
      navigate(onward);
    },
  });

  // A name the build holds at more than one version is a question, not a
  // failure: the server refuses and says which, so this offers them back
  // rather than choosing. Picking one is the whole of the answer.
  const choices = choicesAt(record.error, "component");
  // A summary and a build. Not a severity: a flaw may be recorded before
  // anybody has worked out how bad it is, and making somebody pick a word to
  // get the record written is how a guess ends up stored as a judgment.
  const ready = whole && summary.trim() !== "" && !record.isPending;

  return (
    <>
      <div className="screen-head">
        <h2>Record a flaw</h2>
        <p>
          A vulnerability no scanner reported. Filed under an identifier this deployment mints, then
          triaged like any other finding.
        </p>
        {/* What was recorded here before. The screen that files one is where
            somebody asks whether it is already filed, and the answer was a
            findings list with no way to ask for the kind. */}
        {scope.product && (
          <span style={{ marginLeft: "auto" }}>
            <Link
              className="btn quiet"
              to={`/products/${encodeURIComponent(scope.product)}/findings?origin=manual&below=yes`}
            >
              What has been recorded here
            </Link>
          </span>
        )}
      </div>

      <div className="panel" style={{ maxWidth: "80ch" }}>
        <h3>Builds</h3>
        <p className="hint">A flaw is recorded against one build, so all three are required.</p>
        <div className="fields">
          <div className="field">
            <label htmlFor="rec-product">Product</label>
            <select
              id="rec-product"
              {...notACredential}
              value={product}
              onChange={(event) => {
                setProduct(event.target.value);
                setStreams([]);
                setVariants([]);
                setComponent("");
              }}
            >
              <option value="">Pick one</option>
              {(products.data?.items ?? []).map((each) => (
                <option key={each.name} value={each.name ?? ""}>
                  {each.display_name || each.name}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <span className="l">Branches and tags</span>
            <Picked
              options={(lines.data?.items ?? []).map((each) => ({
                value: each.name ?? "",
                label: each.kind === "tag" ? `${each.name} (tag)` : (each.name ?? ""),
              }))}
              chosen={streams}
              disabled={product === ""}
              empty={product === "" ? "Pick a product first" : "Nothing is declared here yet"}
              onChange={(next) => {
                setStreams(next);
                setComponent("");
              }}
            />
          </div>
          <div className="field">
            <span className="l">Built as</span>
            <Picked
              options={(builtAs.data?.items ?? []).map((each) => ({
                value: each.name ?? "",
                label: each.name ?? "",
              }))}
              chosen={variants}
              disabled={product === ""}
              empty={product === "" ? "Pick a product first" : "Nothing is declared here yet"}
              onChange={(next) => {
                setVariants(next);
                setComponent("");
              }}
            />
          </div>
        </div>
      </div>

      {product !== "" && !mayRecord && (
        <div className="alert" style={{ maxWidth: "80ch", marginTop: 14 }}>
          <strong>Not yours to record</strong>
          <span>
            Recording a flaw is triage work on {product}, and you hold no triage role there.
          </span>
        </div>
      )}

      <div className="panel" style={{ maxWidth: "80ch", marginTop: 14 }}>
        <h3>Description</h3>

        <div className="field">
          <label htmlFor="rec-summary">
            What the flaw is{" "}
            <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--sev-high)" }}>
              required
            </span>
          </label>
          {/* The same editor and the same submission policy as a
              justification. What somebody writes here is our own prose — it is
              rendered as markdown where it is read back, which is why it is
              written as markdown here. */}
          <Editor
            value={summary}
            onChange={setSummary}
            draftKey={`record:${product}`}
            rows={6}
            label="What the flaw is"
            placeholder="The management socket answers a request before anyone has authenticated."
            mentions={mentioning(product, !disclosed)}
          />
          <span className="hint">What a triager reads first.</span>
        </div>

        <div className="field">
          <label htmlFor="rec-severity">Severity</label>
          <select
            id="rec-severity"
            {...notACredential}
            value={severity}
            disabled={vector !== ""}
            onChange={(event) => setSeverity(event.target.value)}
          >
            {/* No default. A severity nobody chose, sitting in the field as
                though somebody had, is a judgment this screen would be making
                on their behalf. */}
            <option value="">Not rated</option>
            {SEVERITIES.map((word) => (
              <option key={word} value={word}>
                {word}
              </option>
            ))}
          </select>
          <span className="hint">
            The same words a scanner's findings carry, so this ranks and comes due beside them.
            {vector !== "" ? (
              <> Set by the vector below.</>
            ) : (
              <>
                {" "}
                Leave it unset during early triage; it comes due as a medium until somebody rates
                it, which is what every unrated finding does.
              </>
            )}
          </span>
        </div>

        <div className="field">
          <label htmlFor="rec-component">What carries it</label>
          {/* Shown as a list rather than left to the browser's datalist, which
              has no affordance at all: no arrow, nothing until two characters,
              and nothing to say whether anything matched. This is the input in
              the tool most likely to be wrong — a name typed from memory
              against thousands — and the refusal afterwards was the only place
              anybody found out.

              Names, not name-and-version rows: a name the build holds three
              times would otherwise offer the same value three times, and which
              of the three is meant is the question the refusal asks properly. */}
          <Suggest
            id="rec-component"
            value={component}
            disabled={!whole}
            placeholder={whole ? "the build itself" : "pick a build first"}
            loading={holding.isFetching}
            options={[...new Set((holding.data?.items ?? []).map((each) => each.component ?? ""))]}
            onChange={(next) => {
              setComponent(next);
              setVersion("");
              setEcosystem("");
            }}
          />
          <span className="hint">
            As the build calls it, searched against what that build actually holds. Leave it empty
            for the build itself, which is the honest answer where the flaw is in how the pieces fit
            together rather than in one of them.
            {version && (
              <>
                {" "}
                Recording against <b>{version}</b>
                {ecosystem && <> ({ecosystem})</>}.
              </>
            )}
          </span>
        </div>

        {choices.length > 0 && (
          <div className="alert">
            <strong>Which {component}?</strong>
            <span>Shipped as more than one component here. Pick the one that carries it.</span>
            <ul className="refs" style={{ marginTop: 8 }}>
              {choices.map((choice) => (
                <li key={`${choice.version} ${choice.ecosystem ?? ""}`}>
                  <button
                    type="button"
                    className="chip"
                    aria-pressed={
                      version === choice.version && ecosystem === (choice.ecosystem ?? "")
                    }
                    onClick={() => {
                      setVersion(choice.version);
                      setEcosystem(choice.ecosystem ?? "");
                      record.reset();
                    }}
                  >
                    {choice.version}
                  </button>
                  {choice.ecosystem && <span className="hint">{choice.ecosystem}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}

        <Scoring vector={vector} onChange={setVector} />

        <div className="field">
          <label htmlFor="rec-files">What proves it</label>
          <p className="hint" style={{ marginTop: 0 }}>
            Optional. Readable by whoever can read the issue, so an undisclosed flaw&rsquo;s
            evidence is undisclosed too.
          </p>
          <input
            id="rec-files"
            type="file"
            multiple
            onChange={(event) => setFiles(Array.from(event.target.files ?? []))}
          />
          {files.length > 0 && (
            <ul className="refs" style={{ marginTop: 8 }}>
              {files.map((file) => (
                <li key={file.name}>
                  <span className="chip">{file.name}</span>
                  <span className="hint">{Math.max(1, Math.round(file.size / 1024))} KB</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <Weaknesses chosen={weaknesses} onChange={setWeaknesses} />

        <div className="field">
          <span className="l">Disclosure</span>
          <div className="seg">
            <button
              type="button"
              aria-pressed={!disclosed}
              disabled={!mayHide}
              onClick={() => setChose(false)}
            >
              Undisclosed
            </button>
            <button type="button" aria-pressed={disclosed} onClick={() => setChose(true)}>
              Public
            </button>
          </div>
          {/* Why the first one cannot be picked, in the open. It was a
              tooltip on a disabled button, which is the shape that reads as a
              broken control rather than as a right somebody does not hold —
              nothing about a grayed button says whether it is unavailable
              here, unavailable now, or unavailable to you. */}
          {!mayHide && (
            <span className="hint">
              Recording an undisclosed flaw needs the private triage role here. Without it, this is
              public once saved.
            </span>
          )}
          <span className="hint">
            {disclosed ? (
              <>Already disclosed, so no embargo.</>
            ) : (
              <>
                Starts undisclosed with a disclosure date. Reaching it escalates rather than
                publishes.
              </>
            )}
          </span>
        </div>

        {/* Who told us. Every field optional: a flaw we found
            ourselves has no reporter, and the two that do work beyond the
            record say so where they are typed — the day it arrived is what
            the embargo runs from, and how they wish to be credited is what an
            advisory's acknowledgments say. */}
        <div className="field">
          <span className="l">Who told us</span>
          <span className="hint" style={{ marginBottom: 6 }}>
            Optional. Only where somebody outside reported it.
          </span>
          <div className="filters">
            <label className="field" style={{ margin: 0 }}>
              <span>Reported by</span>
              <input
                {...notACredential}
                type="text"
                value={reportedBy}
                placeholder="as they gave their name"
                onChange={(event) => setReportedBy(event.target.value)}
              />
            </label>
            <label className="field" style={{ margin: 0 }}>
              <span>How to reach them</span>
              <input
                {...notACredential}
                type="text"
                value={contact}
                placeholder="an address"
                onChange={(event) => setContact(event.target.value)}
              />
            </label>
            <label className="field" style={{ margin: 0 }}>
              <span>Credited as</span>
              <input
                {...notACredential}
                type="text"
                value={credit}
                placeholder="where it differs; anonymous is an answer"
                onChange={(event) => setCredit(event.target.value)}
              />
            </label>
            <label className="field" style={{ margin: 0 }}>
              <span>Arrived on</span>
              <input
                {...notACredential}
                type="date"
                style={{ width: 180 }}
                value={received}
                onChange={(event) => setReceived(event.target.value)}
              />
            </label>
          </div>
          {!disclosed && (
            <span className="hint">
              The embargo is counted from the day it arrived rather than from today: they are
              counting from the day they sent it, and they are the party who will publish
              regardless.
              {received && (
                <>
                  {" "}
                  Ninety days from <b>{received}</b> unless this deployment says otherwise.
                </>
              )}
            </span>
          )}
        </div>

        {record.error != null && choices.length === 0 && (
          <Failed error={record.error} what="That could not be recorded." />
        )}

        {refused.length > 0 && (
          <div className="alert">
            <strong>The flaw was recorded and some files were not</strong>
            <span>
              {refused.join(", ")} could not be stored. The record stands — attach them again from
              the finding.
            </span>
            {onward && (
              <Link className="linkish" to={onward}>
                Open the finding
              </Link>
            )}
          </div>
        )}

        <div className="actions" style={{ marginTop: 8 }}>
          <button
            type="button"
            className="btn"
            disabled={!ready || !mayRecord}
            onClick={() => record.mutate()}
          >
            {record.isPending ? "Recording…" : disclosed ? "Record" : "Record, undisclosed"}
          </button>
          {whole ? (
            <span className="hint">
              Against {streams.length * variants.length}{" "}
              {streams.length * variants.length === 1 ? "build" : "builds"} — one issue, and one
              finding for each place the component sits at in each of them. A build that does not
              hold the component is refused rather than skipped, so deselect it if research says it
              is not affected.
            </span>
          ) : (
            <span className="hint">
              Pick a product, then at least one line and at least one variant.
            </span>
          )}
        </div>
      </div>
    </>
  );
}

// A set of things, chosen by ticking. Not a multiple-select box: those are
// famously hard to use with a mouse and impossible to see the state of at a
// glance, and what somebody needs here is to read back which builds they are
// about to file against.
function Picked({
  options,
  chosen,
  disabled,
  empty,
  onChange,
}: {
  options: { value: string; label: string }[];
  chosen: string[];
  disabled?: boolean;
  empty: string;
  onChange: (next: string[]) => void;
}) {
  if (disabled || options.length === 0) {
    return <span className="hint">{empty}</span>;
  }
  return (
    <>
      <ul className="ticks">
        {options.map((option) => (
          <li key={option.value}>
            <label>
              <input
                type="checkbox"
                checked={chosen.includes(option.value)}
                onChange={() =>
                  onChange(
                    chosen.includes(option.value)
                      ? chosen.filter((each) => each !== option.value)
                      : [...chosen, option.value],
                  )
                }
              />{" "}
              {option.label}
            </label>
          </li>
        ))}
      </ul>
      {options.length > 1 && (
        <button
          type="button"
          className="btn quiet"
          onClick={() =>
            onChange(chosen.length === options.length ? [] : options.map((o) => o.value))
          }
        >
          {chosen.length === options.length ? "None" : "All of them"}
        </button>
      )}
    </>
  );
}
