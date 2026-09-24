// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { notACredential } from "../ui/noautofill";
import { RECORDABLE } from "../ui/severities";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { uploadReportFile, useAfterReport, useRecordReport, useReport } from "../api/intake";
import { api } from "../api/client";
import { at as choicesAt, unwrap } from "../api/queries";
import { useScope } from "../app/scope";
import { mayOf, useWho } from "../app/session";
import { ChoiceCards } from "../ui/ChoiceCards";
import { Dropzone } from "../ui/Dropzone";
import { Editor, mentioning } from "../ui/Editor";
import { Suggest } from "../ui/Suggest";
import { Failed } from "../ui/Failed";
import { useReseed } from "../ui/reseed";
import { Scoring } from "../ui/Scoring";
import { Weaknesses } from "../ui/Weaknesses";

// Reporting a flaw in what we ship: one somebody outside sent, or one somebody
// here found. The one way in for both. What separates them is a single answer
// about where it came from, which decides the disclosure date and whether
// anybody is owed a reply.
//
// Filed as a report, it waits in the product's Inbox to be judged. Recorded as
// a flaw at once, it asks for what a flaw carries — the builds, the component,
// how bad — and is written with its report in the same act. The second is
// offered to whoever may judge reports, and it is the only path for somebody
// who may record a public flaw but may not work reports.
//
// Opened from a report, it records that report as a flaw.
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

  // A vulnerability report this flaw is the record of, where the form was
  // opened from one. It fixes the product, fills the summary from the claim,
  // and takes who reported it from the report rather than asking again.
  const [params] = useSearchParams();
  const fromReport = params.get("from") ?? "";
  // The product the link names, where it names one: the Inbox opens this with
  // its own product picked.
  const [product, setProduct] = useState(params.get("product") ?? scope.product ?? "");
  const report = useReport(fromReport ? product : "", fromReport);
  const afterReport = useAfterReport();
  // The lines, and the ways they are built. Both are sets: the same code
  // goes out on several lines and as several variants at once, and a flaw in
  // it is one issue in every build that ships it. The builds are the product
  // of the two, and the ones that do not exist are simply not offered.
  const [streams, setStreams] = useState<string[]>(scope.stream ? [scope.stream] : []);
  const [variants, setVariants] = useState<string[]>(scope.variant ? [scope.variant] : []);
  // Seeded from the claim where it is already cached, which is the ordinary
  // arrival from the report's own page. The reseed below covers a claim that
  // arrives after the form is drawn.
  const [summary, setSummary] = useState(report.data?.summary ?? "");
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
  // Who told us, or who found it here. All optional: a claim arriving
  // anonymously has no reporter, and a form demanding one asks them to invent
  // an answer.
  const [reportedBy, setReportedBy] = useState("");
  const [contact, setContact] = useState("");
  const [credit, setCredit] = useState("");
  const [received, setReceived] = useState("");
  // Where it came from. No default: a report from outside carries a
  // disclosure date and one found here does not, and a preselected answer is
  // a choice nobody made.
  const [origin, setOrigin] = useState<"" | "here" | "outside">("");
  // Whether to record it as a flaw now rather than file it for judging. The
  // button somebody pressed, and nothing until they press one.
  const [now, setNow] = useState<boolean | null>(null);
  // Files that prove it — a test case, a capture, a screenshot. Held until the
  // report or the issue exists, because an attachment hangs off one of them.
  const [files, setFiles] = useState<File[]>([]);
  const [refused, setRefused] = useState<string[]>([]);
  // The address of the finding just recorded, held while somebody reads
  // which of their files did not attach.
  const [onward, setOnward] = useState("");
  const [weaknesses, setWeaknesses] = useState<string[]>([]);
  // The claim's words as a starting point, once they arrive and only while the
  // summary is still empty.
  useReseed(report.data?.reference ?? "", () => {
    if (report.data?.summary && summary === "") setSummary(report.data.summary);
  });

  const may = mayOf(who.data, product);
  // Recording a flaw is triage at the visibility it is recorded at, and each
  // visibility is its own role: somebody holding one records at that one only.
  const mayHide = !!may?.may_hide;
  const mayPublish = !!may?.triages_public;
  const mayRecord = mayHide || mayPublish;
  const whole = product !== "" && streams.length > 0 && variants.length > 0;
  // Filing a report is working reports, which asks for the right to triage
  // undisclosed work. Without it the only path is recording a flaw that is
  // already public, and from a report there is nothing left to file.
  const recordNow = fromReport !== "" || (product !== "" && !mayHide) || (now ?? false);
  const choosing = fromReport === "" && (product === "" || mayHide);
  const said = fromReport !== "" || origin !== "";

  // Defaulting to undisclosed unless the person cannot record one, which is
  // the case this exists for. Defaulting the other way makes the dangerous
  // mistake the quiet one.
  //
  // Worked out rather than stored, so there is no frame in which the form is
  // drawn one way and corrected to the other once the session has loaded: for
  // somebody holding one of the two roles, that one is the only answer there
  // is, and the control that would say otherwise is disabled.
  const disclosed = !mayHide ? true : !mayPublish ? false : (chose ?? false);
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
            ...(fromReport ? { from_report: fromReport } : told()),
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
      // The report is judged now, and a page that still offers to judge it
      // fails when somebody tries.
      if (fromReport) afterReport();
      setRefused(failed);
      // Onto the issue: every build it landed in, and the advisory about it,
      // which is the next thing a flaw in our own product is headed for.
      const onward = `/issues/${encodeURIComponent(made.identifier)}`;
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

  // Filed for judging: the claim, where it came from, and what arrived with it.
  // The files go against the report, which is what exists once this is done.
  const recordReport = useRecordReport(product);
  const filing = useMutation({
    mutationFn: async () => {
      const made = await recordReport.mutateAsync({ summary: summary.trim(), ...told() });
      const failed: string[] = [];
      for (const each of files) {
        try {
          await uploadReportFile(product, made.reference, each);
        } catch {
          failed.push(each.name);
        }
      }
      return { made, failed };
    },
    onSuccess: ({ made, failed }) => {
      const onward = `/products/${encodeURIComponent(product)}/inbox/${encodeURIComponent(made.reference)}`;
      setRefused(failed);
      if (failed.length > 0) {
        setOnward(onward);
        return;
      }
      navigate(onward);
    },
  });

  // What is said about where it came from, as both requests take it. A flaw
  // found here sends the finder and the credit and nothing about an arrival.
  function told() {
    return {
      ...(reportedBy.trim() ? { reported_by: reportedBy.trim() } : {}),
      ...(credit.trim() ? { credit: credit.trim() } : {}),
      ...(origin === "outside" && contact.trim() ? { contact: contact.trim() } : {}),
      ...(origin === "outside" && received ? { received } : {}),
      ...(origin === "here" ? { found_here: true } : {}),
    };
  }

  // A name the build holds at more than one version is a question, not a
  // failure: the server refuses and says which, so this offers them back
  // rather than choosing. Picking one is the whole of the answer.
  const choices = choicesAt(record.error, "component");
  // A summary and a build. Not a severity: a flaw may be recorded before
  // anybody has worked out how bad it is, and making somebody pick a word to
  // get the record written is how a guess ends up stored as a judgment.
  // Nothing more once something is saved. A file that did not attach keeps
  // the form up to say so, and a second press would file a second report or
  // record a second flaw.
  const ready =
    onward === "" &&
    said &&
    summary.trim() !== "" &&
    !record.isPending &&
    !filing.isPending &&
    (recordNow ? whole && mayRecord : product !== "" && mayHide);

  return (
    <>
      <div className="screen-head">
        <h2>Report a flaw</h2>
        <p>
          {fromReport
            ? "Record this report as a flaw in what we ship."
            : "A flaw in what we ship, sent in or found here. File it for judging, or record it as a flaw now."}
        </p>
        {/* What was recorded here before. The screen that files one is where
            somebody asks whether it is already filed. */}
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
        <h3>The flaw</h3>
        <div className="field">
          <label htmlFor="rec-product">Product</label>
          <select
            id="rec-product"
            {...notACredential}
            value={product}
            // The report names its product, and the reference means nothing
            // in any other.
            disabled={!!fromReport}
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
          <label htmlFor="rec-summary">
            What it is{" "}
            <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--sev-high)" }}>
              required
            </span>
          </label>
          {/* The same editor and the same submission policy as a
              justification. It is rendered as markdown where it is read back,
              which is why it is written as markdown here. */}
          <Editor
            value={summary}
            onChange={setSummary}
            draftKey={`record:${product}`}
            rows={6}
            label="What it is"
            placeholder="The management socket answers a request before anyone has authenticated."
            mentions={mentioning(product, !disclosed)}
          />
        </div>

        <div className="field">
          <label htmlFor="rec-files">Evidence</label>
          <Dropzone id="rec-files" files={files} onChange={setFiles} multiple small>
            {recordNow
              ? "Optional. Readable by whoever can read the issue."
              : "Optional. Readable by whoever can read the report."}
          </Dropzone>
        </div>
      </div>

      <div className="panel" style={{ maxWidth: "80ch", marginTop: 14 }}>
        <h3>Where it came from</h3>
        {fromReport ? (
          <p className="hint">
            From{" "}
            <Link
              className="id"
              to={`/products/${encodeURIComponent(product)}/inbox/${encodeURIComponent(fromReport)}`}
            >
              {fromReport}
            </Link>
            {report.data?.found_here
              ? " · found here"
              : report.data?.reported_by && <> · {report.data.reported_by}</>}
            {report.data?.received && <> · arrived {report.data.received}</>}. Recording it accepts
            the report.
          </p>
        ) : (
          <>
            <ChoiceCards
              label="Where it came from"
              value={origin}
              onChange={setOrigin}
              options={[
                {
                  value: "outside",
                  label: "Sent in from outside",
                  note: "Gets a disclosure date from the day it arrived",
                },
                {
                  value: "here",
                  label: "Found here",
                  note: "No disclosure date, nobody to answer",
                },
              ]}
            />
            {origin !== "" && (
              <div className="filters">
                <label className="field" style={{ margin: 0 }}>
                  <span>{origin === "here" ? "Found by" : "Reported by"}</span>
                  <input
                    {...notACredential}
                    type="text"
                    value={reportedBy}
                    placeholder={origin === "here" ? "optional" : "as they gave their name"}
                    onChange={(event) => setReportedBy(event.target.value)}
                  />
                </label>
                {origin === "outside" && (
                  <label className="field" style={{ margin: 0 }}>
                    <span>Contact</span>
                    <input
                      {...notACredential}
                      type="text"
                      value={contact}
                      placeholder="an address"
                      onChange={(event) => setContact(event.target.value)}
                    />
                  </label>
                )}
                <label className="field" style={{ margin: 0 }}>
                  <span>Credited as</span>
                  <input
                    {...notACredential}
                    type="text"
                    value={credit}
                    placeholder="in the advisory; anonymous is an answer"
                    onChange={(event) => setCredit(event.target.value)}
                  />
                </label>
                {origin === "outside" && (
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
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* The choice between filing and recording, for whoever may do both.
          Somebody who may not work reports only ever records, and a report
          being recorded has nothing left to file. */}
      {choosing && (
        <div className="panel" style={{ maxWidth: "80ch", marginTop: 14 }}>
          <h3>Next</h3>
          <ChoiceCards
            label="What to do with it"
            value={recordNow ? "record" : "file"}
            onChange={(next) => setNow(next === "record")}
            options={[
              { value: "file", label: "File for judging", note: "Waits in the Inbox" },
              {
                value: "record",
                label: "Record as a flaw now",
                note: "Gets an identifier, opens findings",
              },
            ]}
          />
        </div>
      )}

      {product !== "" && !mayRecord && (
        <div className="alert" style={{ maxWidth: "80ch", marginTop: 14 }}>
          <strong>Not yours to report</strong>
          <span>This is triage work on {product}, and you hold no triage role there.</span>
        </div>
      )}

      {recordNow && (
        <div className="panel" style={{ maxWidth: "80ch", marginTop: 14 }}>
          <h3>Builds</h3>
          <div className="fields">
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

          <div className="field">
            <label htmlFor="rec-component">The component carrying it</label>
            {/* Shown as a list rather than left to the browser's datalist,
                which has no affordance at all. Names, not name-and-version
                rows: which of several versions is meant is the question the
                refusal asks properly. */}
            <Suggest
              id="rec-component"
              value={component}
              disabled={!whole}
              placeholder={whole ? "the build itself" : "pick a build first"}
              loading={holding.isFetching}
              options={[
                ...new Set((holding.data?.items ?? []).map((each) => each.component ?? "")),
              ]}
              onChange={(next) => {
                setComponent(next);
                setVersion("");
                setEcosystem("");
              }}
            />
            <span className="hint">
              As the build calls it. Leave it empty for the build itself.
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
              <strong>Components named {component}</strong>
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
              {vector !== ""
                ? "Set by the vector below."
                : "Leave it unset if nobody knows yet. The deadline starts when somebody rates it."}
            </span>
          </div>

          <Scoring vector={vector} onChange={setVector} />

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
              <button
                type="button"
                aria-pressed={disclosed}
                disabled={!mayPublish}
                onClick={() => setChose(true)}
              >
                Public
              </button>
            </div>
            {/* Why one cannot be picked, in the open rather than on a disabled
                button, which reads as broken. */}
            {!mayHide && (
              <span className="hint">
                Recording an undisclosed flaw needs the private triage role here. Without it, this
                is public once saved.
              </span>
            )}
            {!mayPublish && mayHide && (
              <span className="hint">
                Recording a public flaw needs the public triage role here. Without it, this is
                undisclosed once saved.
              </span>
            )}
            <span className="hint">
              {disclosed
                ? "Already disclosed, so no disclosure date."
                : origin === "here" || report.data?.found_here
                  ? "Starts undisclosed, with no disclosure date: nobody outside is counting down."
                  : "Starts undisclosed, with a disclosure date ninety days from the day it arrived unless this deployment says otherwise. Reaching it escalates rather than publishes."}
            </span>
          </div>
        </div>
      )}

      <div className="panel" style={{ maxWidth: "80ch", marginTop: 14 }}>
        {record.error != null && choices.length === 0 && (
          <Failed error={record.error} what="That could not be recorded." />
        )}
        {filing.error != null && <Failed error={filing.error} what="That report was not filed." />}

        {refused.length > 0 && (
          <div className="alert">
            <strong>Saved, and some files were not</strong>
            <span>
              {refused.join(", ")} could not be stored. Attach them again from what was saved.
            </span>
            {onward && (
              <Link className="linkish" to={onward}>
                Open it
              </Link>
            )}
          </div>
        )}

        <div className="actions">
          <button
            type="button"
            className="btn"
            disabled={!ready}
            onClick={() => (recordNow ? record.mutate() : filing.mutate())}
          >
            {record.isPending || filing.isPending
              ? "Saving…"
              : recordNow
                ? disclosed
                  ? "Record flaw"
                  : "Record flaw, undisclosed"
                : "File report"}
          </button>
          <span className="hint">
            {product === ""
              ? "Pick a product."
              : !said
                ? "Say where it came from."
                : !recordNow
                  ? "Goes to the Inbox for judging."
                  : whole
                    ? `Against ${streams.length * variants.length} ${
                        streams.length * variants.length === 1 ? "build" : "builds"
                      }: one issue, and a finding for each place the component sits in each of them. A build that does not hold the component is refused rather than skipped.`
                    : "Pick at least one branch or tag and one variant."}
          </span>
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
