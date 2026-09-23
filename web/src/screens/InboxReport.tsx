import { mayOf, useWho } from "../app/session";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  uploadReportFile,
  useAcceptReport,
  useAcknowledgeReport,
  useReport,
  useReportFiles,
  useRuling,
} from "../api/intake";
import { useQueryClient } from "@tanstack/react-query";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Markdown } from "../ui/Markdown";
import { notACredential } from "../ui/noautofill";
import { on } from "../ui/when";
import { standing } from "./inbox";
import { RuleForm, RulingCard } from "./InboxRuling";

// One report: what was claimed, who sent it, whether they were answered, what
// arrived with it, and what it was judged to be.
export function InboxReport() {
  const { product = "", reference = "" } = useParams();
  const report = useReport(product, reference);
  const ruling = useRuling(product, report.data?.ruling);
  const acknowledge = useAcknowledgeReport(product, reference);
  const works = !!mayOf(useWho().data, product)?.may_hide;

  if (report.isPending) return <Loading />;
  if (report.isError)
    return <Failed error={report.error} what="That vulnerability report could not be read." />;
  const it = report.data;
  const stands = standing(it);
  const inbox = `/products/${encodeURIComponent(product)}/inbox`;

  return (
    <div>
      <div className="screen-head">
        <h2 className="id">{it.reference}</h2>
        <p>
          <Link to={inbox}>Inbox</Link> ·{" "}
          <span className={`state ${stands.tone}`}>{stands.said}</span>
          {it.issue && (
            <>
              {" "}
              <Link className="id" to={`/issues/${encodeURIComponent(it.issue)}`}>
                {it.issue}
              </Link>
            </>
          )}
        </p>
      </div>

      <div className="card">
        <h3>Claim</h3>
        {it.summary ? (
          <Markdown source={it.summary} className="reading" />
        ) : (
          <p className="hint">Recorded with the issue. Its description carries the claim.</p>
        )}
        <p className="hint" style={{ marginTop: 8 }}>
          {it.reported_by || "Anonymous"}
          {it.contact && (
            <>
              {" "}
              · <span className="id">{it.contact}</span>
            </>
          )}
          {it.credit && <> · credit as {it.credit}</>}
          {it.received && <> · arrived {it.received}</>} · recorded by {it.recorded_by},{" "}
          {on(it.recorded_at)}
        </p>
        {it.acknowledged ? (
          <p className="hint">
            Answered {on(it.acknowledged)}
            {it.acknowledged_by && <> by {it.acknowledged_by}</>}
          </p>
        ) : (
          <div className="alert" style={{ margin: "6px 0 0" }}>
            <strong>Not answered.</strong>
            <span>Send them a note, then record it here.</span>
            <button
              hidden={!works}
              type="button"
              className="btn"
              style={{ marginLeft: "auto" }}
              disabled={acknowledge.isPending}
              onClick={() => acknowledge.mutate()}
            >
              Mark as answered
            </button>
          </div>
        )}
        {acknowledge.error != null && (
          <Failed error={acknowledge.error} what="That was not recorded." />
        )}
      </div>

      <Files product={product} reference={reference} works={works} />

      <div className="card" style={{ marginTop: 14 }}>
        <h3>Judgment</h3>
        {it.disposition === "accepted" ? (
          <p className="reading">
            Accepted as{" "}
            <Link className="id" to={`/issues/${encodeURIComponent(it.issue ?? "")}`}>
              {it.issue}
            </Link>
            {it.evaluated_by && (
              <span className="hint">
                {" "}
                · {it.evaluated_by}, {on(it.evaluated)}
              </span>
            )}
          </p>
        ) : it.ruling ? (
          ruling.isPending ? (
            <Loading />
          ) : ruling.isError ? (
            <Failed error={ruling.error} what="The ruling could not be read." />
          ) : (
            ruling.data && <RulingCard ruling={ruling.data} />
          )
        ) : works ? (
          <Judge product={product} reference={reference} />
        ) : (
          <p className="hint">Not judged yet.</p>
        )}
      </div>
    </div>
  );
}

// The two ways to answer a claim: it is an issue here, or it is one of the
// four a ruling says.
function Judge({ product, reference }: { product: string; reference: string }) {
  const [issue, setIssue] = useState("");
  const accept = useAcceptReport(product, reference);
  return (
    <>
      <div className="field">
        <label htmlFor="accept-as">Accept as an issue</label>
        <div style={{ display: "flex", gap: 6 }}>
          <input
            {...notACredential}
            id="accept-as"
            type="text"
            value={issue}
            placeholder="SONIC-2026-000123"
            onChange={(event) => setIssue(event.target.value)}
          />
          <button
            type="button"
            className="btn"
            disabled={issue.trim() === "" || accept.isPending}
            onClick={() => accept.mutate(issue.trim())}
          >
            Accept
          </button>
        </div>
        <span className="hint">
          An issue already recorded in {product}, or{" "}
          <Link
            to={`/record?product=${encodeURIComponent(product)}&from=${encodeURIComponent(reference)}`}
          >
            record it as a new flaw
          </Link>
          .
        </span>
        {accept.error != null && <Failed error={accept.error} what="It was not accepted." />}
      </div>
      <h4 style={{ margin: "14px 0 6px" }}>Or rule on it</h4>
      <RuleForm product={product} references={[reference]} />
    </>
  );
}

// What arrived with the report. Held on the report whatever it is judged to
// be, and read under the report's rule.
function Files({
  product,
  reference,
  works,
}: {
  product: string;
  reference: string;
  works: boolean;
}) {
  const queries = useQueryClient();
  const listed = useReportFiles(product, reference);
  const [sending, setSending] = useState(false);
  const [refused, setRefused] = useState<unknown>(null);
  const files = listed.data?.items ?? [];

  const attach = async (chosen: FileList | null) => {
    if (!chosen || chosen.length === 0) return;
    setSending(true);
    setRefused(null);
    try {
      for (const file of Array.from(chosen)) {
        await uploadReportFile(product, reference, file);
      }
    } catch (error) {
      setRefused(error);
    } finally {
      setSending(false);
      void queries.invalidateQueries({ queryKey: ["recorded-report", product, reference] });
    }
  };

  return (
    <div className="card" style={{ marginTop: 14 }}>
      <h3>Files</h3>
      {listed.isError ? (
        <Failed error={listed.error} what="The files could not be read." />
      ) : files.length === 0 ? (
        <p className="hint">None.</p>
      ) : (
        <ul className="files">
          {files.map((file) =>
            file.redacted ? (
              <li key={file.token}>
                <span className="hint">
                  <b>{file.filename}</b> was removed
                  {file.redacted_reason ? <> — {file.redacted_reason}</> : null}
                </span>
              </li>
            ) : (
              <li key={file.token}>
                <a href={`/v1/attachments/${file.token}`} rel="noreferrer">
                  {file.filename}
                </a>
                <span className="hint">
                  {" "}
                  · {file.content_type} · {Math.max(1, Math.round((file.size ?? 0) / 1024))} KB
                </span>
              </li>
            ),
          )}
        </ul>
      )}
      <label className="btn quiet" style={{ marginTop: 8 }} hidden={!works}>
        {sending ? "Attaching…" : "Attach a file"}
        <input
          type="file"
          multiple
          hidden
          disabled={sending}
          onChange={(event) => void attach(event.target.files)}
        />
      </label>
      {refused != null && <Failed error={refused} what="A file was not attached." />}
    </div>
  );
}
