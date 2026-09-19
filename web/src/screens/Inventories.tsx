import { useState } from "react";
import { Loading } from "../ui/Loading";
import { on } from "../ui/when";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type Body } from "../api/client";
import { unwrap } from "../api/queries";
import { Carried } from "../ui/Carried";
import { CarriedPatches } from "../ui/CarriedPatches";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Fab } from "../ui/Drawer";
import { Icon } from "../ui/Icons";
import { UploadDrawer } from "../ui/Upload";
import { Wide } from "../ui/Wide";

// Each build's uploads, and what the scan of them found. A scan is what the
// deployment does to an inventory after it arrives; what a person uploads, and
// what this list is of, is inventories.
//
// A build quietly dropping out is the failure that makes everything else
// wrong, so a build that has gone quiet is named at the top rather than being
// invisible on the screen about it.
export function Inventories() {
  const { product = "", stream = "", variant = "" } = useParams();
  const at = { product, stream, variant };
  const [uploading, setUploading] = useState(false);

  const scans = useQuery({
    queryKey: ["scans", product, stream, variant],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/scans", {
          params: { path: { product, stream, variant } },
        }),
      ),
    // Receipts move on their own while an upload is being read.
    refetchInterval: 15_000,
  });
  const scanning = useQuery({
    queryKey: ["scanning", product],
    queryFn: async () => unwrap(await api.GET("/v1/scanning", { params: { query: { product } } })),
  });
  const quiet = (scanning.data?.items ?? []).filter((b) => b.quiet);
  // The total, against the number named. These rows are named
  // rather than counted, so the page is what a reader sees — but a page short
  // of the answer named some builds and stayed silent about the rest, which on
  // this screen reads as "those are the quiet ones".
  const quietTotal = scanning.data?.quiet ?? 0;
  // Silence on a release that has gone out of support is expected rather than
  // a fault, so it is said quietly rather than raised — but it is still said.
  // "Not scanned, and that is fine" and "not mentioned" are different answers.
  const retired = (scanning.data?.items ?? []).filter((b) => b.retired && b.quiet_days > 0);

  if (scans.isPending) return <Loading />;
  if (scans.isError)
    return <Failed error={scans.error} what="The inventories could not be read." />;

  const items = scans.data?.items ?? [];
  const measured = scans.data?.measured_against;

  return (
    <>
      <div className="screen-head">
        <h2>Inventories</h2>
        <p>
          {product} · {stream} · {variant}· newest first
        </p>
        <span style={{ marginLeft: "auto" }}>
          <button type="button" className="btn" onClick={() => setUploading(true)}>
            <Icon name="upload" size={14} /> Upload inventory
          </button>
        </span>
      </div>

      {quiet.map((build) => (
        <div
          className="alert"
          key={`${build.stream} ${build.variant}`}
          style={{ marginBottom: 10 }}
        >
          <strong>
            {build.stream} · {build.variant}: no inventory
            {build.last_received_at ? ` for ${build.quiet_days} days` : " ever"}
          </strong>
          <span>
            {build.last_received_at
              ? "Nothing has arrived. A build that stops being scanned looks healthy."
              : `Declared ${build.quiet_days} days ago, and nothing has ever been filed against it.`}
          </span>
        </div>
      ))}

      {quietTotal > quiet.length && (
        <p className="hint" style={{ marginBottom: 10 }}>
          {(quietTotal - quiet.length).toLocaleString()} more{" "}
          {quietTotal - quiet.length === 1 ? "build has" : "builds have"} gone quiet here and are
          not named above. The scan-coverage report lists every one of them.
        </p>
      )}

      {retired.length > 0 && (
        <p className="hint" style={{ marginBottom: 10 }}>
          {retired.map((build) => `${build.stream} · ${build.variant}`).join(", ")}
          {retired.length === 1 ? " is" : " are"} out of support, so nothing is expected to arrive
          for {retired.length === 1 ? "it" : "them"}. The findings and the history stay.
        </p>
      )}

      {items.length === 0 ? (
        <Empty
          title="Nothing has been uploaded here."
          detail="A build pipeline uploads an inventory, or somebody does from the button above, and what became of it appears here."
        />
      ) : (
        <Wide>
          <table>
            <thead>
              <tr>
                <th>Received</th>
                <th>Built</th>
                <th>State</th>
                <th className="num">Opened</th>
                <th className="num">Closed</th>
                <th>Sent</th>
                <th className="num">Placed</th>
                <th>Measured with</th>
                <th>Serial</th>
              </tr>
            </thead>
            <tbody>
              {items.map((scan) => (
                <tr key={scan.scan_id}>
                  <td>{scan.received_at?.replace("T", " ").slice(0, 16)}</td>
                  <td className="hint">{scan.built_at?.replace("T", " ").slice(0, 16)}</td>
                  <td>
                    {/* The run's own page, where there is one. A
                        state word is where somebody asks "what did it find",
                        and the answer had nowhere to go. */}
                    {scan.run_id ? (
                      <Link
                        to={
                          `/products/${encodeURIComponent(product)}` +
                          `/streams/${encodeURIComponent(stream)}` +
                          `/variants/${encodeURIComponent(variant)}/runs/${scan.run_id}`
                        }
                        title="What this run opened and closed, and what it was measured with"
                      >
                        <State state={scan.state} />
                      </Link>
                    ) : (
                      <State state={scan.state} />
                    )}
                    {scan.failure && (
                      <div className="hint" style={{ marginTop: 4 }}>
                        {scan.failure}
                      </div>
                    )}
                    {/* A scanner that answers and warns its answer is coarse
                        is qualifying every finding of that run. Shown beside a
                        run that worked, because that is when it is said. */}
                    {scan.caution && (
                      <div
                        className="hint"
                        style={{ marginTop: 4 }}
                        title="A warning from a scan that still succeeded"
                      >
                        ⚠ {scan.caution}
                      </div>
                    )}
                  </td>
                  {/* Grouped, like every other count here. Seven thousand
                      findings written as 7587 is a number somebody has to
                      count the digits of.

                      A run that changed nothing says 0. Nothing at all is
                      left blank, which is the row of an upload whose run is
                      reported against a newer one — a run covers a build
                      rather than an upload — and of one no run has answered
                      yet. Drawn as a dash, both of those read as "this upload
                      opened nothing", which is a statement about a scan that
                      never read it. */}
                  <td className="num">{counted(scan.opened)}</td>
                  <td className="num">{counted(scan.closed)}</td>
                  <td>
                    <Sent at={at} scan={scan.scan_id ?? 0} sent={scan.sent ?? []} />
                  </td>
                  <td className="num">
                    <Placed components={scan.components} placed={scan.placed} />
                  </td>
                  {/* What the run answering *this* upload was made with,
                      rather than what the newest run was. A page spanning a
                      scanner upgrade, or a vulnerability database that
                      stopped moving, is exactly what somebody reads this
                      screen to notice — and it is what makes a corrected feed
                      answerable afterwards. */}
                  <td className="hint">
                    {scan.measured ? (
                      <span
                        title={
                          `${scan.measured.scanner ?? ""} ${scan.measured.scanner_version ?? ""}` +
                          `, vulnerability database ${scan.measured.database_version || "unstated"}` +
                          (scan.measured.ran_here ? "" : ", run by the build rather than here")
                        }
                      >
                        {shortly(scan.measured.database_version) || "—"}
                        {scan.measured.scanner_version && (
                          <>
                            <br />
                            <span style={{ color: "var(--faint)" }}>
                              {scan.measured.scanner} {scan.measured.scanner_version}
                            </span>
                          </>
                        )}
                      </span>
                    ) : (
                      ""
                    )}
                  </td>
                  {/* A document that named itself, or an em dash. An empty
                      cell reads as a column that failed to load rather than
                      as a producer that supplied no serial. */}
                  <td className="id hint">{scan.serial || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Wide>
      )}

      {measured && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3 title="Every inventory is scanned here, on a schedule, by the same scanner against the same database, so counts compare between products">
            Scanner
          </h3>
          <div className="scores">
            <div className="score">
              <span className="n">{measured.scanner ?? "—"}</span>
              <span className="l">Scanner</span>
            </div>
            <div className="score">
              <span className="n">{measured.scanner_version ?? "—"}</span>
              <span className="l">Version</span>
            </div>
            <div className="score">
              <span className="n">{measured.database_version ?? "—"}</span>
              <span className="l">Vulnerability data</span>
            </div>
            <div className="score">
              <span className="n">{on(measured.ran_at) ?? "—"}</span>
              <span className="l">Last run</span>
            </div>
          </div>
        </div>
      )}

      {/* What this line would inherit from another, and which of it to take
. Here because this is the screen somebody is on when a line
          has just had its first scan, which is the moment the question
          arises. */}
      <Carried at={{ product, stream, variant }} />

      {/* What the build says about itself, which is the other half of what it
          sent: the inventory says what it ships and this says what it has
          already dealt with. Folded by default — most visits are
          about whether a scan landed. */}
      <CarriedPatches at={{ product, stream, variant }} />

      <Fab label="Upload inventory" onClick={() => setUploading(true)} />
      <UploadDrawer open={uploading} onClose={() => setUploading(false)} />
    </>
  );
}

// The documents an upload was made of, and whether they are still here.
//
// The record outlives the files: a branch build's contents are let go once
// they have been read, because the next night supersedes them, and a tagged
// release keeps them because re-scanning it years from now needs what it
// contained. Both read back as what arrived, so an upload whose files are gone
// does not look like one that arrived with nothing.
//
// The hash is on the title rather than on the row. Somebody needs it about
// once — when a build is asked to send a file again and the second copy has to
// be checked against the first — and a column of hexadecimal on every row for
// that is a table nobody can read.
//
// One that is still here is a link. Retaining a tag's documents is what makes
// re-scanning a release later possible, and without a route that hands one
// back the inventory a release was scanned against is answered from the build
// system, which is the copy that may have moved since. One whose contents were
// let go is not a link, because a link that answers 410 is a control that
// looks like it works.
function Sent({
  at,
  scan,
  sent,
}: {
  at: { product: string; stream: string; variant: string };
  scan: number;
  sent: {
    document_id?: number;
    kind?: string;
    size_bytes?: number;
    hash?: string;
    held?: boolean;
  }[];
}) {
  if (sent.length === 0) return <span className="hint">—</span>;
  const where = (document: number) =>
    `/v1/products/${encodeURIComponent(at.product)}` +
    `/streams/${encodeURIComponent(at.stream)}` +
    `/variants/${encodeURIComponent(at.variant)}` +
    `/scans/${scan}/documents/${document}`;
  return (
    <span className="sent">
      {sent.map((doc, i) => {
        const what = doc.kind === "suppressions" ? "suppressions" : "inventory";
        const said = `${doc.hash ?? ""}${doc.held ? "" : " — contents let go; the record of what arrived is kept"}`;
        if (!doc.held || !doc.document_id) {
          return (
            <span key={`${doc.kind}-${i}`} className="doc letgo" title={said}>
              {what} {size(doc.size_bytes ?? 0)}
            </span>
          );
        }
        return (
          <a
            key={`${doc.kind}-${i}`}
            className="doc"
            href={where(doc.document_id)}
            title={`Download it as it arrived — ${said}`}
          >
            {what} {size(doc.size_bytes ?? 0)}
          </a>
        );
      })}
    </span>
  );
}

// Bytes as somebody reads them. Whole units below a thousand of the next one,
// because "1.2 MB" is the answer to how large a file is and "1,234,567 bytes"
// is the answer to a question nobody asked.
function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// A count of what a run changed, or nothing where this row is not where that
// is reported.
//
// Zero is an answer: a nightly run that opened nothing is a fact about the
// night. Absent is a different one — the run that answers this upload is
// reported against a newer upload, because a run covers a build rather than an
// upload, or no run has answered it yet. Drawn as a dash, both of those read
// as a scan that looked and found nothing.
function counted(howMany?: number | null) {
  if (howMany == null) return "";
  return howMany.toLocaleString();
}

// The share of an inventory anything placed in the graph.
//
// The pair, not one number. A document that places none of its components
// produces findings that are each correct and cannot answer "why is this
// here" about any of them — and one unplaced component is ordinary while a
// producer emitting none of the edges is not. Only the ratio tells the two
// apart, so the ratio is what is drawn.
//
// Marked when nothing was placed, because that is the case somebody has to
// notice: it means the dependency tree for this build will be empty and every
// finding in it will say nothing recorded what pulls it in.
function Placed({ components, placed }: { components?: number; placed?: number }) {
  if (components == null || placed == null) return <span className="hint">—</span>;
  const none = components > 0 && placed === 0;
  return (
    <span
      className={none ? "state lapsed" : undefined}
      title={
        none
          ? "This inventory lists no dependencies, so the tree " +
            "for this build is empty and no finding can say why it is here."
          : `${placed.toLocaleString()} of ${components.toLocaleString()} components are placed in the graph`
      }
    >
      {placed.toLocaleString()} / {components.toLocaleString()}
    </span>
  );
}

// The vocabulary the server declares for what an upload is doing, read out of
// the generated client rather than retyped.
type Uploaded = NonNullable<Body<"ReceiptBody">["state"]>;

// The states an upload passes through, and the one it can end in.
//
// One table keyed on the vocabulary the server declares, rather than three
// parallel ones over the same four words: a state added to one of the three
// and not the others drew a label with the wrong color, or a color with no
// label, and nothing here would have said so. Keyed on the generated union, a
// fifth state is a compile error at this table rather than a silent neutral
// badge.
const STATES: Record<Uploaded, { cls: string; label: string; means: string }> = {
  reading: {
    cls: "waiting",
    label: "Queued — parsing",
    means: "accepted, not yet parsed",
  },
  scanning: {
    cls: "waiting",
    label: "Scanning",
    means: "parsed; the vulnerability scan is still running",
  },
  scanned: { cls: "agreed", label: "Completed", means: "complete" },
  failed: {
    cls: "lapsed",
    label: "Failed",
    means: "it did not finish, and the reason is beside it",
  },
};

function State({ state }: { state?: string }) {
  const it = state ? STATES[state as Uploaded] : undefined;
  if (!it) return <span className="state open">{state ?? "—"}</span>;
  return (
    <span className={`state ${it.cls}`} title={it.means}>
      {it.label}
    </span>
  );
}

// A vulnerability database's version, short enough for a column.
//
// Producers stamp it as a full timestamp, which wraps over two lines beside
// everything else on the row and says nothing the date does not. The whole of
// it is on the title, where somebody comparing two runs to the minute can
// still read it.
function shortly(version: string | undefined): string {
  if (!version) return "";
  return version.length > 10 && version[4] === "-" ? on(version) : version;
}
