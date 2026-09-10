import { Link, useParams } from "react-router-dom";
import { Loading } from "../ui/Loading";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Failed } from "../ui/Failed";

type Changed = {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
};

// What one run of the scanner did.
//
// **A receipt says a run happened; nothing said what it did.** A row reading
// "scanned · 7,604 opened" is a number with no shape: opened *what*, and is
// any of it urgent. Somebody looking at a build that jumped by four thousand
// overnight is asking which of them matter, and the answer was a findings list
// with no way to narrow to that run.
export function Run() {
  const { product = "", stream = "", variant = "", run = "" } = useParams();
  const at = { product, stream, variant, run: Number(run) };
  const build =
    `/products/${encodeURIComponent(product)}` +
    `/streams/${encodeURIComponent(stream)}` +
    `/variants/${encodeURIComponent(variant)}`;

  const ran = useQuery({
    queryKey: ["run", at],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/streams/{stream}/variants/{variant}/runs/{run}", {
          params: { path: at },
        }),
      ),
  });

  if (ran.isPending) return <Loading />;
  if (ran.isError) return <Failed error={ran.error} what="That run could not be read." />;
  const it = ran.data;
  if (!it) return null;

  return (
    <div>
      <div className="screen-head">
        <span className="crumbs">
          <Link to={`${build}/scans`} className="linkish" style={{ fontWeight: 500 }}>
            Inventories
          </Link>{" "}
          › <b>run {it.run_id}</b>
        </span>
        <h2>Scan results</h2>
        <p>
          {product} · {stream} · {variant} ·{" "}
          {it.finished_at ? (
            <>finished {it.finished_at.replace("T", " ").slice(0, 16)}</>
          ) : (
            <b>still running</b>
          )}
        </p>
      </div>

      {it.failure && (
        <div className="alert" style={{ marginBottom: 14 }}>
          <strong>It produced nothing</strong>
          <span>{it.failure}</span>
        </div>
      )}
      {/* What the scanner said while succeeding qualifies every finding of
          this run, which is why it sits beside a run that worked rather than
          instead of one. */}
      {it.caution && (
        <div className="alert info" style={{ marginBottom: 14 }}>
          <strong>It qualified its answer</strong>
          <span>{it.caution}</span>
        </div>
      )}

      <div className="card">
        <h3>Scanner and data</h3>
        <div className="scores">
          <div className="score">
            <span className="n">{it.scanner}</span>
            <span className="l">scanner</span>
          </div>
          <div className="score">
            <span className="n">{it.scanner_version || "—"}</span>
            <span className="l">version</span>
          </div>
          <div className="score">
            <span className="n">{it.database_version || "—"}</span>
            <span className="l">vulnerability data</span>
          </div>
          <div className="score">
            <span className="n">{it.ran_here ? "here" : "the build"}</span>
            <span className="l">ran it</span>
          </div>
        </div>
        <p className="hint" style={{ marginTop: 8 }}>
          Every finding this run opened records these, so work done on the strength of a
          vulnerability database that was later corrected can be found again.
        </p>
      </div>

      <div className="detail" style={{ marginTop: 14 }}>
        <Shape title="What it opened" changed={it.opened} exploited={it.opened_exploited} />
        <Shape title="What it closed" changed={it.closed} />
      </div>

      <p className="hint" style={{ marginTop: 10 }}>
        Counted as issues at components, which is what the findings list counts: a component reached
        twenty ways carries the same issue twenty times. Worked out when this page is read, so it
        moves as findings close and reopen.
      </p>
    </div>
  );
}

// One direction of a run's change, with the shape a total does not have.
function Shape({
  title,
  changed,
  exploited,
}: {
  title: string;
  changed: Changed | undefined;
  exploited?: number;
}) {
  const bands: [string, number][] = [
    ["critical", changed?.critical ?? 0],
    ["high", changed?.high ?? 0],
    ["medium", changed?.medium ?? 0],
    ["low", changed?.low ?? 0],
  ];
  const total = changed?.total ?? 0;
  return (
    <div className="card">
      <h3>{title}</h3>
      <p className="n" style={{ fontSize: "var(--step-3)", margin: "0 0 8px" }}>
        {total.toLocaleString()}
      </p>
      {total === 0 ? (
        <p className="hint" style={{ margin: 0 }}>
          Nothing. A rebuild that finds exactly what the last one found is the ordinary case.
        </p>
      ) : (
        <>
          {/* A band with none of them is left out rather than drawn as a
              zero: a row of zeros reads as a chart that failed to load. */}
          <div className="variants">
            {bands
              .filter(([, n]) => n > 0)
              .map(([band, n]) => (
                <span key={band} className={`sev ${band}`}>
                  {n.toLocaleString()} {band}
                </span>
              ))}
          </div>
          {(exploited ?? 0) > 0 && (
            <p className="alert" style={{ marginTop: 10 }}>
              <strong>{exploited?.toLocaleString()} known to be exploited</strong>
              <span>
                Which is what decides whether this is an evening&rsquo;s work or a night&rsquo;s.
              </span>
            </p>
          )}
        </>
      )}
    </div>
  );
}
