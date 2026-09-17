import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import { unwrap } from "../../api/queries";
import { useScope } from "../../app/scope";
import { Empty } from "../../ui/Empty";
import { Failed } from "../../ui/Failed";
import { Loading } from "../../ui/Loading";
import { Sheet } from "./Sheet";
import {
  PeriodPicker,
  WindowPicker,
  asked,
  coveringPeriod,
  daysAsked,
  periodAsked,
} from "./Window";
import { Wide } from "../../ui/Wide";

// The windows this question is worth asking over: a month, a quarter, a year.
// Shorter than a month is a fortnight's noise, and the answer is read at a
// planning meeting.
const WINDOWS = [30, 90, 365] as const;

// How many rows the sheet carries. What it is read for is the top of the list.
const SHOWN = 50;

// Where the work went.
//
// **Every other report here counts the backlog** — what is open, what is
// overdue, how long things wait. None of them says what the quarter actually
// went into, which is the question a planning meeting asks and the one a
// manager has to answer without any of the others.
//
// **Counted in claims rather than in the rows they wrote.** A claim is one
// person's act; counting its rows measures how far a component fans out
// through an image, and the component every image vendors would be the answer
// every quarter. Both numbers are shown, because ten claims over ten places
// and one claim over a thousand are different afternoons.
export function Effort() {
  const at = useScope();
  const [params, setParams] = useSearchParams();
  const days = daysAsked(params, 90);
  const period = periodAsked(params);
  const when = asked(period, days);
  const product = at.product ?? "";
  // Whose work, which is the question the report was built for: a manager
  // asking how their own people are doing read the deployment's numbers
  // otherwise. In the address like the period, so a narrowed sheet is
  // something somebody sends.
  const team = params.get("team") ?? "";

  const teams = useQuery({
    queryKey: ["teams"],
    queryFn: async () => unwrap(await api.GET("/v1/teams", {})),
    retry: false,
  });

  const spent = useQuery({
    queryKey: ["effort", when, product, team],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/effort", {
          params: {
            query: {
              ...when,
              limit: SHOWN,
              ...(product ? { product } : {}),
              ...(team ? { team } : {}),
            },
          },
        }),
      ),
  });

  const rows = spent.data?.items ?? [];

  return (
    <Sheet
      settled={spent.isSuccess}
      name="Where the effort went"
      answers="what the judgments in this period were about."
      asked={coveringPeriod(period, days)}
    >
      <WindowPicker offered={WINDOWS} days={days} />
      <PeriodPicker period={period} />

      {(teams.data?.items ?? []).length > 0 && (
        <div className="controls">
          <label>
            Whose{" "}
            <select
              value={team}
              onChange={(e) => {
                const next = new URLSearchParams(params);
                if (e.target.value === "") next.delete("team");
                else next.set("team", e.target.value);
                setParams(next);
              }}
            >
              <option value="">everyone</option>
              {(teams.data?.items ?? []).map((one) => (
                <option key={one.name} value={one.name}>
                  {one.display_name || one.name}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}

      {spent.isPending ? (
        <Loading />
      ) : spent.isError ? (
        <Failed error={spent.error} what="Where the work went could not be read." />
      ) : rows.length === 0 ? (
        <section className="panel">
          <Empty
            title="Nothing was argued in this period."
            detail="Judgments are dated by when they were proposed, which is when the work happened."
          />
        </section>
      ) : (
        <section className="panel">
          <p className="hint" style={{ marginTop: 0 }}>
            Most argued first. <b>Claims</b> is arguments made — one act, however many places it
            covered — and <b>places</b> is how far they reached. What came out of them is beside it,
            because a component that took forty arguments and dismissed forty is a different quarter
            from one that promised forty upgrades.
          </p>
          <Wide>
            <table>
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Product</th>
                  <th className="num">Claims</th>
                  <th className="num">Places</th>
                  <th className="num">People</th>
                  <th className="num">Promised</th>
                  <th className="num">Dismissed</th>
                  <th className="num">Deferred</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.product} ${row.component}`} className="row">
                    <td className="id">
                      {row.component || (
                        // A judgment about a place no build carries any more.
                        // The work happened; what it was about is gone.
                        <span className="hint">no longer in any build</span>
                      )}
                    </td>
                    <td>{row.product}</td>
                    <td className="num">{row.claims.toLocaleString()}</td>
                    <td className="num hint">{row.decisions.toLocaleString()}</td>
                    <td className="num hint">{row.people.toLocaleString()}</td>
                    <td className="num">{row.promised.toLocaleString()}</td>
                    <td className="num">{row.dismissed.toLocaleString()}</td>
                    <td className="num">{row.deferred.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Wide>
        </section>
      )}
    </Sheet>
  );
}
