import { Link, useLocation } from "react-router-dom";

// An address this application does not answer.
//
// It used to redirect to the home screen, which made a link built wrong look
// like a click that did nothing: the address went out of the bar with the
// redirect, so there was nothing left to read and nothing to report. A
// component link composed with no product selected — `/products//components/x`
// — was reported as "it brings you back to the homepage".
//
// So the address stays in the bar and the screen says it was not recognized.
// The two ways on are the two that are always right: the home screen, and the
// findings list, which answers for every product a reader can see.
export function NotFound() {
  const { pathname, search } = useLocation();
  return (
    <>
      <div className="screen-head">
        <h2>No screen at this address</h2>
        <p>
          Nothing here answers <span className="id">{pathname + search}</span>.
        </p>
      </div>
      <div className="card" style={{ textAlign: "center", padding: "34px 20px" }}>
        <p style={{ margin: 0, fontWeight: 600 }}>The address may be mistyped, or out of date.</p>
        <p className="hint" style={{ margin: "4px 0 0" }}>
          A link from outside the application can also point at a screen that has since moved.
        </p>
        <p style={{ margin: "14px 0 0" }}>
          <Link to="/" className="btn quiet">
            Home
          </Link>{" "}
          <Link to="/findings" className="btn quiet">
            Findings
          </Link>
        </p>
      </div>
    </>
  );
}
