import { Component, type ErrorInfo, type ReactNode } from "react";
import { Failed } from "../ui/Failed";

// What a render-time throw reaches.
//
// Without one, React unmounts the whole tree: a screen that threw takes the
// rail, the scope bar and every other screen with it, and what is left is a
// blank page with nothing to press. That is also what a chunk that failed to
// arrive looks like, which is an ordinary thing on a flaky connection rather
// than a defect anybody wrote.
//
// A class because this is the one thing hooks cannot do — `getDerivedStateFromError`
// and `componentDidCatch` have no function equivalent.
//
// It logs as well as renders. A boundary that only renders swallows the
// stack that was going to the console, which takes away the thing a developer
// needs and leaves the sentence a reader cannot act on.
export class Boundary extends Component<
  { children: ReactNode; what?: string; where?: string },
  { error?: Error }
> {
  state: { error?: Error } = {};

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`${this.props.where ?? "the interface"} threw while rendering`, error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div>
        <Failed
          error={this.state.error}
          what={this.props.what ?? "This screen could not be drawn."}
        />
        <div className="actions" style={{ marginTop: 12 }}>
          <button type="button" className="btn" onClick={() => this.setState({ error: undefined })}>
            Try again
          </button>
        </div>
      </div>
    );
  }
}
