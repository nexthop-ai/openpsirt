import { useState } from "react";

// When something goes out of support, and a way to say so.
//
// A date rather than a switch: a date answers "what goes out of support next
// quarter", which is a real planning question, and it takes effect on its own
// rather than waiting for somebody to remember.
//
// Shown to everybody because it explains two other things a reader sees — past
// it nothing carries a deadline, and a build that stops being scanned is
// expected rather than a fault. Editable by an administrator, because it
// decides both of those.
export function EndOfLife({
  what,
  on,
  inherited,
  admin,
  onSet,
}: {
  what: string;
  on: string;
  // inherited says the date shown belongs to something above this. Following a
  // date and stating the same one are different things: a release that stated
  // it would stop following the next time its product moved.
  inherited?: boolean;
  admin: boolean;
  onSet: (on: string) => void;
}) {
  const [value, setValue] = useState(on);
  const changed = value !== on;

  if (!admin) {
    if (!on) return <span className="hint">—</span>;
    return (
      <span>
        {on}
        {inherited && <span className="hint"> · product&rsquo;s</span>}
      </span>
    );
  }
  return (
    <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
      <input
        type="date"
        // Empty clears it, which is how extended support is recorded: a date
        // taken back rather than a release recreated.
        value={inherited && !changed ? "" : value}
        aria-label={`When ${what}`}
        placeholder={inherited ? on : ""}
        onChange={(event) => setValue(event.target.value)}
      />
      {inherited && !changed && (
        <span className="hint" title="Inherited. Setting one here stops it following.">
          {on} · product&rsquo;s
        </span>
      )}
      {changed && (
        <button type="button" className="btn" onClick={() => onSet(value)}>
          Save
        </button>
      )}
    </span>
  );
}
