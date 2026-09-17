import { ROLLED } from "./severities";

// What a count is made of, as one bar whose widths are the counts.
//
// The shape is the answer: a bar that is mostly one color says where the weight
// is before a number is read, which a chip per band at a fixed width does not.
//
// **The key carries the identity, not the color.** Two of the severity colors
// are close enough that a colorblind reader cannot separate them, so the labels
// are what says which band is which and the color reinforces it. Where a row is
// one line the key is dropped and the title carries it, because five legends
// down a table say the same thing five times.
//
// Shared rather than owned by one screen: the component view drew this and the
// dependency tree drew a chip per band from the same `Record<string, number>`,
// which answered "which bands are present" — the fact a reader least needs —
// and said nothing about where the weight was.
export function Shape({ by, key_ = true }: { by?: Record<string, number>; key_?: boolean }) {
  const there = ROLLED.filter((band) => (by ?? {})[band]);
  if (there.length === 0) return null;
  const said = there.map((band) => `${(by ?? {})[band]} ${band}`).join(" · ");
  return (
    <>
      <span className="sevbar" role="img" aria-label={said} title={key_ ? undefined : said}>
        {there.map((band) => (
          <i key={band} className={band} style={{ flex: (by ?? {})[band] }} />
        ))}
      </span>
      {key_ && (
        <span className="sevkey">
          {there.map((band) => (
            <span key={band}>
              <i className={band} />
              {(by ?? {})[band]} {band}
            </span>
          ))}
        </span>
      )}
    </>
  );
}
