import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";

// A table that may be wider than the box it is in.
//
// A wide table scrolls sideways inside its box, which is discoverable once
// somebody knows it is a table and not once they think the page is cut off —
// so it says so, and the clipped edge is shaded so the overflow shows before
// the note is read. The saying is the part that has to be measured: a caption
// written by the stylesheet appears over every table, including the two-column
// ones that fit, and a note about scrolling on a table nobody can scroll is
// the kind of wrong that teaches people to stop reading notes.
//
// A table that scrolls takes a tab stop, so the arrow keys move it once it has
// focus. A box that only a pointer can scroll is a table a keyboard cannot
// read to the end of.
//
// Both the box and the table are watched. The box changes with the window;
// the table changes as rows arrive, and that does not move the box at all.
export function Wide({
  className,
  style,
  children,
}: {
  className?: string;
  style?: CSSProperties;
  children: ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [wider, setWider] = useState(false);
  // Which edge holds more: the side the shade is drawn on.
  const [clipped, setClipped] = useState<"left" | "right" | "both" | "">("");

  useEffect(() => {
    const at = box.current;
    if (!at || typeof ResizeObserver === "undefined") return;
    const measure = () => {
      const more = at.scrollWidth - at.clientWidth;
      const is = more > 1;
      setWider(is);
      if (!is) {
        setClipped("");
      } else if (at.scrollLeft <= 1) {
        setClipped("right");
      } else if (at.scrollLeft >= more - 1) {
        setClipped("left");
      } else {
        setClipped("both");
      }
    };
    measure();
    const watching = new ResizeObserver(measure);
    watching.observe(at);
    const table = at.firstElementChild;
    if (table) watching.observe(table);
    at.addEventListener("scroll", measure, { passive: true });
    return () => {
      watching.disconnect();
      at.removeEventListener("scroll", measure);
    };
  }, []);

  return (
    <div
      ref={box}
      className={className ? `tablewrap ${className}` : "tablewrap"}
      data-wider={wider ? "yes" : undefined}
      data-clipped={clipped || undefined}
      // Focusable only while there is somewhere to scroll to: a tab stop on
      // a box that does not move is a stop for nothing.
      tabIndex={wider ? 0 : undefined}
      style={style}
    >
      {children}
    </div>
  );
}
