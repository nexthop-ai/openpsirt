import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";

// A table that may be wider than the screen it is on.
//
// On a phone a wide table scrolls sideways, which is discoverable once
// somebody knows it is a table and not once they think the page is cut off —
// so it says so. The saying is the part that has to be measured: a caption
// written by the stylesheet appears over every table at that width, including
// the two-column ones that fit, and a note about scrolling on a table nobody
// can scroll is the kind of wrong that teaches people to stop reading notes.
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

  useEffect(() => {
    const at = box.current;
    if (!at || typeof ResizeObserver === "undefined") return;
    const measure = () => setWider(at.scrollWidth > at.clientWidth);
    measure();
    const watching = new ResizeObserver(measure);
    watching.observe(at);
    const table = at.firstElementChild;
    if (table) watching.observe(table);
    return () => watching.disconnect();
  }, []);

  return (
    <div
      ref={box}
      className={className ? `tablewrap ${className}` : "tablewrap"}
      data-wider={wider ? "yes" : undefined}
      style={style}
    >
      {children}
    </div>
  );
}
