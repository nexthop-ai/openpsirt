// The look this browser draws, of the two.
//
// A look is a token set on the root element and nothing else — the markup is
// the same under both. It is a personal preference kept in the browser, the
// same rule as saved filters: it changes what one person sees and nothing
// anybody else is shown.
//
// Unset means the operating system decides, and keeps deciding: somebody
// whose machine turns dark at sunset gets a dark interface at sunset without
// having said anything here. Choosing one pins it, because a person who has
// said which they want has answered a question the operating system was only
// guessing at.

export const LOOKS = [
  {
    name: "light",
    label: "Light mode",
    said: "dark rail, light work surface",
    a: "#141a23",
    b: "#2b62e3",
  },
  { name: "dark", label: "Dark mode", said: "dark throughout", a: "#0e1117", b: "#6ea8ff" },
] as const;

export type Look = (typeof LOOKS)[number]["name"];

const KEPT = "openpsirt.look";

// The operating system's own answer, for somebody who has not chosen.
export function systemLook(): Look {
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    // A browser without the query gets the light one.
    return "light";
  }
}

// The choice somebody made, or nothing where they have not.
export function chosenLook(): Look | null {
  try {
    const kept = window.localStorage.getItem(KEPT);
    if (kept && LOOKS.some((each) => each.name === kept)) return kept as Look;
  } catch {
    // A browser that refuses storage has chosen nothing.
  }
  return null;
}

export function applyLook(look: Look) {
  document.documentElement.setAttribute("data-look", look);
  try {
    window.localStorage.setItem(KEPT, look);
  } catch {
    // The look still applies for this page.
  }
}

// Go back to following the operating system.
export function clearLook() {
  try {
    window.localStorage.removeItem(KEPT);
  } catch {
    // Nothing was kept, so nothing has to be removed.
  }
  document.documentElement.setAttribute("data-look", systemLook());
}

// Follow the operating system while nobody has chosen. Returns the unsubscribe.
export function followSystem(onChange: (look: Look) => void): () => void {
  try {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const moved = () => {
      if (chosenLook() === null) {
        const look = systemLook();
        document.documentElement.setAttribute("data-look", look);
        onChange(look);
      }
    };
    query.addEventListener("change", moved);
    return () => query.removeEventListener("change", moved);
  } catch {
    return () => {};
  }
}
