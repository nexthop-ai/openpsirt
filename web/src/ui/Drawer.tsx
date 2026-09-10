import { useEffect, type ReactNode } from "react";
import { Icon } from "./Icons";

// Adding something is an action, not a form above the table. A header control
// and a floating action both open this drawer; the table is what the screen is
// about, and the form appears when somebody means to use it.
export function Drawer({
  open,
  title,
  onClose,
  children,
  footer,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    function key(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [open, onClose]);

  return (
    <>
      <div className={open ? "scrim open" : "scrim"} onClick={onClose} />
      <aside
        className={open ? "drawer open" : "drawer"}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        aria-hidden={!open}
      >
        <header>
          <h3>{title}</h3>
          <button type="button" className="shut" onClick={onClose}>
            Close (Esc)
          </button>
        </header>
        <div className="dbody">{open && children}</div>
        <footer>{footer}</footer>
      </aside>
    </>
  );
}

// The floating action. One per screen at most, and only where there is
// something to add.
export function Fab({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button type="button" className="fab" aria-label={label} title={label} onClick={onClick}>
      <Icon name="plus" />
    </button>
  );
}
