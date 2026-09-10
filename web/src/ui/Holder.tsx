import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { notACredential } from "./noautofill";

// Who work is being handed to: a person or a team, found by typing.
//
// **It was a select fed by the mentions endpoint**, which answers who can
// already *read* a finding. That is right for offering a name inside text and
// wrong here twice over — a team cannot be mentioned in prose but is a
// perfectly good holder of work, so no finding could be handed to a team from
// the interface at all, though the API has taken one from the start.
//
// **And a select is the wrong control at this size.** A deployment with a
// hundred people is a hundred options to scroll, with no way to type toward
// the one you want. The narrowing is the server's, because a list that is
// capped before it is filtered would leave out the name somebody typed and
// then report that nothing matched.
//
// Teams sort above people: there are few of them, and a picker that buries
// three teams under twenty-five names is one where the team is never found.

export type Held = { kind: "person" | "team"; identity: string; name: string };

export function Holder({
  product,
  undisclosed,
  value,
  onPick,
  disabled,
  placeholder = "Type a name or a team",
  none = "No one",
}: {
  product: string;
  // Which kind of work is being handed over, so the people offered are the
  // ones who could open it.
  undisclosed?: boolean;
  // What is held now, shown when the field is not being typed in.
  value?: { identity: string; name?: string } | null;
  onPick: (held: Held | null) => void;
  disabled?: boolean;
  placeholder?: string;
  // What choosing nobody is called here.
  none?: string;
}) {
  const [typed, setTyped] = useState("");
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState(-1);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function away(event: MouseEvent) {
      if (box.current && !box.current.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const found = useQuery({
    enabled: open && product !== "",
    queryKey: ["holders", product, undisclosed === true, typed.trim()],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/holders", {
          params: {
            path: { product },
            query: {
              ...(undisclosed ? { visibility: "private" as const } : {}),
              ...(typed.trim() ? { q: typed.trim() } : {}),
              limit: 25,
            },
          },
        }),
      ),
    retry: false,
  });
  const offered = (found.data?.items ?? []) as Held[];

  function choose(held: Held | null) {
    onPick(held);
    setTyped("");
    setOpen(false);
    setAt(-1);
  }

  return (
    <div className="suggest" ref={box}>
      <input
        {...notACredential}
        type="text"
        role="combobox"
        aria-expanded={open}
        aria-autocomplete="list"
        aria-label="Who holds this"
        disabled={disabled}
        placeholder={value?.identity ? (value.name ?? value.identity) : placeholder}
        value={typed}
        onFocus={() => setOpen(true)}
        onChange={(event) => {
          setTyped(event.target.value);
          setOpen(true);
          setAt(-1);
        }}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault();
            setOpen(true);
            setAt((was) => Math.min(offered.length - 1, was + 1));
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            setAt((was) => Math.max(-1, was - 1));
          } else if (event.key === "Enter" && at >= 0 && offered[at]) {
            event.preventDefault();
            choose(offered[at]);
          } else if (event.key === "Escape") {
            setOpen(false);
          }
        }}
      />
      {open && (
        <ul className="suggestions" role="listbox">
          <li>
            <button type="button" onClick={() => choose(null)}>
              {none}
            </button>
          </li>
          {found.isFetching && offered.length === 0 && <li className="hint">Looking…</li>}
          {!found.isFetching && offered.length === 0 && (
            <li className="hint">Nobody here is called that.</li>
          )}
          {offered.map((held, i) => (
            <li key={`${held.kind} ${held.identity}`} aria-selected={i === at} role="option">
              <button
                type="button"
                className={i === at ? "on" : undefined}
                onClick={() => choose(held)}
              >
                {held.name}
                {/* Which of the two it is, because a team and a person share
                    one name space and the difference decides who is told: a
                    person is interrupted, a queue filling up is not. */}
                <span className="hint"> {held.kind === "team" ? "team" : "person"}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
