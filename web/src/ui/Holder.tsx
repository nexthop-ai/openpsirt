import { useRef, useState } from "react";
import { useClickAway } from "./away";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { notACredential } from "./noautofill";
import { useWho } from "../app/session";

// The party work is handed to: a person or a team, found by typing.
//
// Typed rather than chosen from everybody: a deployment with a hundred people
// is a hundred options to scroll with no way to reach the one you want. The
// narrowing is the server's, because a list capped before it is filtered would
// leave out the name somebody typed and then report that nothing matched.
//
// Teams as well as people, because a team holds work exactly as a person does.
// They sort above people: there are few of them, and a picker that buries
// three teams under twenty-five names is one where the team is never found.
//
// Yourself first, because taking work is the common case and needs no more
// right than reaching this control does. Read from who is signed in rather
// than found among what the server answered, so it is offered whether or not
// your own name is in the twenty-five that came back.

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
  // The kind of work being handed over, so the people offered are the
  // ones who could open it.
  undisclosed?: boolean;
  // The present holder, shown when the field is not being typed in.
  value?: { identity: string; name?: string } | null;
  onPick: (held: Held | null) => void;
  disabled?: boolean;
  placeholder?: string;
  // The label for choosing nobody.
  none?: string;
}) {
  const [typed, setTyped] = useState("");
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState(-1);
  const box = useRef<HTMLDivElement>(null);
  const who = useWho();
  // The present holder, which the field states rather than suggests. Drawn as
  // the placeholder, a held finding shows the holder's name in the grey a
  // browser paints text nobody has typed, so work somebody has taken reads as
  // an empty box prompting for a name. While the list is open the field is a
  // search box again, because that is what somebody is doing with it.
  const holder = value?.identity ? (value.name ?? value.identity) : "";

  // Closing without a pick puts the field back to stating who holds it. A
  // half-typed fragment left in it reads as a name somebody chose, now that
  // what the field holds is drawn in ink.
  function close() {
    setTyped("");
    setOpen(false);
    setAt(-1);
  }

  useClickAway(box, open, close, false);

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

  // Yourself, where you are a person: a credential is not a party work can be
  // handed to. Not offered where you already hold it, because there is nothing
  // to do, and dropped while what is typed does not match your own name, so
  // typing narrows the whole list rather than all of it but one row.
  const me = who.data;
  const term = typed.trim().toLowerCase();
  const yours: Held | null =
    me?.kind === "person" && me.identity !== "" && value?.identity !== me.identity
      ? { kind: "person", identity: me.identity, name: me.name || me.identity }
      : null;
  const you =
    yours &&
    (term === "" ||
      yours.name.toLowerCase().includes(term) ||
      yours.identity.toLowerCase().includes(term))
      ? yours
      : null;

  // Every row the arrows walk, in the order they are drawn. Nobody is one of
  // them: it is a choice like the others, and a row the keyboard could not
  // reach was one somebody had to take a hand off the keys for. A null stands
  // for it, which is what choosing it sends.
  const rows: (Held | null)[] = [
    ...(you ? [you] : []),
    null,
    ...offered.filter((held) => !(you && held.kind === "person" && held.identity === you.identity)),
  ];

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
        aria-label="The holder of this"
        disabled={disabled}
        placeholder={holder ? "" : placeholder}
        value={open || typed !== "" ? typed : holder}
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
            setAt((was) => Math.min(rows.length - 1, was + 1));
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            setAt((was) => Math.max(-1, was - 1));
          } else if (event.key === "Enter" && at >= 0 && at < rows.length) {
            event.preventDefault();
            choose(rows[at] ?? null);
          } else if (event.key === "Escape") {
            close();
          }
        }}
      />
      {open && (
        <ul className="suggestions" role="listbox">
          {rows.map((held, i) => (
            <li
              key={held ? `${held.kind} ${held.identity}` : "nobody"}
              aria-selected={i === at}
              role="option"
            >
              <button
                type="button"
                className={i === at ? "on" : undefined}
                onClick={() => choose(held)}
              >
                {held ? held.name : none}
                {/* What it is, beside the name and not under it: a team and a
                    person share one name space, and which of the two decides
                    who is told — a person is interrupted, a queue filling up
                    is not. */}
                {held && (
                  <span className="hint">
                    {" "}
                    {held === you ? "you" : held.kind === "team" ? "team" : "person"}
                  </span>
                )}
              </button>
            </li>
          ))}
          {found.isFetching && offered.length === 0 && <li className="hint">Looking…</li>}
          {!found.isFetching && offered.length === 0 && (
            <li className="hint">Nobody here is called that.</li>
          )}
        </ul>
      )}
    </div>
  );
}
