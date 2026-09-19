import { notACredential } from "./noautofill";
import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { unwrap } from "../api/queries";
import { Markdown } from "./Markdown";
import { keep, restore } from "../app/drafts";
import { Icon } from "./Icons";

// Write and Preview over a plain textarea, with a formatting toolbar. Not a
// rich-text editor: what is stored is markdown, and an editor that hides that
// eventually disagrees with what gets published.
//
// Preview goes through the same renderer as published text, so the two cannot
// disagree — there is no second implementation to drift.

type Mark = { label: string; title: string; wrap: [string, string]; icon?: string };

// Enough to write a justification with, and no more. Each has to be reachable
// on a phone, so they are buttons rather than keyboard shortcuts.
//
// A mark is drawn as the character it inserts where the bundled font has one,
// and as an icon where it does not. Nothing here may fall back to a glyph
// somebody's system supplies: the fonts ride in the bundle so that an
// air-gapped install looks like any other, and a control that needs an emoji
// font is a control that is an empty box on a machine without one.
const MARKS: Mark[] = [
  { label: "B", title: "Bold", wrap: ["**", "**"] },
  { label: "I", title: "Italic", wrap: ["_", "_"] },
  { label: "`", title: "Code", wrap: ["`", "`"] },
  { label: "{ }", title: "Code block", wrap: ["```\n", "\n```"] },
  { label: "•", title: "List item", wrap: ["- ", ""] },
  { label: "", title: "Quote", wrap: ["> ", ""], icon: "quote" },
  { label: "", title: "Link", wrap: ["[", "](https://)"], icon: "link" },
];

// The people who may be offered after an @, as the editor takes them.
//
// The question is about what is being discussed rather than about who is
// asking: the endpoint answers with the people who can already read findings
// of that visibility in that product, so asking as though an undisclosed
// finding were public offers colleagues who cannot open what they are being
// called to. Written once because four screens ask it and two of them had
// started to answer it differently.
export function mentioning(
  product?: string,
  undisclosed?: boolean,
): { product: string; visibility: "public" | "private" } | undefined {
  if (!product) return undefined;
  return { product, visibility: undisclosed ? "private" : "public" };
}

export function Editor({
  value,
  onChange,
  draftKey,
  rows = 8,
  placeholder,
  label,
  mentions,
  attachTo,
}: {
  value: string;
  onChange: (next: string) => void;
  // The place an unsent draft is kept. Text somebody typed is theirs, and
  // losing it to a failed request, an expired session or a closed tab is the
  // thing that teaches people to write less.
  draftKey?: string;
  rows?: number;
  placeholder?: string;
  label?: string;
  // The product mentions are offered from. Omitted where there is none in
  // hand, in which case nothing is offered rather than everybody.
  mentions?: { product: string; visibility?: "public" | "private" };
  // The issue a file would be attached to. Omitted where there is none in
  // hand, and then no attach control is offered — a control that could not
  // say what it was attaching to would be one that guessed.
  attachTo?: { product: string; vulnerability: string };
}) {
  const [showing, setShowing] = useState<"write" | "preview">("write");
  const [typing, setTyping] = useState<string | null>(null);
  const [attaching, setAttaching] = useState(false);
  const [refused, setRefused] = useState<string | null>(null);
  const box = useRef<HTMLTextAreaElement>(null);
  const chooser = useRef<HTMLInputElement>(null);

  // Only people who can already read what this text is about. An autocomplete
  // listing everybody teaches somebody to name a colleague who then cannot
  // open what they were called to — and on an undisclosed finding the mention
  // itself would say a finding exists.
  const offerable = useQuery({
    queryKey: ["mentionable", mentions?.product, mentions?.visibility],
    enabled: typing !== null && !!mentions?.product,
    staleTime: 5 * 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/products/{product}/mentionable", {
          params: {
            path: { product: mentions?.product ?? "" },
            query: { visibility: mentions?.visibility ?? "public", limit: 50 },
          },
        }),
      ),
  });

  const candidates = (offerable.data?.items ?? []).filter((each) =>
    typing ? (each.identity ?? "").toLowerCase().startsWith(typing.toLowerCase()) : true,
  );

  // The text typed after an @, if any. Read from the text before the
  // cursor rather than tracked as state, so it stays right however somebody
  // edits — pasting, deleting, clicking elsewhere in the line.
  function partial(field: HTMLTextAreaElement): string | null {
    const upto = field.value.slice(0, field.selectionStart);
    const match = /(?:^|\s)@([A-Za-z0-9._-]*)$/.exec(upto);
    return match ? (match[1] ?? "") : null;
  }

  function complete(identity: string) {
    const field = box.current;
    if (!field) return;
    const upto = value.slice(0, field.selectionStart);
    const start = upto.lastIndexOf("@");
    if (start < 0) return;
    const next = value.slice(0, start) + "@" + identity + " " + value.slice(field.selectionStart);
    onChange(next);
    setTyping(null);
    queueMicrotask(() => {
      field.focus();
      const at = start + identity.length + 2;
      field.setSelectionRange(at, at);
    });
  }

  // Restore whatever was left behind, once per draft, and only over an empty
  // field — a draft must never overwrite something the caller supplied.
  //
  // Once per *draft*, not once per mount. The key changes under a mounted
  // editor whenever what it is about changes, and a one-shot flag meant the
  // second draft was never restored at all.
  const restored = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (restored.current === draftKey || !draftKey || value !== "") return;
    restored.current = draftKey;
    const kept = restore(draftKey);
    if (kept) onChange(kept);
  }, [draftKey, value, onChange]);

  // The text on screen is stored under the key it was typed under, never under
  // a key that arrived after it. This effect runs on a change of either, so
  // the first run after the key moves carries the old text — which wrote one
  // thing's draft into another's.
  const writtenUnder = useRef(draftKey);
  useEffect(() => {
    if (writtenUnder.current !== draftKey) {
      writtenUnder.current = draftKey;
      return;
    }
    keep(draftKey, value);
  }, [draftKey, value]);

  function surround(mark: Mark) {
    const field = box.current;
    if (!field) return;
    const [before, after] = mark.wrap;
    const start = field.selectionStart;
    const end = field.selectionEnd;
    const chosen = value.slice(start, end);
    const next = value.slice(0, start) + before + chosen + after + value.slice(end);
    onChange(next);
    // Put the cursor where somebody would carry on typing, which is inside
    // the marks when nothing was selected and after them when something was.
    queueMicrotask(() => {
      field.focus();
      const at = start + before.length + chosen.length;
      field.setSelectionRange(chosen ? at + after.length : at, chosen ? at + after.length : at);
    });
  }

  // Puts one file against the issue and writes the reference where the cursor
  // is. An image goes in as one, and everything else as a link: what decides
  // that is the type the server chose from the bytes, not the file's name.
  async function attach(file: File) {
    if (!attachTo) return;
    setAttaching(true);
    setRefused(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const answered = await api.POST("/v1/products/{product}/issues/{vulnerability}/attachments", {
        params: { path: attachTo },
        body: form as never,
        bodySerializer: (body: unknown) => body as FormData,
      });
      const stored = unwrap(answered);
      const written = stored.inline
        ? `![${stored.filename}](${stored.reference})`
        : `[${stored.filename}](${stored.reference})`;
      const field = box.current;
      const at = field ? field.selectionStart : value.length;
      onChange(value.slice(0, at) + written + value.slice(at));
      queueMicrotask(() => field?.focus());
    } catch (error) {
      // Said here rather than thrown away. The two refusals somebody can act
      // on are a file too large and a deployment with no room, and both are
      // invisible if the control simply does nothing.
      setRefused(error instanceof Error ? error.message : "That file could not be attached.");
    } finally {
      setAttaching(false);
      if (chooser.current) chooser.current.value = "";
    }
  }

  return (
    <div className="rounded-lg border border-[var(--line)] bg-[var(--surface)]">
      <div className="flex flex-wrap items-center gap-1 border-b border-[var(--line)] px-2 py-1.5">
        {MARKS.map((mark) => (
          <button
            key={mark.title}
            type="button"
            title={mark.title}
            aria-label={mark.title}
            onClick={() => surround(mark)}
            className="inline-flex min-h-8 min-w-8 items-center justify-center rounded px-2 text-sm text-[var(--muted)] hover:bg-[var(--raised)] hover:text-[var(--ink)]"
          >
            {mark.icon ? <Icon name={mark.icon} size={16} /> : mark.label}
          </button>
        ))}
        {attachTo && (
          <>
            <input
              ref={chooser}
              type="file"
              hidden
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void attach(file);
              }}
            />
            <button
              type="button"
              title="Attach a file"
              aria-label="Attach a file"
              disabled={attaching}
              onClick={() => chooser.current?.click()}
              className="inline-flex min-h-8 min-w-8 items-center justify-center rounded px-2 text-sm text-[var(--muted)] hover:bg-[var(--raised)] hover:text-[var(--ink)] disabled:opacity-50"
            >
              {attaching ? "…" : <Icon name="paperclip" size={16} />}
            </button>
          </>
        )}
        <div className="ml-auto flex gap-1">
          {(["write", "preview"] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setShowing(tab)}
              aria-pressed={showing === tab}
              className={`min-h-8 rounded px-2 text-sm ${
                showing === tab
                  ? "bg-[var(--raised)] text-[var(--ink)]"
                  : "text-[var(--muted)] hover:text-[var(--ink)]"
              }`}
            >
              {tab === "write" ? "Write" : "Preview"}
            </button>
          ))}
        </div>
      </div>

      {refused && (
        <p className="mx-3 mt-2 rounded border border-[var(--line)] bg-[var(--raised)] px-3 py-2 text-sm text-[var(--sev-critical)]">
          {refused}
        </p>
      )}

      {showing === "write" && typing !== null && candidates.length > 0 && (
        <ul className="mx-3 mt-1 max-h-40 overflow-y-auto rounded border border-[var(--line)] bg-[var(--raised)] text-sm">
          {candidates.map((each) => (
            <li key={each.identity}>
              <button
                type="button"
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => complete(each.identity ?? "")}
                className="block w-full px-3 py-1.5 text-left hover:bg-[var(--surface)]"
              >
                <span className="font-medium">@{each.identity}</span>
                {each.name && each.name !== each.identity && (
                  <span className="ml-2 text-[var(--muted)]">{each.name}</span>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}

      {showing === "write" ? (
        <textarea
          {...notACredential}
          ref={box}
          value={value}
          rows={rows}
          aria-label={label ?? "Markdown"}
          placeholder={placeholder}
          onChange={(event) => {
            onChange(event.target.value);
            setTyping(mentions?.product ? partial(event.target) : null);
          }}
          onKeyUp={(event) => setTyping(mentions?.product ? partial(event.currentTarget) : null)}
          onBlur={() => {
            // Left open, a list floating over the next control is worse than
            // no list. Delayed so a click on an entry still lands.
            window.setTimeout(() => setTyping(null), 150);
          }}
          className="w-full resize-y bg-transparent px-3 py-2 font-mono text-sm outline-none"
        />
      ) : (
        <div className="px-3 py-2 text-sm">
          {value ? (
            <Markdown source={value} />
          ) : (
            <p className="text-[var(--muted)]">Nothing written yet.</p>
          )}
        </div>
      )}
    </div>
  );
}

// forget clears a draft once its text has actually been accepted, re-exported
// here because that is where every caller already looks for it. Where a draft
// is kept, and under whose name, is decided in one place (`app/drafts`).
export { forget } from "../app/drafts";
