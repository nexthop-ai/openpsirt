// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState, type DragEvent, type ReactNode } from "react";
import { Icon } from "./Icons";

// Picking files: a zone that takes a click or a drop, with what was picked
// listed under it as chips that can be taken off again.
//
// The browser's own file input draws a button whose words and look change
// with the browser and the operating system, and it takes no drop. The input
// here is out of sight and still in the tab order, so a keyboard reaches it
// through the zone's focus ring.

// The files a pick leaves: added to what is there for a zone taking several,
// replacing it for a zone taking one. A file already listed by name and size
// is not listed twice.
export function picked(current: readonly File[], added: readonly File[], many: boolean): File[] {
  if (!many) return added.slice(0, 1);
  const seen = new Set(current.map((each) => `${each.name}\u0000${each.size}`));
  const out = [...current];
  for (const each of added) {
    const key = `${each.name}\u0000${each.size}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(each);
  }
  return out;
}

export function sizeSaid(bytes: number): string {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export function Dropzone({
  id,
  files,
  onChange,
  multiple = false,
  accept,
  disabled,
  small,
  action,
  children,
}: {
  id?: string;
  // What is picked. A zone that acts on each pick at once passes none, and
  // lists nothing under itself.
  files: readonly File[];
  onChange: (files: File[]) => void;
  multiple?: boolean;
  accept?: string;
  disabled?: boolean;
  small?: boolean;
  // The words on the button-look at the zone's end.
  action?: string;
  // What the zone says while nothing is picked.
  children: ReactNode;
}) {
  const [over, setOver] = useState(false);

  const take = (list: FileList | null) => {
    if (!list || list.length === 0 || disabled) return;
    onChange(picked(files, Array.from(list), multiple));
  };
  const onDrag = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    if (!disabled) setOver(true);
  };

  const classes = ["dropzone"];
  if (small) classes.push("small");
  if (files.length > 0) classes.push("has");
  if (over) classes.push("over");

  return (
    <>
      <label
        className={classes.join(" ")}
        aria-disabled={disabled || undefined}
        onDragEnter={onDrag}
        onDragOver={onDrag}
        onDragLeave={() => setOver(false)}
        onDrop={(event) => {
          event.preventDefault();
          setOver(false);
          take(event.dataTransfer.files);
        }}
      >
        <input
          id={id}
          type="file"
          multiple={multiple}
          accept={accept}
          disabled={disabled}
          onChange={(event) => {
            take(event.target.files);
            // Picking the same file again after taking it off still counts.
            event.target.value = "";
          }}
        />
        <Icon name="upload" />
        <span>{children}</span>
        <span className="pick">{action ?? (multiple ? "Add files" : "Choose file")}</span>
      </label>
      {files.length > 0 && (
        <ul className="picked">
          {files.map((each) => (
            <li key={`${each.name} ${each.size}`} className="chip">
              {each.name} <small>{sizeSaid(each.size)}</small>
              <button
                type="button"
                aria-label={`Remove ${each.name}`}
                title="Remove"
                disabled={disabled}
                onClick={() => onChange(files.filter((other) => other !== each))}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
