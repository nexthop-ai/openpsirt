// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { Drawer, Fab } from "./Drawer";
import { Failed } from "./Failed";
import { Icon } from "./Icons";

// Declaring something into the catalog: an action, not a form above the table.
// Products, branches and variants are declared rather than discovered — a
// misspelled release is indistinguishable from a real one, so a scan naming
// something nobody declared is refused instead of quietly creating it.

// The header control that opens the drawer, and the floating action beside it.
export function AddButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <>
      <span style={{ marginLeft: "auto" }}>
        <button type="button" className="btn" onClick={onClick}>
          <Icon name="plus" size={14} /> {label}
        </button>
      </span>
      <Fab label={label} onClick={onClick} />
    </>
  );
}

export function Declare({
  title,
  open,
  onClose,
  hint,
  children,
  onSubmit,
  error,
  busy,
  ok,
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  hint: string;
  children: ReactNode;
  onSubmit: () => void;
  error: unknown;
  busy: boolean;
  ok: string;
}) {
  return (
    <Drawer
      open={open}
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" disabled={busy} onClick={onSubmit}>
            {ok}
          </button>
          <button type="button" className="btn quiet" onClick={onClose}>
            Cancel
          </button>
        </>
      }
    >
      {error != null && <Failed error={error} what={`That could not be declared.`} />}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy) onSubmit();
        }}
      >
        {children}
      </form>
      <p className="reading">{hint}</p>
    </Drawer>
  );
}

// One labeled input, so the forms look like one thing.
export function Field({
  label,
  value,
  onChange,
  placeholder,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  hint?: string;
}) {
  const id = `declare-${label.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        type="text"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}
