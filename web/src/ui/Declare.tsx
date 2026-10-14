// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { Drawer, Fab } from "./Drawer";
import { Failed } from "./Failed";
import { Icon } from "./Icons";
import { notACredential } from "./noautofill";

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

// Whether what a place builds reaches customers, as a yes or no. One control,
// because its wording and what it feeds have to read the same wherever a place
// is declared or edited.
export function FacingField({
  id,
  value,
  onChange,
}: {
  id: string;
  value: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>Ships to customers</label>
      <select
        id={id}
        value={value ? "yes" : "no"}
        onChange={(event) => onChange(event.target.value === "yes")}
      >
        <option value="yes">Yes</option>
        <option value="no">No</option>
      </select>
      <span className="hint">Feeds how urgent a finding here is</span>
    </div>
  );
}

// One labeled input, so the forms look like one thing.
//
// No field here is a sign-in, so every one says so to a password manager. A
// secret one is masked and kept out of the browser's form history, which would
// otherwise hold a signing secret or a token-bearing address and offer it in
// the next field of the same name.
export function Field({
  label,
  value,
  onChange,
  placeholder,
  hint,
  secret = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  hint?: string;
  secret?: boolean;
}) {
  const id = `declare-${label.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        {...notACredential}
        {...(secret ? { type: "password", autoComplete: "new-password" } : { type: "text" })}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}
