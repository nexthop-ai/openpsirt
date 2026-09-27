// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// A build is a stream and a variant together, never one of them: the same
// branch built two ways is two builds, and comparing across the pair without
// saying so is how a release note reports the wrong hardware.
export function PickBuild({
  label,
  stream,
  variant,
  streams,
  variants,
  onStream,
  onVariant,
}: {
  label: string;
  stream: string;
  variant: string;
  streams: string[];
  variants: string[];
  onStream: (value: string) => void;
  onVariant: (value: string) => void;
}) {
  return (
    <span style={{ display: "inline-flex", gap: 5, alignItems: "center" }}>
      <select
        aria-label={`${label} stream`}
        style={{ width: "auto" }}
        value={stream}
        onChange={(event) => onStream(event.target.value)}
      >
        <option value="">Select a branch or tag</option>
        {streams.map((name) => (
          <option key={name} value={name}>
            {name}
          </option>
        ))}
      </select>
      <select
        aria-label={`${label} variant`}
        style={{ width: "auto" }}
        value={variant}
        onChange={(event) => onVariant(event.target.value)}
      >
        <option value="">Select a variant</option>
        {variants.map((name) => (
          <option key={name} value={name}>
            {name}
          </option>
        ))}
      </select>
    </span>
  );
}
