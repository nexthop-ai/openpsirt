// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { notACredential } from "../ui/noautofill";

// A number and the unit it is counted in, as a box and a list beside it: a
// duration in hours, days or weeks, a size in megabytes or gigabytes.
//
// The count is the text in the box, so an emptied box stays empty rather
// than snapping back to a number while somebody is typing over it.
export function Composer<U extends string>({
  id,
  names,
  unitLabel,
  count,
  onCount,
  unit,
  onUnit,
  units,
}: {
  id?: string;
  // The form names the two controls carry, where a form needs them.
  names?: { count: string; unit: string };
  unitLabel: string;
  count: string;
  onCount: (count: string) => void;
  unit: U;
  onUnit: (unit: U) => void;
  units: readonly { unit: U }[];
}) {
  return (
    <>
      <input
        id={id}
        name={names?.count}
        {...notACredential}
        type="number"
        min={1}
        style={{ width: 90 }}
        value={count}
        onChange={(event) => onCount(event.target.value)}
      />
      <select
        aria-label={unitLabel}
        name={names?.unit}
        {...notACredential}
        style={{ width: "auto" }}
        value={unit}
        onChange={(event) => {
          const picked = units.find((each) => each.unit === event.target.value);
          if (picked) onUnit(picked.unit);
        }}
      >
        {units.map((each) => (
          <option key={each.unit} value={each.unit}>
            {each.unit}
          </option>
        ))}
      </select>
    </>
  );
}
