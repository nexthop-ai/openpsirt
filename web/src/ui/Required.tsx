// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// The mark on a field the form will not submit without. One shape everywhere,
// drawn as a tag beside the label rather than as a word run on from it, so it
// cannot be read as part of the field's name.
export function Required() {
  return <span className="req">Required</span>;
}
