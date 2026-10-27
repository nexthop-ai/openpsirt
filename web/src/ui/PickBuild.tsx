// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useSearchParams } from "react-router-dom";
import { useProductVariants, useBranchesAndTags } from "../api/catalog";
import { Failed } from "./Failed";

// A build is a branch or tag and a variant together, never one of them: the same
// branch built two ways is two builds, and comparing across the pair without
// saying so is how a release note reports the wrong hardware.
function PickBuild({
  label,
  branch_or_tag: branchOrTag,
  variant,
  branchesAndTags,
  variants,
  onBranchOrTag,
  onVariant,
}: {
  label: string;
  branch_or_tag: string;
  variant: string;
  branchesAndTags: string[];
  variants: string[];
  onBranchOrTag: (value: string) => void;
  onVariant: (value: string) => void;
}) {
  return (
    <span style={{ display: "inline-flex", gap: 5, alignItems: "center" }}>
      <select
        aria-label={`${label} branch or tag`}
        style={{ width: "auto" }}
        value={branchOrTag}
        onChange={(event) => onBranchOrTag(event.target.value)}
      >
        <option value="">Select a branch or tag</option>
        {branchesAndTags.map((name) => (
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

// The two builds of one product the address names, and what there is to pick
// them from.
type BuildPair = ReturnType<typeof useBuildPair>;

// useBuildPair reads the earlier and the later build from the address, and the
// product's branches and tags and variants to offer. Setting a value writes the address,
// and an empty value takes the parameter off.
export function useBuildPair(product: string) {
  const [params, setParams] = useSearchParams();
  const from = params.get("from") ?? "";
  const fromVariant = params.get("from_variant") ?? "";
  const to = params.get("to") ?? "";
  const toVariant = params.get("to_variant") ?? "";

  const branchesAndTags = useBranchesAndTags(product);
  const variants = useProductVariants(product);

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
  }

  return {
    params,
    from,
    fromVariant,
    to,
    toVariant,
    ready: from !== "" && fromVariant !== "" && to !== "" && toVariant !== "",
    // The two builds alone, as every comparison of them takes them.
    pair: { from, from_variant: fromVariant, to, to_variant: toVariant },
    set,
    branchOrTagNames: (branchesAndTags.data?.items ?? []).map((each) => each.name ?? ""),
    variantNames: (variants.data?.items ?? []).map((each) => each.name ?? ""),
    readError: branchesAndTags.isError
      ? branchesAndTags.error
      : variants.isError
        ? variants.error
        : null,
  };
}

// PickPair is the two builds as two pickers, earlier then later. `set` is the
// pair's own unless the screen does more when a build changes.
export function PickPair({
  builds,
  set = builds.set,
}: {
  builds: BuildPair;
  set?: (key: string, value: string) => void;
}) {
  return (
    <>
      {builds.readError && (
        <Failed error={builds.readError} what="The builds to compare could not be read." />
      )}
      <PickBuild
        label="Earlier build"
        branch_or_tag={builds.from}
        variant={builds.fromVariant}
        branchesAndTags={builds.branchOrTagNames}
        variants={builds.variantNames}
        onBranchOrTag={(value) => set("from", value)}
        onVariant={(value) => set("from_variant", value)}
      />
      <span style={{ color: "var(--faint)" }}>to</span>
      <PickBuild
        label="Later build"
        branch_or_tag={builds.to}
        variant={builds.toVariant}
        branchesAndTags={builds.branchOrTagNames}
        variants={builds.variantNames}
        onBranchOrTag={(value) => set("to", value)}
        onVariant={(value) => set("to_variant", value)}
      />
    </>
  );
}
