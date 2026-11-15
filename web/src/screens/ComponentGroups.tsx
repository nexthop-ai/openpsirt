// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Body } from "../api/client";
import { beneathOf, unwrap } from "../api/queries";
import { analyticsReportAt, buildFindingsAt, dependenciesAt, type Build } from "../app/routes";
import { Empty } from "../ui/Empty";
import { Failed } from "../ui/Failed";
import { Loading } from "../ui/Loading";
import { Shape } from "../ui/Shape";
import { Wide } from "../ui/Wide";

// A build's components listed by repository or by ecosystem instead of as a
// tree. Grouping is presentation: every count is the tree's unit, once per
// issue in each package, and each row opens the burndown and the findings list
// for what it counts.

export type Listing = "tree" | "repository" | "ecosystem";
type Group = Body<"GroupBody">;

const NO_ECOSYSTEM = "none";

// The ways the screen lists a build, as the switch offers them.
export const LISTINGS: { list: Listing; words: string }[] = [
  { list: "tree", words: "Tree" },
  { list: "repository", words: "By repository" },
  { list: "ecosystem", words: "By ecosystem" },
];

// Where a repository row's subtree starts: its one component, which is what
// the row counts on this build, or every component of its package identifier
// where it ships several commits.
function beneathRow(row: Group) {
  return row.component ? beneathOf(row.component.name, row.component) : { beneath_purl: row.key };
}

// The burndown of what a row counts. A repository is its subtree on this
// build; any other row is chosen by its package identifier, at any version,
// across the scope.
function burndownOf(at: Build, by: Listing, row: Group, ecosystem: string): string | null {
  if (by === "repository") {
    return analyticsReportAt("findings-burndown", {
      branch_or_tag: at.branch_or_tag,
      variant: at.variant,
      ...beneathRow(row),
    });
  }
  const purl = by === "ecosystem" && !ecosystem ? `pkg:${row.key}/` : row.key;
  if (!purl.startsWith("pkg:") || row.key === NO_ECOSYSTEM) return null;
  return analyticsReportAt("findings-burndown", {
    branch_or_tag: at.branch_or_tag,
    variant: at.variant,
    purl,
  });
}

// The findings list for a row: a repository's subtree on this build, an
// ecosystem's components, and a package by its package identifier at every
// version, as its burndown chooses. A name within its kind is no package: it
// spans namespaces the row keeps apart. Components with no identifier have
// none, since nothing names them.
function findingsOf(at: Build, by: Listing, row: Group, ecosystem: string): string | null {
  if (by === "repository") return buildFindingsAt(at, beneathRow(row));
  if (!ecosystem) {
    return row.key === NO_ECOSYSTEM ? null : buildFindingsAt(at, { ecosystem: row.key });
  }
  return row.key.startsWith("pkg:") ? buildFindingsAt(at, { purl: row.key }) : null;
}

export function ComponentGroups({
  at,
  by,
  ecosystem,
}: {
  at: Build;
  by: "repository" | "ecosystem";
  ecosystem: string;
}) {
  const groups = useQuery({
    queryKey: ["component-groups", at, by, ecosystem],
    queryFn: async () =>
      unwrap(
        await api.GET(
          "/v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/component-groups",
          {
            params: {
              path: at,
              query: { by, ...(by === "ecosystem" && ecosystem ? { ecosystem } : {}) },
            },
          },
        ),
      ),
  });
  if (groups.isPending) return <Loading />;
  if (groups.isError) {
    return <Failed error={groups.error} what="The build's components could not be grouped." />;
  }
  const rows = groups.data.items ?? [];
  const packages = by === "ecosystem" && ecosystem !== "";
  if (rows.length === 0) {
    return (
      <Empty
        title={by === "repository" ? "No repositories." : "Nothing here."}
        detail={
          by === "repository"
            ? "No component here has a pkg:github identifier."
            : "No component here is in this ecosystem."
        }
      />
    );
  }
  return (
    <>
      {packages && (
        <p className="hint" style={{ marginTop: 0 }}>
          <Link to={dependenciesAt(at, { list: "ecosystem" })}>Every ecosystem</Link> · {ecosystem}
        </p>
      )}
      <Wide>
        <table>
          <thead>
            <tr>
              <th>{by === "repository" ? "Repository" : packages ? "Package" : "Ecosystem"}</th>
              <th>{by === "repository" ? "Shipped" : packages ? "Versions" : "Components"}</th>
              <th className="num" title="Once per issue in each package">
                Open
              </th>
              <th />
              <th className="num" title="Fixed, with nothing of it open now">
                Fixed
              </th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const burn = burndownOf(at, by, row, ecosystem);
              const list = findingsOf(at, by, row, ecosystem);
              return (
                <tr key={row.key}>
                  <td className="id">
                    {by === "ecosystem" && !packages ? (
                      <Link to={dependenciesAt(at, { list: "ecosystem", ecosystem: row.key })}>
                        {row.key}
                      </Link>
                    ) : (
                      row.key
                    )}
                  </td>
                  <td className="id hint">
                    {by === "ecosystem" && !packages
                      ? row.components.toLocaleString()
                      : (row.versions ?? []).join(", ")}
                  </td>
                  <td className="num">{row.open.toLocaleString()}</td>
                  <td>
                    <Shape by={row.open_by_severity} key_={false} />
                  </td>
                  <td className="num">{row.fixed.toLocaleString()}</td>
                  <td className="hint">
                    {list && <Link to={list}>Findings</Link>}
                    {list && burn && " · "}
                    {burn && <Link to={burn}>Burndown</Link>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Wide>
      <p className="hint">
        {by === "repository"
          ? "A repository counts its own components and everything under them."
          : "Each row counts its own components only."}
      </p>
    </>
  );
}
