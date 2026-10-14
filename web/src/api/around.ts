// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { api } from "./client";
import { unwrap } from "./queries";

// What sits above and below one component in one build, read under one key by
// the component screen and the dependency tree, so a node either opened is
// the other's cached answer.
type Build = { product: string; stream: string; variant: string };

export const aroundKey = (
  at: Build,
  component: string,
  version = "",
  ecosystem = "",
  namespace = "",
) => ["around", at, component, version, ecosystem, namespace] as const;

// A name is not always enough: a build ships some libraries at several
// versions, and a few it ships at one version as two components, which only
// the kind of package or its namespace tells apart.
export const fetchAround =
  (at: Build, component: string, version = "", ecosystem = "", namespace = "") =>
  async () =>
    unwrap(
      await api.GET(
        "/v1/products/{product}/streams/{stream}/variants/{variant}/components/{component}/around",
        {
          params: {
            path: { ...at, component },
            query: {
              ...(version ? { version } : {}),
              ...(ecosystem ? { ecosystem } : {}),
              ...(namespace ? { namespace } : {}),
            },
          },
        },
      ),
    );
