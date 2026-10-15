// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { act, type ReactNode } from "react";
import { answer, client, screen, settle, watchInvalidations, type Sent } from "./mount";

// Draws a mutation hook behind a button, presses it once, and returns what it
// sent and which query keys it invalidated after the request landed.
//
// The hook runs through a real query client, so a hook that stops calling its
// shared set, or calls it before the request answers, shows here.
export async function acted<T>(
  render: (node: ReactNode) => void,
  host: () => HTMLElement,
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  useHook: () => { mutate: (vars: T) => void },
  vars: T,
  status = 200,
): Promise<{ sent: Sent[]; invalidated: string[] }> {
  const sent = answer(method, () => ({ status, data: {} }));
  const queries = client();
  const invalidated = watchInvalidations(queries);
  function Act() {
    const hook = useHook();
    return (
      <button type="button" onClick={() => hook.mutate(vars)}>
        act
      </button>
    );
  }
  render(screen(<Act />, "/", "*", queries));
  await act(async () => host().querySelector("button")?.click());
  await settle();
  return { sent: sent(), invalidated: invalidated() };
}
