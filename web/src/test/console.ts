// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

import { afterAll, afterEach, beforeEach } from "vitest";

// Fails a test that writes to console.error or console.warn.
//
// React reports an update outside act, a missing or repeated key and a render
// that threw through console.error, and the router reports an address no route
// answers through console.warn. Each is a defect the test's assertions do not
// see, and a passing run prints it where nobody reads.
//
// A test expecting such output spies on the method itself and asserts on the
// spy: the spy takes the method's place, so what it receives is never recorded
// here. Each test starts with the recorder back in place, so a spy left behind
// silences nothing in the next test.

type Method = "error" | "warn";

type VirtualConsole = { on(event: "jsdomError", listener: (error: Error) => void): void };

const methods: Method[] = ["error", "warn"];
const printed: string[] = [];

const recorders = Object.fromEntries(
  methods.map((method) => [
    method,
    (...args: unknown[]) => {
      printed.push(`console.${method}: ${formatted(args)}`);
    },
  ]),
) as Record<Method, (...args: unknown[]) => void>;

// The arguments as the console prints them: React passes a format string
// with %s substitutions.
function formatted(args: unknown[]): string {
  const [first, ...rest] = args;
  const head =
    typeof first === "string"
      ? first.replace(/%[sdifoOc]/g, (token) =>
          token === "%c" ? (rest.shift(), "") : shown(rest.shift()),
        )
      : shown(first);
  return [head, ...rest.map(shown)].join(" ");
}

function shown(arg: unknown): string {
  if (arg instanceof Error) return arg.stack ?? arg.message;
  if (typeof arg === "string") return arg;
  try {
    return JSON.stringify(arg) ?? String(arg);
  } catch {
    return String(arg);
  }
}

function install() {
  for (const method of methods) console[method] = recorders[method];
}

// Throwing from a hook fails the test it ran for; output after the last test
// fails the file.
function report(when: string) {
  if (printed.length === 0) return;
  const said = printed.splice(0).join("\n\n");
  throw new Error(`${when} wrote to the console:\n\n${said}`);
}

install();

// jsdom reports what it does not implement, such as scrolling, on a console of
// its own outside the test's.
const environment = (globalThis as { jsdom?: { virtualConsole?: VirtualConsole } }).jsdom;
environment?.virtualConsole?.on("jsdomError", (error: Error) => {
  printed.push(`jsdom: ${error.message}`);
});

beforeEach(() => {
  install();
  report("the file, between tests,");
});

afterEach(() => report("the test"));

afterAll(() => report("the file, after its last test,"));
