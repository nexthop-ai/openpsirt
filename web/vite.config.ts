// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The built assets are embedded into the Go binary and served from it, so the
// output lands where //go:embed can see it and nothing is fetched from a CDN
// at run time — an air-gapped install is a normal install for this tool.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", emptyOutDir: true, assetsDir: "assets" },
  // The renderer sanitizes what it renders, in the browser, so it is tested
  // against a corpus of payloads. DOMPurify needs a DOM to sanitize in, which
  // is what jsdom is here for.
  //
  // `.test.tsx` as well as `.test.ts`, because JSX cannot be written in a
  // `.ts` file and without the second pattern no component can be rendered in
  // a test at all. A `.tsx` *module* is importable from a `.ts` test either
  // way, so an untested pure function in a `.tsx` file is a choice rather than
  // a limit. A component is rendered with React's own root, mounted in jsdom,
  // and no rendering library is installed.
  //
  // Coverage is measured and reported for the interface the way it is for the
  // Go half, so that a figure quoted for this repository covers both.
  test: {
    environment: "jsdom",
    // Each file gets a jsdom of its own inside a VM context, rather than a
    // worker of its own: building the environment per worker was most of the
    // run. Child processes rather than threads, because a test that sets the
    // time zone needs it to take effect, and Node applies a change of `TZ`
    // only on a process's main thread.
    pool: "vmForks",
    // `scripts/` as well as `src/`, because the gate scripts live there. They
    // are `.mjs` with their detection exported, so the test beside them is an
    // ordinary `.test.ts`.
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "scripts/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text-summary"],
      include: ["src/**/*.{ts,tsx}"],
      // Generated from the API document, and the screens are compiled
      // against it — a type file has nothing to execute. The entry point
      // mounts the app and the harness is what tests draw with; neither is a
      // behavior of the interface.
      exclude: ["src/api/schema.d.ts", "src/**/*.test.{ts,tsx}", "src/main.tsx", "src/test/**"],
      // Every file is reached by some test, so a screen added with none fails
      // the run.
      thresholds: { perFile: true, statements: 1 },
    },
  },
  server: {
    // Vite refuses a Host header it does not recognize, which is protection
    // against a hostile page resolving a name to this machine. Browsing by
    // anything but localhost therefore has to say so — a hostname, not a wild
    // card, so the protection still means something.
    allowedHosts: (process.env.OPENPSIRT_DEV_HOSTS ?? "")
      .split(",")
      .map((host) => host.trim())
      .filter(Boolean),
    // In development the API is a separate process. Same-origin in production,
    // so nothing here needs CORS and no origin is configured in two places.
    proxy: {
      "/v1": {
        target: process.env.OPENPSIRT_DEV_API ?? "http://localhost:8080",
        changeOrigin: false,
        // Signing in locally otherwise needs an identity provider. The server
        // already supports a trusted header — a deployment behind a proxy that
        // authenticates for it — and this is that proxy, for one developer on
        // one machine.
        //
        // It does nothing unless OPENPSIRT_DEV_USER is set here *and* the
        // server is started trusting that header from this address. Two
        // deliberate settings, neither of which a real deployment has, and
        // this file never ships: it configures the dev server, which is not
        // the thing that serves the built interface.
        headers: process.env.OPENPSIRT_DEV_USER
          ? { "X-User": process.env.OPENPSIRT_DEV_USER }
          : undefined,
      },
    },
  },
});
