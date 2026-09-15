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
  // The renderer carries the sanitizing that used to run on the server, so it
  // is tested against the same corpus of payloads. DOMPurify needs a DOM to
  // sanitize in, which is what jsdom is here for.
  //
  // `.test.tsx` as well as `.test.ts`, because JSX cannot be written in a
  // `.ts` file and without the second pattern no component can be rendered in
  // a test at all. A `.tsx` *module* is importable from a `.ts` test either
  // way, so an untested pure function in a `.tsx` file is a choice rather than
  // a limit — and the pure functions are what is tested here. Rendering a
  // component needs a library to render it with, and none is installed:
  // nothing is gained by carrying one before the first test that renders.
  //
  // Coverage is measured and reported for the interface the way it is for the
  // Go half, so that a figure quoted for this repository covers both.
  test: {
    environment: "jsdom",
    // `scripts/` as well as `src/`, because the gate scripts live there and
    // were outside the glob: a test for one could not be collected even if
    // somebody wrote it, which is why none of the four had one. They are
    // `.mjs` with their detection exported, so the test beside them is an
    // ordinary `.test.ts`.
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "scripts/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text-summary"],
      include: ["src/**/*.{ts,tsx}"],
      // Generated from the API document, and the screens are compiled
      // against it — a type file has nothing to execute.
      exclude: ["src/api/schema.d.ts", "src/**/*.test.{ts,tsx}"],
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
