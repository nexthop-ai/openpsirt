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
  test: { environment: "jsdom", include: ["src/**/*.test.ts"] },
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
