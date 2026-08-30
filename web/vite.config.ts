import { defineConfig } from "vite";

// The console is embedded in the daemon (ADR-0011), so the build has two
// unusual requirements and one ordinary one.
//
// Everything must be inlined or emitted as a local file: no CDN, no runtime
// fetch, no external font. An air-gapped install cannot reach the network, and
// a console that half-loads is worse than one that says it is missing.
//
// The output goes straight into the Go package that embeds it, so there is one
// place the bundle lives and no copy step to forget.
export default defineConfig({
  build: {
    outDir: "../internal/console/dist",
    emptyOutDir: true,
    // Everything in one place with hashed names: index.html is served with no
    // cache and names these, so they can be cached forever.
    assetsDir: "assets",
    // No source maps in the shipped binary. They would roughly double its
    // size to serve something only a console developer wants, and `npm run
    // dev` gives them the real thing.
    sourcemap: false,
    target: "es2022",
    // Small enough that a warning about chunk size would only be noise.
    chunkSizeWarningLimit: 1024,
  },
  server: {
    // `npm run dev` proxies to a daemon on a TCP listener, so the console can
    // be developed against a real campaign rather than against fixtures.
    proxy: {
      "/v1": {
        target: process.env.XFUZZ_ADDR ?? "http://127.0.0.1:7777",
        changeOrigin: true,
      },
    },
  },
});
