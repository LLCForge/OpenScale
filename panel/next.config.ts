import type { NextConfig } from "next";

// The panel is exported as static files and embedded into the openscale Go
// binary (docs/adr/0012-yonetim-paneli.md). There is no Node.js server at
// runtime, so only client-side features are used.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  poweredByHeader: false,
  reactStrictMode: true,
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
