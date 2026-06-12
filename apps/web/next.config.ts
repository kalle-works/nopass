import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV === "development";

// The API origin must be allowed in connect-src or every vault request is
// blocked by our own CSP. Derived from the same env var the client uses.
const apiOrigin = (() => {
  try {
    return new URL(process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3001").origin;
  } catch {
    return "http://localhost:3001";
  }
})();

// nonce-based CSP would require dynamic rendering; we use a strict allowlist instead.
// 'unsafe-inline' is intentionally excluded — Next.js inlines styles at build time,
// so we allow style-src 'self' only in production.
const csp = [
  "default-src 'self'",
  // Scripts: only self + Next.js inline bootstrap (needs 'unsafe-inline' in dev only)
  isDev ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'" : "script-src 'self'",
  // Styles: self only (no CDN fonts)
  "style-src 'self' 'unsafe-inline'",
  // Fonts loaded from self (Martian Mono + IBM Plex Sans are self-hosted)
  "font-src 'self'",
  // Images: self + data URIs for inline SVG favicons
  "img-src 'self' data:",
  // Connects: self + the nopwd API + HaveIBeenPwned (only used on /vault/health)
  `connect-src 'self' ${apiOrigin} https://api.pwnedpasswords.com`,
  // Disallow all framing
  "frame-ancestors 'none'",
  // No plugins, no object embeds
  "object-src 'none'",
  // Workers: self only
  "worker-src 'self'",
  // Form submissions: self only
  "form-action 'self'",
  // Require HTTPS for all navigations
  "upgrade-insecure-requests",
].join("; ");

const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value: csp,
  },
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains; preload",
  },
];

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1"],
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
