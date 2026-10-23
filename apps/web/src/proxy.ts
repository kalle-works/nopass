import { NextResponse, type NextRequest } from "next/server";
import { buildCsp, resolveApiOrigin } from "@/lib/csp";

const apiOrigin = resolveApiOrigin(process.env.NEXT_PUBLIC_API_URL);

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = buildCsp({ nonce, isDev: process.env.NODE_ENV === "development", apiOrigin });

  // Next.js reads the nonce from the request's CSP header while rendering and
  // stamps it on framework scripts and styles; x-nonce is for our own tags.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
