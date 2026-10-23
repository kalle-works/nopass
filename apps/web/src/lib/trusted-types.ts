// Trusted Types enforcement (`require-trusted-types-for 'script'`, see csp.ts).
//
// The only sink the app feeds a plain string is `script.src`: the Turbopack
// runtime loads route chunks by assigning "/_next/static/chunks/<name>.js".
// The "default" policy below hands out a TrustedScriptURL for exactly that
// shape and refuses everything else. It defines no createHTML or createScript,
// so innerHTML, eval-style sinks and inline script text stay blocked, and the
// CSP lists no other policy names, so injected code cannot register a
// permissive policy of its own.

type ScriptUrlPolicyFactory = {
  createPolicy(name: string, rules: { createScriptURL(input: string): string }): unknown;
};

/**
 * Must stay self-contained (no outer references): it is serialized into an
 * inline script that runs before any bundle.
 */
export function installScriptUrlPolicy(factory: ScriptUrlPolicyFactory | undefined, origin: string): void {
  if (!factory) return;
  factory.createPolicy("default", {
    createScriptURL(input: string): string {
      let url: URL;
      try {
        url = new URL(input, origin);
      } catch {
        throw new TypeError("blocked script URL");
      }
      const chunkPath = /^\/_next\/static\/[A-Za-z0-9_\-./~%]+\.js$/;
      if (url.origin !== origin || !chunkPath.test(url.pathname) || url.pathname.includes("..")) {
        throw new TypeError("blocked script URL");
      }
      return input;
    },
  });
}

/** Inline script text that installs the policy; render it first in <head>. */
export const TRUSTED_TYPES_BOOT_SCRIPT = `(${installScriptUrlPolicy.toString()})(window.trustedTypes, location.origin)`;
