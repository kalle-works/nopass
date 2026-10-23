// Fails the build when the desktop CSP and the API base URL disagree: the app
// would otherwise ship a CSP that blocks every request to its own API.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = new URL("..", import.meta.url);

function connectOrigins(csp) {
  const directive = csp.split(";").map((d) => d.trim()).find((d) => d.startsWith("connect-src "));
  return (directive ?? "").split(/\s+/).slice(1).filter((s) => /^https?:\/\//.test(s));
}

/** Returns a list of problems; empty means the CSP and the API origins agree. */
export function checkCsp({ conf, origins, envUrl }) {
  const problems = [];
  const expected = {
    csp: new URL(envUrl || origins.production).origin,
    devCsp: new URL(envUrl || origins.development).origin,
  };
  for (const key of ["csp", "devCsp"]) {
    const value = conf.app?.security?.[key];
    if (typeof value !== "string") {
      problems.push(`app.security.${key} is not set`);
      continue;
    }
    const allowed = connectOrigins(value).filter((o) => o !== "http://ipc.localhost");
    const unexpected = allowed.filter((o) => o !== expected[key]);
    if (!allowed.includes(expected[key])) problems.push(`${key} connect-src does not allow the API origin ${expected[key]}`);
    // devCsp may additionally allow the Vite websocket, which is not http(s)
    if (unexpected.length > 0) problems.push(`${key} connect-src allows unexpected origins: ${unexpected.join(", ")}`);
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const read = (p) => JSON.parse(readFileSync(new URL(p, root), "utf8"));
  const problems = checkCsp({
    conf: read("src-tauri/tauri.conf.json"),
    origins: read("api-origin.json"),
    envUrl: process.env.VITE_API_URL,
  });
  if (problems.length > 0) {
    console.error(`CSP check failed:\n- ${problems.join("\n- ")}`);
    process.exit(1);
  }
}
