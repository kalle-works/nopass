import assert from "node:assert/strict";
import { test } from "node:test";
import { checkCsp } from "./check-csp.mjs";

const origins = { production: "https://api.nopwd.dev", development: "http://localhost:3001" };
const conf = (csp, devCsp) => ({ app: { security: { csp, devCsp } } });
const good = conf(
  "default-src 'self'; connect-src 'self' ipc: http://ipc.localhost https://api.nopwd.dev",
  "default-src 'self'; connect-src 'self' ipc: http://ipc.localhost ws://localhost:1420 http://localhost:3001",
);

test("accepts a CSP that matches the API origins", () => {
  assert.deepEqual(checkCsp({ conf: good, origins }), []);
});

test("fails when a VITE_API_URL override is not in the CSP", () => {
  const problems = checkCsp({ conf: good, origins, envUrl: "https://api.example.com" });
  assert.ok(problems.some((p) => p.includes("https://api.example.com")));
});

test("fails when the CSP allows an origin the app does not use", () => {
  const loose = conf(good.app.security.csp + " https://evil.example", good.app.security.devCsp);
  assert.ok(checkCsp({ conf: loose, origins }).some((p) => p.includes("https://evil.example")));
});

test("fails when the CSP is missing", () => {
  assert.equal(checkCsp({ conf: { app: { security: { csp: null } } }, origins }).length, 2);
});

test("fails when the production CSP allows inline styles, but devCsp may", () => {
  const inline = conf(
    "default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ipc: http://ipc.localhost https://api.nopwd.dev",
    "default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ipc: http://ipc.localhost ws://localhost:1420 http://localhost:3001",
  );
  const problems = checkCsp({ conf: inline, origins });
  assert.deepEqual(problems, ["csp allows 'unsafe-inline' for scripts or styles"]);
});
