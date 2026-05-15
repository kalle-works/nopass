import { describe, expect, it } from "vitest";
import { hostnameOf, urlMatches, nameMatches } from "../lib/url-match";

describe("hostnameOf", () => {
  it("extracts hostname from https URL", () => {
    expect(hostnameOf("https://github.com/user/repo")).toBe("github.com");
  });

  it("extracts hostname from http URL", () => {
    expect(hostnameOf("http://localhost:3000/login")).toBe("localhost");
  });

  it("returns null for invalid URL", () => {
    expect(hostnameOf("not-a-url")).toBeNull();
    expect(hostnameOf("")).toBeNull();
    expect(hostnameOf("ftp://")).toBeNull();
  });

  it("handles subdomains", () => {
    expect(hostnameOf("https://accounts.google.com/login")).toBe("accounts.google.com");
  });
});

describe("urlMatches", () => {
  it("returns true when a stored URL shares the hostname with the tab URL", () => {
    expect(urlMatches(["https://github.com"], "https://github.com/login")).toBe(true);
  });

  it("returns false for different hostnames", () => {
    expect(urlMatches(["https://github.com"], "https://gitlab.com/login")).toBe(false);
  });

  it("matches across http/https scheme difference (same hostname)", () => {
    expect(urlMatches(["http://example.com"], "https://example.com/path")).toBe(true);
  });

  it("returns false when item has no URLs", () => {
    expect(urlMatches([], "https://github.com")).toBe(false);
  });

  it("returns false for invalid tab URL", () => {
    expect(urlMatches(["https://github.com"], "not-a-url")).toBe(false);
  });

  it("matches any URL in the list", () => {
    expect(urlMatches(
      ["https://github.com", "https://gitlab.com"],
      "https://gitlab.com/login",
    )).toBe(true);
  });

  it("does NOT match subdomains — requires exact hostname match", () => {
    expect(urlMatches(["https://github.com"], "https://gist.github.com")).toBe(false);
  });
});

describe("nameMatches", () => {
  it("matches case-insensitively", () => {
    expect(nameMatches("GitHub", "github")).toBe(true);
    expect(nameMatches("github", "GITHUB")).toBe(true);
  });

  it("returns true for empty query (show all)", () => {
    expect(nameMatches("GitHub", "")).toBe(true);
    expect(nameMatches("", "")).toBe(true);
  });

  it("returns false when query is not in name", () => {
    expect(nameMatches("GitHub", "gitlab")).toBe(false);
  });

  it("matches substring", () => {
    expect(nameMatches("My GitHub Account", "github")).toBe(true);
  });
});
