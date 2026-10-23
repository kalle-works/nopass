import { describe, expect, it } from "vitest";
import { hostnameOf, originMatches, urlMatches, nameMatches } from "../lib/url-match";

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

describe("originMatches", () => {
  // [saved item URL, page origin, may fill?]
  const cases: Array<[string, string, string, boolean]> = [
    ["same https origin", "https://github.com/login", "https://github.com", true],
    ["different site", "https://github.com", "https://gitlab.com", false],
    ["lookalike suffix", "https://github.com", "https://github.com.evil.example", false],
    ["lookalike prefix", "https://github.com", "https://evilgithub.com", false],
    ["punycode lookalike", "https://apple.com", "https://xn--pple-43d.com", false],
    ["https item never fills an http page", "https://bank.example", "http://bank.example", false],
    ["http item opts in to its http page", "http://router.example", "http://router.example", true],
    ["http item upgrades to https", "http://example.com", "https://example.com", true],
    ["http page on localhost", "https://localhost", "http://localhost", true],
    ["http page on 127.0.0.1", "https://127.0.0.1", "http://127.0.0.1", true],
    ["explicit port must match", "https://example.com:8443", "https://example.com:8443", true],
    ["different port refused", "https://example.com:8443", "https://example.com", false],
    ["portless item refuses a non-default port", "https://example.com", "https://example.com:8443", false],
    ["registrable item fills its subdomains", "https://example.com", "https://login.example.com", true],
    ["subdomain item fills only itself", "https://login.example.com", "https://other.example.com", false],
    ["subdomain item does not fill the parent", "https://login.example.com", "https://example.com", false],
    ["ICANN multi-label suffix", "https://example.co.uk", "https://shop.example.co.uk", true],
    ["sibling under a private PSL suffix", "https://foo.github.io", "https://bar.github.io", false],
    ["bare private suffix item fills no tenant", "https://github.io", "https://foo.github.io", false],
    ["bare ICANN suffix item fills no site", "https://co.uk", "https://example.co.uk", false],
    ["IP item does not act as a parent", "https://10.0.0.1", "https://1.10.0.0.1", false],
    ["non-web page scheme", "https://example.com", "file:///etc/passwd", false],
    ["non-web item scheme", "ftp://example.com", "https://example.com", false],
    ["invalid page URL", "https://example.com", "not-a-url", false],
  ];

  it.each(cases)("%s", (_label, item, page, expected) => {
    expect(originMatches(item, page)).toBe(expected);
  });
});

describe("urlMatches", () => {
  it("matches when any saved URL matches", () => {
    expect(urlMatches(["https://github.com", "https://gitlab.com"], "https://gitlab.com/login")).toBe(true);
  });

  it("returns false when item has no URLs", () => {
    expect(urlMatches([], "https://github.com")).toBe(false);
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
