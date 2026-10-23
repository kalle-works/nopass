import { describe, expect, it, vi } from "vitest";
import { takeShareKey } from "../share-key";

function fakeWindow(hash: string) {
  const replaceState = vi.fn();
  return {
    win: { location: { hash, pathname: "/s/abc", search: "?ref=mail" }, history: { replaceState } },
    replaceState,
  };
}

describe("takeShareKey", () => {
  it("returns the key and strips the fragment from the URL", () => {
    const { win, replaceState } = fakeWindow("#k=SECRETKEY");
    expect(takeShareKey(win)).toBe("SECRETKEY");
    // pathname and query stay, the fragment is gone
    expect(replaceState).toHaveBeenCalledWith(null, "", "/s/abc?ref=mail");
  });

  it("leaves the URL alone when there is no key", () => {
    const { win, replaceState } = fakeWindow("#other=1");
    expect(takeShareKey(win)).toBeNull();
    expect(replaceState).not.toHaveBeenCalled();
  });
});
