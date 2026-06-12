import { describe, expect, it } from "vitest";
import { normalizeTags } from "../components/ItemEditor/TagsEditor";

describe("normalizeTags", () => {
  it("trims whitespace and drops empty entries", () => {
    expect(normalizeTags(["  work ", "", "   ", "home"])).toEqual(["work", "home"]);
  });

  it("dedupes case-insensitively, keeping the first spelling", () => {
    expect(normalizeTags(["Work", "work", "WORK", "bank"])).toEqual(["Work", "bank"]);
  });

  it("keeps insertion order", () => {
    expect(normalizeTags(["b", "a", "c"])).toEqual(["b", "a", "c"]);
  });

  it("handles comma-split fragments from paste input", () => {
    expect(normalizeTags("work, personal,  ,work".split(","))).toEqual(["work", "personal"]);
  });
});
