import { describe, expect, it } from "vitest";

import { cn } from "@/shared/lib/cn";

describe("cn", () => {
  it("merges classes and removes conflicts", () => {
    expect(cn("px-2", "px-4", "text-sm")).toContain("px-4");
    expect(cn("px-2", "px-4", "text-sm")).not.toContain("px-2");
  });
});
