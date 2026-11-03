import { describe, expect, it } from "vitest";
import { readBearerToken } from "../../src/http/bearer.js";

/**
 * `readBearerToken` is the only thing standing between a raw `Authorization`
 * header and every authenticated route, so its accept/reject set is pinned
 * here rather than only exercised indirectly through contract tests.
 */
function parse(authorization: string | undefined): string | null {
  try {
    return readBearerToken({ headers: { authorization } } as never);
  } catch {
    return null;
  }
}

describe("readBearerToken", () => {
  it("extracts the token after the scheme and separator", () => {
    expect(parse("Bearer token-1")).toBe("token-1");
    expect(parse("Bearer \ttoken-2")).toBe("token-2");
    expect(parse("Bearer   token-3")).toBe("token-3");
  });

  it("accepts any casing of the scheme", () => {
    expect(parse("bearer token-1")).toBe("token-1");
    expect(parse("BEARER token-1")).toBe("token-1");
    expect(parse("BeArEr token-1")).toBe("token-1");
  });

  it("keeps whitespace that belongs to the token itself", () => {
    expect(parse("Bearer token with spaces")).toBe("token with spaces");
  });

  it("rejects a missing or empty header", () => {
    expect(parse(undefined)).toBeNull();
    expect(parse("")).toBeNull();
  });

  it("rejects a header without the scheme or the separator", () => {
    expect(parse("token-1")).toBeNull();
    expect(parse("Bearer")).toBeNull();
    expect(parse("Bearerx token-1")).toBeNull();
    expect(parse("Bearer token-1 trailing")).toBe("token-1 trailing");
  });

  it("rejects a single-whitespace header, matching the prior regex", () => {
    // `/^Bearer\s+(.+)$/` needed `.+` to consume a character, so `"Bearer "`
    // and `"Bearer \t"` never matched; the linear parser preserves that.
    expect(parse("Bearer ")).toBeNull();
    expect(parse("Bearer\t")).toBeNull();
    expect(parse("Bearer \n")).toBeNull();
  });

  it("rejects tokens containing a line terminator", () => {
    expect(parse("Bearer token\nmore")).toBeNull();
    expect(parse("Bearer token\rmore")).toBeNull();
    // A trailing newline is rejected too: `.` never matched line terminators,
    // so `/^Bearer\s+(.+)$/` could not span one even at the end.
    expect(parse("Bearer token\n")).toBeNull();
    expect(parse("Bearer token\r\n")).toBeNull();
  });
});
