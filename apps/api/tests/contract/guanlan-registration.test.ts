import { createHmac, timingSafeEqual } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createGuanlanRegistrationTransport } from "../../src/guanlan-registration.js";

const secret = "contract-fixture-secret-with-at-least-32-bytes";
const accountId = "cloud-account-uuid-001";

/** Contract fixture mirrors the Guanlan receiver requirements; it is not production receiver code. */
function verifyAndRegister(headers: Headers, body: string, spaces: Set<string>, nowSeconds: number): Response {
  const timestamp = headers.get("x-mira-timestamp") ?? "";
  const signature = headers.get("x-mira-signature") ?? "";
  if (!/^\d+$/.test(timestamp) || Math.abs(nowSeconds - Number(timestamp)) > 300) {
    return Response.json({ error: "invalid_timestamp" }, { status: 401 });
  }
  const expected = "sha256=" + createHmac("sha256", secret).update(timestamp + "." + body).digest("hex");
  const actualBytes = Buffer.from(signature);
  const expectedBytes = Buffer.from(expected);
  if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) {
    return Response.json({ error: "invalid_signature" }, { status: 401 });
  }
  const payload: unknown = JSON.parse(body);
  if (typeof payload !== "object" || payload === null ||
      (payload as { version?: unknown }).version !== 1 ||
      typeof (payload as { accountId?: unknown }).accountId !== "string" ||
      !(payload as { accountId: string }).accountId.trim()) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }
  // Set models Guanlan's UNIQUE account_id / INSERT OR IGNORE idempotency.
  spaces.add((payload as { accountId: string }).accountId);
  return Response.json({ accountId: (payload as { accountId: string }).accountId, registered: true });
}

describe("GLN-012 Cloud Auth ↔ Guanlan registration contract", () => {
  it("sends the canonical account ID with a verifiable timestamped HMAC; duplicate registration is idempotent", async () => {
    const spaces = new Set<string>();
    const fetcher: typeof fetch = async (_input, init) => {
      const body = String(init?.body ?? "");
      const headers = new Headers(init?.headers);
      const response = verifyAndRegister(headers, body, spaces, Number(headers.get("x-mira-timestamp")));
      return response;
    };
    const transport = createGuanlanRegistrationTransport("https://guanlan.example/internal/register", secret, fetcher);
    expect(await transport.send(accountId)).toBe(true);
    expect(await transport.send(accountId)).toBe(true);
    expect(spaces.size).toBe(1);
    expect(spaces.has(accountId)).toBe(true);
  });

  it("receiver fixture rejects stale timestamps and tampered payload signatures", () => {
    const spaces = new Set<string>();
    const body = JSON.stringify({ version: 1, accountId });
    const timestamp = "1000";
    const signature = "sha256=" + createHmac("sha256", secret).update(timestamp + "." + body).digest("hex");
    const stale = verifyAndRegister(new Headers({ "x-mira-timestamp": timestamp, "x-mira-signature": signature }), body, spaces, 2000);
    expect(stale.status).toBe(401);
    const tampered = verifyAndRegister(new Headers({ "x-mira-timestamp": "1000", "x-mira-signature": signature }), JSON.stringify({ version: 1, accountId: "other-account" }), spaces, 1000);
    expect(tampered.status).toBe(401);
    expect(spaces.size).toBe(0);
  });

  it("does not treat a mismatched receiver receipt as successful delivery", async () => {
    const transport = createGuanlanRegistrationTransport(
      "https://guanlan.example/internal/register", secret,
      async () => Response.json({ accountId: "another-account", registered: true }),
    );
    expect(await transport.send(accountId)).toBe(false);
  });
});
