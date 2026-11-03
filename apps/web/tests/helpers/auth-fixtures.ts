import { expect } from "vitest";
import type { IssuedCloudSession } from "@uichat-mira/cloud-auth-contracts";
import type { AuthStore } from "@/lib/auth/store";

export const account = { id: "account-1", username: "pilot" } as const;

/**
 * Fixture Cloud Session expiry, anchored an hour ahead of the test run.
 *
 * The browser store re-checks the deadline on every `getSessionToken()` call and
 * drops the persisted session once it passes, so a literal timestamp silently
 * turns every seeded "signed in" fixture into a signed-out one as real time moves
 * on. Anchoring it to the run keeps the fixture representing a live session.
 */
export const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();

export function issuedSession(sessionToken: string): IssuedCloudSession {
  return { sessionToken, account, expiresAt };
}

export function expectLoggedOutState(store: AuthStore): void {
  expect(store.getState()).toMatchObject({
    status: "unauthenticated",
    account: null,
    expiresAt: null,
    failure: null,
    pending: null,
  });
}

export function expectUnavailableState(store: AuthStore, kind = "service_unavailable"): void {
  expect(store.getState()).toMatchObject({
    status: "unavailable",
    failure: { kind },
    pending: null,
  });
}
