import { describe, expect, it, vi } from "vitest";
import type { CloudSession } from "@uichat-mira/cloud-auth-contracts";
import type { CloudAuthClient } from "@/lib/auth/client";
import { CloudAuthError, createAuthFailure } from "@/lib/auth/errors";
import type { PersistedCloudSession } from "@/lib/auth/session-storage";
import { createMemoryStorage } from "../helpers/session-storage";
import {
  account,
  expiresAt,
  expectLoggedOutState,
  expectUnavailableState,
  issuedSession,
} from "../helpers/auth-fixtures";
import { createAuthStore, type AuthStore } from "@/lib/auth/store";

function cloudSession(): CloudSession {
  return { account, expiresAt };
}

function createClient(overrides: Partial<CloudAuthClient> = {}): CloudAuthClient {
  return {
    login: async () => issuedSession("token-1"),
    getSession: async () => cloudSession(),
    renewSession: async () => issuedSession("token-2"),
    changePassword: async () => undefined,
    logout: async () => undefined,
    ...overrides,
  };
}

async function createAuthenticatedLogoutStore(
  logout: CloudAuthClient["logout"] = async () => undefined,
): Promise<{
  store: AuthStore;
  storage: ReturnType<typeof createMemoryStorage>;
  stored: PersistedCloudSession;
}> {
  const storage = createMemoryStorage();
  const store = createAuthStore({
    client: createClient({ logout }),
    storage,
  });

  await store.getState().login("pilot", "password");
  const stored = storage.load();
  if (!stored) throw new Error("Expected login to persist a Cloud Session");

  return { store, storage, stored };
}

function createRestoreFailureStore(
  storage: ReturnType<typeof createMemoryStorage>,
  kind: "reauth_required" | "service_unavailable",
): AuthStore {
  return createAuthStore({
    client: createClient({
      getSession: async () => {
        throw new CloudAuthError(createAuthFailure(kind));
      },
    }),
    storage,
  });
}

describe("auth store", () => {
  it("stores the issued session after login without exposing token in state", async () => {
    const storage = createMemoryStorage();
    const store = createAuthStore({ client: createClient(), storage });

    await store.getState().login("pilot", "correct horse battery staple");

    expect(store.getState()).toMatchObject({
      status: "authenticated",
      account,
      expiresAt,
      failure: null,
      pending: null,
    });
    expect(storage.load()).toEqual({ sessionToken: "token-1", expiresAt });
    expect(JSON.stringify(store.getState())).not.toContain("token-1");
  });

  it("keeps a stable failure state for invalid credentials", async () => {
    const storage = createMemoryStorage();
    const store = createAuthStore({
      client: createClient({
        login: async () => {
          throw new CloudAuthError(createAuthFailure("invalid_credentials"));
        },
      }),
      storage,
    });

    await store.getState().login("pilot", "wrong");

    expect(store.getState()).toMatchObject({
      status: "unauthenticated",
      account: null,
      pending: null,
      failure: { kind: "invalid_credentials", message: "账号或密码不正确。" },
    });
    expect(storage.load()).toBeNull();
  });

  it("clears the stored session when restore returns 401", async () => {
    const storage = createMemoryStorage({
      sessionToken: "token-1",
      expiresAt,
    });
    const store = createRestoreFailureStore(storage, "reauth_required");

    await store.getState().restore();

    expect(store.getState()).toMatchObject({
      status: "unauthenticated",
      account: null,
      failure: { kind: "reauth_required" },
      pending: null,
    });
    expect(storage.load()).toBeNull();
  });

  it("preserves the stored session when restore is transiently unavailable", async () => {
    const stored = { sessionToken: "token-1", expiresAt };
    const storage = createMemoryStorage(stored);
    const store = createRestoreFailureStore(storage, "service_unavailable");

    await store.getState().restore();

    expectUnavailableState(store);
    expect(storage.load()).toEqual(stored);
  });

  it("treats a locally expired session as signed out instead of handing out its token", async () => {
    // The store enforces the deadline itself, so an already-expired credential
    // must never reach a privileged request. This is the behaviour that a
    // literal fixture timestamp silently violated once real time passed it.
    //
    // Start from a genuinely signed-in store, then let the deadline lapse: when
    // `account`/`expiresAt` are already `null` at creation, asserting them
    // afterwards would only restate the initial state and prove nothing.
    const storage = createMemoryStorage();
    const store = createAuthStore({ client: createClient(), storage });
    await store.getState().login("pilot", "correct horse battery staple");
    expect(store.getState()).toMatchObject({ status: "authenticated", account, expiresAt });

    storage.save({
      sessionToken: "expired-token",
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });

    expect(store.getState().getSessionToken()).toBeNull();
    expect(storage.load()).toBeNull();
    expect(store.getState()).toMatchObject({
      status: "unauthenticated",
      account: null,
      expiresAt: null,
      failure: { kind: "reauth_required" },
    });
  });

  it("rejects a credential the moment its deadline is reached", () => {
    // The guard is `<=`, so the deadline itself is already too late. Pin that
    // edge so a later `<` refactor cannot quietly hand out the last token.
    const deadline = new Date(Date.now() - 30 * 60_000).toISOString();
    const storage = createMemoryStorage({ sessionToken: "boundary-token", expiresAt: deadline });
    const store = createAuthStore({ client: createClient(), storage });

    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date(deadline));
      expect(store.getState().getSessionToken()).toBeNull();
    } finally {
      vi.useRealTimers();
    }
    expect(storage.load()).toBeNull();
    expect(store.getState()).toMatchObject({
      status: "unauthenticated",
      failure: { kind: "reauth_required" },
    });
  });

  it("keeps returning the token while the session is still live", () => {
    const storage = createMemoryStorage({ sessionToken: "live-token", expiresAt });
    const store = createAuthStore({ client: createClient(), storage });

    expect(store.getState().getSessionToken()).toBe("live-token");
    expect(storage.load()).toEqual({ sessionToken: "live-token", expiresAt });
  });

  it("rotates the stored token after renewal", async () => {
    const storage = createMemoryStorage({
      sessionToken: "token-1",
      expiresAt,
    });
    const store = createAuthStore({ client: createClient(), storage });

    await store.getState().renew();

    expect(store.getState()).toMatchObject({
      status: "authenticated",
      account,
      expiresAt,
      notice: "session_renewed",
    });
    expect(storage.load()).toEqual({ sessionToken: "token-2", expiresAt });
  });

  it("does not report renewal success when an older pending renew finishes after a new login", async () => {
    let finishRenew: ((value: ReturnType<typeof issuedSession>) => void) | undefined;
    const storage = createMemoryStorage({ sessionToken: "old", expiresAt });
    const store = createAuthStore({
      storage,
      client: createClient({
        login: async () => issuedSession("new-login"),
        renewSession: async () =>
          new Promise<ReturnType<typeof issuedSession>>((resolve) => {
            finishRenew = resolve;
          }),
      }),
    });
    await store.getState().restore();
    const staleRenew = store.getState().renew();
    store.getState().invalidateSession("old");
    await store.getState().login("pilot", "password");
    finishRenew?.(issuedSession("stale-renew"));
    await staleRenew;
    expect(storage.load()?.sessionToken).toBe("new-login");
    expect(store.getState()).toMatchObject({
      status: "authenticated",
      notice: null,
      pending: null,
    });
  });

  it("clears the local session and announces forced re-login after a password change", async () => {
    const storage = createMemoryStorage({ sessionToken: "token-1", expiresAt });
    const calls: Array<{
      token: string;
      currentPassword: string;
      newPassword: string;
    }> = [];
    const store = createAuthStore({
      client: createClient({
        changePassword: async (token, request) => {
          calls.push({ token, ...request });
        },
      }),
      storage,
    });
    await store.getState().restore();

    await store
      .getState()
      .changePassword("correct horse battery staple", "another strong replacement passphrase");

    expect(calls).toEqual([
      {
        token: "token-1",
        currentPassword: "correct horse battery staple",
        newPassword: "another strong replacement passphrase",
      },
    ]);
    expect(store.getState()).toMatchObject({
      status: "unauthenticated",
      account: null,
      expiresAt: null,
      failure: null,
      notice: "password_changed",
      pending: null,
    });
    expect(storage.load()).toBeNull();
    expect(JSON.stringify(store.getState())).not.toContain("correct horse battery staple");
  });

  it("keeps the session usable when the current password is incorrect", async () => {
    const storage = createMemoryStorage({ sessionToken: "token-1", expiresAt });
    const store = createAuthStore({
      client: createClient({
        changePassword: async () => {
          throw new CloudAuthError(
            createAuthFailure("invalid_credentials", {
              status: 401,
              code: "AUTH_INVALID_CREDENTIALS",
            }),
          );
        },
      }),
      storage,
    });
    await store.getState().restore();

    await store.getState().changePassword("wrong", "another strong replacement passphrase");

    expect(store.getState()).toMatchObject({
      status: "authenticated",
      account,
      expiresAt,
      pending: null,
      failure: { kind: "invalid_credentials" },
    });
    expect(storage.load()).toEqual({ sessionToken: "token-1", expiresAt });
  });

  it("keeps the session usable when the new password fails policy", async () => {
    const storage = createMemoryStorage({ sessionToken: "token-1", expiresAt });
    const store = createAuthStore({
      client: createClient({
        changePassword: async () => {
          throw new CloudAuthError(
            createAuthFailure("invalid_password", {
              status: 400,
              code: "AUTH_INVALID_PASSWORD",
            }),
          );
        },
      }),
      storage,
    });
    await store.getState().restore();

    await store.getState().changePassword("correct horse battery staple", "too short");

    expect(store.getState()).toMatchObject({
      status: "authenticated",
      pending: null,
      failure: { kind: "invalid_password" },
    });
    expect(storage.load()).toEqual({ sessionToken: "token-1", expiresAt });
  });

  it("clears the local session when password change reports re-authentication required", async () => {
    const storage = createMemoryStorage({ sessionToken: "token-1", expiresAt });
    const store = createAuthStore({
      client: createClient({
        changePassword: async () => {
          throw new CloudAuthError(createAuthFailure("reauth_required"));
        },
      }),
      storage,
    });
    await store.getState().restore();

    await store
      .getState()
      .changePassword("correct horse battery staple", "another strong replacement passphrase");

    expect(store.getState()).toMatchObject({
      status: "unauthenticated",
      account: null,
      failure: { kind: "reauth_required" },
      pending: null,
    });
    expect(storage.load()).toBeNull();
  });

  it("preserves the local session when password change is transiently unavailable", async () => {
    const storage = createMemoryStorage({ sessionToken: "token-1", expiresAt });
    const store = createAuthStore({
      client: createClient({
        changePassword: async () => {
          throw new CloudAuthError(createAuthFailure("service_unavailable"));
        },
      }),
      storage,
    });
    await store.getState().restore();

    await store
      .getState()
      .changePassword("correct horse battery staple", "another strong replacement passphrase");

    expect(store.getState()).toMatchObject({
      status: "authenticated",
      pending: null,
      failure: { kind: "service_unavailable" },
    });
    expect(storage.load()).toEqual({ sessionToken: "token-1", expiresAt });
  });

  it("does not attempt a password change without a local session", async () => {
    let called = false;
    const storage = createMemoryStorage();
    const store = createAuthStore({
      client: createClient({
        changePassword: async () => {
          called = true;
        },
      }),
      storage,
    });

    await store
      .getState()
      .changePassword("correct horse battery staple", "another strong replacement passphrase");

    expect(called).toBe(false);
    expect(store.getState()).toMatchObject({
      status: "unauthenticated",
      failure: { kind: "reauth_required" },
      pending: null,
    });
  });

  it("clears the stored session after an explicit logout", async () => {
    let logoutToken: string | null = null;
    const { store, storage } = await createAuthenticatedLogoutStore(async (token) => {
      logoutToken = token;
    });

    await store.getState().logout();

    expect(logoutToken).toBe("token-1");
    expectLoggedOutState(store);
    expect(storage.load()).toBeNull();
  });

  it("clears the stored session when logout reports re-authentication required", async () => {
    const { store, storage } = await createAuthenticatedLogoutStore(async () => {
      throw new CloudAuthError(
        createAuthFailure("reauth_required", {
          status: 401,
          code: "AUTH_REAUTH_REQUIRED",
        }),
      );
    });

    await store.getState().logout();

    expectLoggedOutState(store);
    expect(storage.load()).toBeNull();
  });

  it.each([
    "network_unavailable",
    "service_unavailable",
    "malformed_response",
    "unexpected_response",
  ] as const)(
    "preserves the stored session and surfaces a retryable failure when logout fails with %s",
    async (kind) => {
      const failure = createAuthFailure(kind);
      const { store, storage, stored } = await createAuthenticatedLogoutStore(async () => {
        throw new CloudAuthError(failure);
      });

      await store.getState().logout();

      expect(store.getState()).toMatchObject({
        status: "authenticated",
        account,
        expiresAt,
        pending: null,
        failure,
      });
      expect(storage.load()).toEqual(stored);
    },
  );

  it("turns malformed and rate-limited failures into stable state", async () => {
    const malformedStore = createAuthStore({
      client: createClient({
        login: async () => {
          throw new CloudAuthError(createAuthFailure("malformed_response"));
        },
      }),
      storage: createMemoryStorage(),
    });
    await malformedStore.getState().login("pilot", "password");

    expect(malformedStore.getState().failure?.kind).toBe("malformed_response");

    const rateLimitedStore = createAuthStore({
      client: createClient({
        login: async () => {
          throw new CloudAuthError(createAuthFailure("rate_limited", { retryAfterSeconds: 15 }));
        },
      }),
      storage: createMemoryStorage(),
    });
    await rateLimitedStore.getState().login("pilot", "password");

    expect(rateLimitedStore.getState().failure).toMatchObject({
      kind: "rate_limited",
      retryAfterSeconds: 15,
    });
  });
});
