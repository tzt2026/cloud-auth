import { render } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { routes } from "@/app/routes";
import type { CloudAuthClient } from "@/lib/auth/client";
import { AuthProvider } from "@/lib/auth/context";
import { createAuthStore, type AuthStore } from "@/lib/auth/store";
import type { PersistedCloudSession } from "@/lib/auth/session-storage";
import type { HostGrantsClient } from "@/lib/grants/client";
import { HostGrantsProvider } from "@/lib/grants/context";
import { expiresAt } from "./auth-fixtures";
import { createFakeAuthClient, createFakeHostGrantsClient } from "./host-grants-fixtures";
import { createMemoryStorage } from "./session-storage";

/**
 * A persisted Cloud Session for the seeded states. `restore()` asks the service,
 * but `getSessionToken()` also enforces the deadline locally and drops the
 * persisted session once it passes, so this must stay a live expiry — hence the
 * run-relative `expiresAt` from `./auth-fixtures`.
 */
export const storedSession: PersistedCloudSession = {
  sessionToken: "mcs_v1.session.secret",
  expiresAt,
};

/**
 * Mount the real route tree with the same provider composition as
 * `@/app/providers` (`AuthProvider` + `HostGrantsProvider`), except that both
 * dependencies are injectable. Route-level tests need fakes: every page below
 * `/account` reads `useHostGrantsClient()`, and mounting the tree without the
 * grants provider throws straight into the route `errorElement`.
 */
export function mountPortal({
  path,
  client = createFakeAuthClient(),
  grantsClient = createFakeHostGrantsClient(),
  session = null,
  configure,
}: {
  path: string;
  client?: CloudAuthClient;
  grantsClient?: HostGrantsClient;
  session?: PersistedCloudSession | null;
  /** Last chance to touch the store before the first render (e.g. pin the gate). */
  configure?: ((store: AuthStore) => void) | undefined;
}) {
  const storage = createMemoryStorage(session);
  const store = createAuthStore({ client, storage });
  configure?.(store);
  const router = createMemoryRouter(routes, { initialEntries: [path] });

  const result = render(
    <AuthProvider store={store}>
      <HostGrantsProvider client={grantsClient}>
        <RouterProvider router={router} />
      </HostGrantsProvider>
    </AuthProvider>,
  );

  return { ...result, router, store, storage };
}

export type PortalRouter = ReturnType<typeof createMemoryRouter>;
