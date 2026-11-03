import { createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  RELAY_TRANSPORT_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  issuedServiceCredentialSchema,
  serviceCredentialErrorEnvelopeSchema,
} from "@uichat-mira/cloud-auth-contracts";
import { GuanlanRegistrationOutboxReadiness } from "../../src/service-credentials/guanlan-space-readiness.js";
import { verifyServiceCredential } from "../../src/service-credentials/index.js";
import { ServiceCredentialService } from "../../src/service-credentials/service.js";
import {
  createFirstPartySession,
  createTestOAuthContext,
  type TestOAuthContext,
  type TestOAuthOptions,
} from "../helpers/oauth.js";
import { createTestServiceCredentialKeyMaterial } from "../helpers/service-credential.js";

const password = "correct horse battery staple";
const cleanup: string[] = [];

afterEach(() => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

function databasePath(): string {
  const dir = mkdtempSync(join(tmpdir(), "mira-relay-authorization-"));
  cleanup.push(dir);
  return join(dir, "auth.sqlite");
}

function context(
  path: string,
  options: TestOAuthOptions = {},
): TestOAuthContext {
  return createTestOAuthContext(path, {
    serviceCredentialKeyMaterial: createTestServiceCredentialKeyMaterial(),
    ...options,
  });
}

function issue(context: TestOAuthContext, token: string, room: string, role: "client" | "host") {
  return context.app.inject({
    method: "POST",
    url: "/v1/service-credentials",
    headers: { authorization: `Bearer ${token}` },
    payload: {
      audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      relay: { room, role },
    },
  });
}

function trustedKeys(context: TestOAuthContext): Map<string, KeyObject> {
  const ring = context.keyRing;
  if (!ring) throw new Error("Expected a configured key ring");
  return new Map(
    ring.jwks.keys.map((jwk) => [
      jwk.kid,
      createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }),
    ]),
  );
}

async function createFamily(context: TestOAuthContext, username = "alice") {
  await context.service.provisionAccount(username, password);
  const desktop = await createFirstPartySession(context, { username, password });
  const mobile = await createFirstPartySession(context, {
    username,
    password,
    platform: "mobile",
  });
  const host = context.hostService.register(desktop.sessionToken);
  return { desktop, mobile, host };
}

describe("Relay ticket authorization on SQLite", () => {
  it("rejects a mismatched room even if a resolver returns a different valid owner", async () => {
    const path = databasePath();
    const testContext = context(path);
    const family = await createFamily(testContext);

    // Simulate a future resolver bug returning a real, available Host for the
    // wrong requested room. The admission helper must reject the mismatch.
    const mismatchedResolverService = new ServiceCredentialService(
      testContext.repository,
      testContext.keyRing,
      {
        resolveRoomOwnership: () =>
          testContext.hostService.resolveRoomOwnership(family.host.relayRoom),
      },
      new GuanlanRegistrationOutboxReadiness(testContext.db),
    );

    for (const [token, role] of [
      [family.desktop.sessionToken, "host"],
      [family.mobile.sessionToken, "client"],
    ] as const) {
      expect(() =>
        mismatchedResolverService.issue(token, {
          audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
          relay: { room: "room_unrelated", role },
        }),
      ).toThrowError("Relay transport ticket is not authorized for this device");
    }

    await testContext.app.close();
    testContext.db.close();
  });


  it("persists room ownership and remains authorized across process restart", async () => {
    const path = databasePath();
    const fixedNow = new Date();
    const keyMaterial = createTestServiceCredentialKeyMaterial();
    const options: TestOAuthOptions = {
      now: () => fixedNow,
      sessionTtlSeconds: 3600,
      hostLeaseSeconds: 300,
      serviceCredentialKeyMaterial: keyMaterial,
    };
    const first = context(path, options);
    const family = await createFamily(first);

    expect(
      (await issue(first, family.desktop.sessionToken, family.host.relayRoom, "host"))
        .statusCode,
    ).toBe(200);
    expect(
      (await issue(first, family.mobile.sessionToken, family.host.relayRoom, "client"))
        .statusCode,
    ).toBe(200);

    await first.app.close();
    first.db.close();

    const second = context(path, options);
    expect(second.hostService.resolveRoomOwnership(family.host.relayRoom)).toMatchObject({
      accountId: family.desktop.account.id,
      availability: "available",
    });

    const [hostTicketResponse, clientTicketResponse] = await Promise.all([
      issue(second, family.desktop.sessionToken, family.host.relayRoom, "host"),
      issue(second, family.mobile.sessionToken, family.host.relayRoom, "client"),
    ]);
    expect(hostTicketResponse.statusCode).toBe(200);
    expect(clientTicketResponse.statusCode).toBe(200);

    const hostTicket = issuedServiceCredentialSchema.parse(hostTicketResponse.json());
    const verified = verifyServiceCredential(hostTicket.token, {
      issuer: SERVICE_CREDENTIAL_ISSUER,
      audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      publicKeys: trustedKeys(second),
      expectedRelay: { room: family.host.relayRoom, role: "host" },
    });
    expect(verified.claims).toMatchObject({
      sub: family.desktop.account.id,
      device_id: family.host.deviceId,
      scope: [RELAY_TRANSPORT_SCOPE],
    });

    await second.app.close();
    second.db.close();
  });

  it("fails closed when the Host lease expires and reopens only after a fresh registration", async () => {
    const path = databasePath();
    const clock = { value: Date.now() };
    const testContext = context(path, {
      now: () => new Date(clock.value),
      sessionTtlSeconds: 3600,
      hostLeaseSeconds: 60,
    });
    const family = await createFamily(testContext);

    clock.value += 61_000;
    expect(testContext.hostService.resolveRoomOwnership(family.host.relayRoom)).toMatchObject({
      availability: "offline",
    });

    const expiredHost = await issue(
      testContext,
      family.desktop.sessionToken,
      family.host.relayRoom,
      "host",
    );
    const expiredClient = await issue(
      testContext,
      family.mobile.sessionToken,
      family.host.relayRoom,
      "client",
    );
    for (const response of [expiredHost, expiredClient]) {
      expect(response.statusCode).toBe(403);
      expect(serviceCredentialErrorEnvelopeSchema.parse(response.json()).error.code).toBe(
        "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
      );
    }

    const refreshed = testContext.hostService.register(family.desktop.sessionToken);
    expect(refreshed.relayRoom).toBe(family.host.relayRoom);
    expect(
      (await issue(testContext, family.desktop.sessionToken, refreshed.relayRoom, "host"))
        .statusCode,
    ).toBe(200);
    expect(
      (await issue(testContext, family.mobile.sessionToken, refreshed.relayRoom, "client"))
        .statusCode,
    ).toBe(200);

    await testContext.app.close();
    testContext.db.close();
  });

  it("revokes the old room for host role, client role, logout and account disable", async () => {
    const path = databasePath();
    const testContext = context(path, { sessionTtlSeconds: 3600, hostLeaseSeconds: 300 });
    const family = await createFamily(testContext);
    const room = family.host.relayRoom;

    testContext.deviceService.revoke(family.mobile.sessionToken, family.host.deviceId);
    expect(testContext.hostService.resolveRoomOwnership(room)).toBeNull();

    const revokedHost = await issue(testContext, family.desktop.sessionToken, room, "host");
    const revokedClient = await issue(testContext, family.mobile.sessionToken, room, "client");
    expect(revokedHost.statusCode).toBe(401);
    expect(serviceCredentialErrorEnvelopeSchema.parse(revokedHost.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
    );
    expect(revokedClient.statusCode).toBe(403);
    expect(serviceCredentialErrorEnvelopeSchema.parse(revokedClient.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
    );

    testContext.service.logout(family.mobile.sessionToken);
    expect(
      (await issue(testContext, family.mobile.sessionToken, room, "client")).statusCode,
    ).toBe(401);

    const secondFamily = await createFamily(testContext, "bob");
    testContext.service.logout(secondFamily.desktop.sessionToken);
    expect(testContext.hostService.resolveRoomOwnership(secondFamily.host.relayRoom)).toBeNull();
    expect(
      (await issue(testContext, secondFamily.desktop.sessionToken, secondFamily.host.relayRoom, "host"))
        .statusCode,
    ).toBe(401);
    expect(
      (await issue(testContext, secondFamily.mobile.sessionToken, secondFamily.host.relayRoom, "client"))
        .statusCode,
    ).toBe(403);

    const thirdFamily = await createFamily(testContext, "carol");
    testContext.service.setDisabled("carol", true);
    expect(testContext.hostService.resolveRoomOwnership(thirdFamily.host.relayRoom)).toBeNull();
    expect(
      (await issue(testContext, thirdFamily.desktop.sessionToken, thirdFamily.host.relayRoom, "host"))
        .statusCode,
    ).toBe(401);
    expect(
      (await issue(testContext, thirdFamily.mobile.sessionToken, thirdFamily.host.relayRoom, "client"))
        .statusCode,
    ).toBe(401);

    await testContext.app.close();
    testContext.db.close();
  });

  it("denies a foreign account and an unregistered or stale room on real account/device rows", async () => {
    const path = databasePath();
    const testContext = context(path, { sessionTtlSeconds: 3600, hostLeaseSeconds: 300 });
    const alice = await createFamily(testContext, "alice");
    const bob = await createFamily(testContext, "bob");

    for (const [token, room, role] of [
      [bob.mobile.sessionToken, alice.host.relayRoom, "client"],
      [bob.desktop.sessionToken, alice.host.relayRoom, "host"],
      [alice.mobile.sessionToken, bob.host.relayRoom, "client"],
      [alice.desktop.sessionToken, "room_unknown", "host"],
      [alice.mobile.sessionToken, "room_unknown", "client"],
    ] as const) {
      const response = await issue(testContext, token, room, role);
      expect(response.statusCode).toBe(403);
      expect(serviceCredentialErrorEnvelopeSchema.parse(response.json()).error.code).toBe(
        "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
      );
      expect(response.body).not.toContain(alice.host.relayRoom);
      expect(response.body).not.toContain(bob.host.relayRoom);
    }

    await testContext.app.close();
    testContext.db.close();
  });

  it("never issues a fresh ticket after another SQLite connection revokes the Host device", async () => {
    const path = databasePath();
    const fixedNow = new Date();
    const keyMaterial = createTestServiceCredentialKeyMaterial();
    const options: TestOAuthOptions = {
      now: () => fixedNow,
      sessionTtlSeconds: 3600,
      hostLeaseSeconds: 300,
      serviceCredentialKeyMaterial: keyMaterial,
    };
    const first = context(path, options);
    const second = context(path, options);
    const family = await createFamily(first);
    const room = family.host.relayRoom;

    second.deviceService.revoke(family.mobile.sessionToken, family.host.deviceId);
    expect(second.hostService.resolveRoomOwnership(room)).toBeNull();

    const responses = await Promise.all([
      issue(first, family.desktop.sessionToken, room, "host"),
      issue(first, family.mobile.sessionToken, room, "client"),
      issue(second, family.desktop.sessionToken, room, "host"),
      issue(second, family.mobile.sessionToken, room, "client"),
    ]);
    expect(responses.map((response) => response.statusCode)).toEqual([401, 403, 401, 403]);
    expect(
      responses.map(
        (response) => serviceCredentialErrorEnvelopeSchema.parse(response.json()).error.code,
      ),
    ).toEqual([
      "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
      "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
      "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
      "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
    ]);
    for (const response of responses) {
      expect(response.body).not.toContain("eyJ");
    }

    expect(
      first.db.prepare("SELECT COUNT(*) AS count FROM desktop_hosts WHERE revoked_at IS NULL").get(),
    ).toEqual({ count: 0 });
    expect(
      first.db
        .prepare("SELECT revoked_at, revoke_reason FROM desktop_hosts WHERE id = ?")
        .get(family.host.id),
    ).toMatchObject({
      revoked_at: expect.any(String),
      revoke_reason: "host_device_revoked",
    });

    await first.app.close();
    first.db.close();
    await second.app.close();
    second.db.close();
  });
});
