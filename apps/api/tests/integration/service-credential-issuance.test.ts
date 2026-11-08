import {
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  CLOUD_WHO_YOU_AUDIENCE,
  RELAY_TRANSPORT_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  SHIYAN_AUTHENTICATE_SCOPE,
  WHOYOU_MAIL_SEND_SCOPE,
  WHOYOU_MAIL_WRITE_SCOPE,
  WHOYOU_READ_SCOPE,
  issuedServiceCredentialSchema,
  serviceCredentialErrorEnvelopeSchema,
  serviceCredentialJwksSchema,
} from "@uichat-mira/cloud-auth-contracts";
import { parseSessionToken } from "../../src/security/session-token.js";
import {
  issueServiceCredential,
  verifyServiceCredential,
  type ServiceCredentialVerifierConfig,
} from "../../src/service-credentials/index.js";
import { createFirstPartySession } from "../helpers/oauth.js";
import {
  createTestServiceCredentialContext,
  createTestServiceCredentialKeyMaterial,
  type TestServiceCredentialContext,
} from "../helpers/service-credential.js";

const password = "correct horse battery staple";
const cleanup: string[] = [];

afterEach(async () => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

function createContext(
  keyMaterial: ReturnType<typeof createTestServiceCredentialKeyMaterial> | null =
    createTestServiceCredentialKeyMaterial(),
): TestServiceCredentialContext {
  const dir = mkdtempSync(join(tmpdir(), "mira-service-credentials-"));
  cleanup.push(dir);
  return createTestServiceCredentialContext(join(dir, "auth.sqlite"), keyMaterial);
}

async function registerDevice(
  context: TestServiceCredentialContext,
  token: string,
  platform: "desktop" | "mobile" = "desktop",
) {
  return context.deviceService.register(token, {
    installationId: randomUUID(),
    platform,
    clientName: `Mira ${platform}`,
  });
}

async function issue(
  context: TestServiceCredentialContext,
  token: string,
  body: unknown,
) {
  return context.app.inject({
    method: "POST",
    url: "/v1/service-credentials",
    headers: { authorization: `Bearer ${token}` },
    payload: body as Record<string, unknown>,
  });
}

function trustedKeys(context: TestServiceCredentialContext): Map<string, KeyObject> {
  const ring = context.keyRing;
  if (!ring) throw new Error("Expected a configured key ring");
  return new Map(
    ring.jwks.keys.map((jwk) => [
      jwk.kid,
      createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }),
    ]),
  );
}

function shiyanVerifier(
  context: TestServiceCredentialContext,
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_SHIYAN_AUDIENCE,
    publicKeys: trustedKeys(context),
  };
}

function relayVerifier(
  context: TestServiceCredentialContext,
  room = "room-7f3a",
  role: "client" | "host" = "client",
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
    publicKeys: trustedKeys(context),
    expectedRelay: { room, role },
  };
}

function whoYouVerifier(
  context: TestServiceCredentialContext,
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_WHO_YOU_AUDIENCE,
    publicKeys: trustedKeys(context),
  };
}

describe("authenticated service credential issuance", () => {
  it("issues a canonical Shiyan credential from a device-bound Cloud Session", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    const login = await context.service.login("alice", password, "127.0.0.1");
    const device = await registerDevice(context, login.sessionToken);

    const response = await issue(context, login.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });

    expect(response.statusCode).toBe(200);
    const issued = issuedServiceCredentialSchema.parse(response.json());
    expect(issued).toMatchObject({
      tokenType: "Bearer",
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    expect(response.body).not.toContain(login.sessionToken);

    const verified = verifyServiceCredential(issued.token, shiyanVerifier(context));
    expect(verified.claims).toMatchObject({
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: login.account.id,
      device_id: device.id,
      aud: CLOUD_SHIYAN_AUDIENCE,
      scope: [SHIYAN_AUTHENTICATE_SCOPE],
    });
    expect(verified.expiresAt.toISOString()).toBe(issued.expiresAt);
    expect(verified.keyId).toBe(context.keyRing?.activeKeyId);

    context.db.close();
    await context.app.close();
  });

  it("issues Relay transport tickets only for the authorized host room and role", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    const desktop = await createFirstPartySession(context, {
      username: "alice",
      password,
    });
    const mobile = await createFirstPartySession(context, {
      username: "alice",
      password,
      platform: "mobile",
    });
    const host = context.hostService.register(desktop.sessionToken);

    const hostResponse = await issue(context, desktop.sessionToken, {
      audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      relay: { room: host.relayRoom, role: "host" },
    });
    expect(hostResponse.statusCode).toBe(200);
    const hostIssued = issuedServiceCredentialSchema.parse(hostResponse.json());
    const hostVerified = verifyServiceCredential(
      hostIssued.token,
      relayVerifier(context, host.relayRoom, "host"),
    );
    expect(hostVerified.claims).toMatchObject({
      sub: desktop.account.id,
      device_id: host.deviceId,
      aud: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      scope: [RELAY_TRANSPORT_SCOPE],
      relay: { room: host.relayRoom, role: "host" },
    });

    expect(() =>
      verifyServiceCredential(hostIssued.token, relayVerifier(context, "room-other", "host")),
    ).toThrow(/Relay ticket does not match/);
    expect(() =>
      verifyServiceCredential(hostIssued.token, relayVerifier(context, host.relayRoom, "client")),
    ).toThrow(/Relay ticket does not match/);
    expect(() => verifyServiceCredential(hostIssued.token, shiyanVerifier(context))).toThrow(
      /audience/,
    );

    const clientResponse = await issue(context, mobile.sessionToken, {
      audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      relay: { room: host.relayRoom, role: "client" },
    });
    expect(clientResponse.statusCode).toBe(200);
    const clientIssued = issuedServiceCredentialSchema.parse(clientResponse.json());
    const clientVerified = verifyServiceCredential(
      clientIssued.token,
      relayVerifier(context, host.relayRoom, "client"),
    );
    expect(clientVerified.claims).toMatchObject({
      sub: mobile.account.id,
      aud: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      scope: [RELAY_TRANSPORT_SCOPE],
      relay: { room: host.relayRoom, role: "client" },
    });
    expect(clientVerified.claims.device_id).not.toBe(host.deviceId);

    const shiyan = await issue(context, desktop.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    expect(() =>
      verifyServiceCredential(
        issuedServiceCredentialSchema.parse(shiyan.json()).token,
        relayVerifier(context),
      ),
    ).toThrow(/audience/);

    context.db.close();
    await context.app.close();
  });

  it("rejects client-supplied identity, issuer, key, scope and malformed requests", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    const login = await context.service.login("alice", password, "127.0.0.1");
    const device = await registerDevice(context, login.sessionToken);

    for (const body of [
      { audience: CLOUD_SHIYAN_AUDIENCE, accountId: "another-account" },
      { audience: CLOUD_SHIYAN_AUDIENCE, deviceId: "another-device" },
      { audience: CLOUD_SHIYAN_AUDIENCE, iss: "mira:attacker" },
      { audience: CLOUD_SHIYAN_AUDIENCE, kid: "attacker-key" },
      { audience: CLOUD_SHIYAN_AUDIENCE, scope: [RELAY_TRANSPORT_SCOPE] },
      { audience: CLOUD_RELAY_TRANSPORT_AUDIENCE },
      { audience: CLOUD_RELAY_TRANSPORT_AUDIENCE, relay: { room: "room-1", role: "owner" } },
      { audience: CLOUD_RELAY_TRANSPORT_AUDIENCE, relay: { room: "room 1", role: "client" } },
      { audience: "mira:unknown" },
      { audience: CLOUD_SHIYAN_AUDIENCE, relay: { room: "room-1", role: "client" } },
    ]) {
      const response = await issue(context, login.sessionToken, body);
      expect(response.statusCode).toBe(400);
      expect(serviceCredentialErrorEnvelopeSchema.parse(response.json()).error.code).toBe(
        "SERVICE_CREDENTIAL_INVALID_REQUEST",
      );
    }

    const valid = await issue(context, login.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    const claims = verifyServiceCredential(
      issuedServiceCredentialSchema.parse(valid.json()).token,
      shiyanVerifier(context),
    ).claims;
    expect(claims.device_id).toBe(device.id);
    expect(claims.sub).toBe(login.account.id);

    context.db.close();
    await context.app.close();
  });

  it("binds credentials to the authenticated account rather than another account", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    await context.service.provisionAccount("bob", password);
    const aliceLogin = await context.service.login("alice", password, "127.0.0.1");
    const bobLogin = await context.service.login("bob", password, "127.0.0.2");
    const aliceDevice = await registerDevice(context, aliceLogin.sessionToken);
    const bobDevice = await registerDevice(context, bobLogin.sessionToken);

    const aliceIssued = issuedServiceCredentialSchema.parse(
      (
        await issue(context, aliceLogin.sessionToken, {
          audience: CLOUD_SHIYAN_AUDIENCE,
        })
      ).json(),
    );
    const bobIssued = issuedServiceCredentialSchema.parse(
      (
        await issue(context, bobLogin.sessionToken, {
          audience: CLOUD_SHIYAN_AUDIENCE,
        })
      ).json(),
    );

    expect(verifyServiceCredential(aliceIssued.token, shiyanVerifier(context)).claims).toMatchObject({
      sub: aliceLogin.account.id,
      device_id: aliceDevice.id,
    });
    expect(verifyServiceCredential(bobIssued.token, shiyanVerifier(context)).claims).toMatchObject({
      sub: bobLogin.account.id,
      device_id: bobDevice.id,
    });

    context.db.close();
    await context.app.close();
  });

  it("revokes one device without affecting another device on the same account", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    const firstLogin = await context.service.login("alice", password, "127.0.0.1");
    const secondLogin = await context.service.login("alice", password, "127.0.0.2");
    const firstDevice = await registerDevice(context, firstLogin.sessionToken, "desktop");
    const secondDevice = await registerDevice(context, secondLogin.sessionToken, "mobile");

    expect(
      (await issue(context, firstLogin.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(200);
    expect(
      (await issue(context, secondLogin.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(200);

    context.deviceService.revoke(firstLogin.sessionToken, firstDevice.id);

    const revoked = await issue(context, firstLogin.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    expect(revoked.statusCode).toBe(401);
    expect(serviceCredentialErrorEnvelopeSchema.parse(revoked.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
    );

    const stillValid = await issue(context, secondLogin.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    expect(stillValid.statusCode).toBe(200);
    expect(
      verifyServiceCredential(
        issuedServiceCredentialSchema.parse(stillValid.json()).token,
        shiyanVerifier(context),
      ).claims.device_id,
    ).toBe(secondDevice.id);

    context.db.close();
    await context.app.close();
  });

  it("rejects disabled accounts, revoked sessions, expired sessions and stale rotated tokens", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    const login = await context.service.login("alice", password, "127.0.0.1");
    await registerDevice(context, login.sessionToken);

    const loggedOut = await context.service.login("alice", password, "127.0.0.2");
    await registerDevice(context, loggedOut.sessionToken);
    context.service.logout(loggedOut.sessionToken);
    expect(
      (await issue(context, loggedOut.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(401);

    const renewed = await context.service.login("alice", password, "127.0.0.3");
    await registerDevice(context, renewed.sessionToken);
    const replacement = context.service.renewSession(renewed.sessionToken);
    expect(
      (await issue(context, renewed.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(401);
    expect(
      (await issue(context, replacement.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(200);

    const expired = await context.service.login("alice", password, "127.0.0.4");
    await registerDevice(context, expired.sessionToken);
    const expiredSessionId = parseSessionToken(expired.sessionToken)?.id;
    expect(expiredSessionId).toBeTruthy();
    context.db
      .prepare("UPDATE sessions SET expires_at = ? WHERE id = ?")
      .run("2026-01-01T00:00:00.000Z", expiredSessionId!);
    expect(
      (await issue(context, expired.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(401);

    expect(
      (await issue(context, login.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(200);
    context.service.setDisabled("alice", true);
    expect(
      (await issue(context, login.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(401);

    context.db.close();
    await context.app.close();
  });

  it("fails closed for malformed, unknown and legacy unbound Web sessions", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    const legacy = await context.service.login("alice", password, "127.0.0.1");

    for (const token of ["", "not-a-token", "mcs_v1.unknown.secret"]) {
      const response = await issue(context, token, { audience: CLOUD_SHIYAN_AUDIENCE });
      expect(response.statusCode).toBe(401);
    }

    const legacyResponse = await issue(context, legacy.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    expect(legacyResponse.statusCode).toBe(403);
    expect(serviceCredentialErrorEnvelopeSchema.parse(legacyResponse.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_DEVICE_REQUIRED",
    );
    // The legacy Web session still works for normal Cloud Session behavior.
    expect(context.service.getSession(legacy.sessionToken).account.username).toBe("alice");

    context.db.close();
    await context.app.close();
  });

  it("keeps login, health and readiness available when signing is not configured", async () => {
    const context = createContext(null);
    await context.service.provisionAccount("alice", password);
    const login = await context.service.login("alice", password, "127.0.0.1");
    await registerDevice(context, login.sessionToken);

    expect((await context.app.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
    expect((await context.app.inject({ method: "GET", url: "/ready" })).statusCode).toBe(200);

    const response = await issue(context, login.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    expect(response.statusCode).toBe(503);
    expect(serviceCredentialErrorEnvelopeSchema.parse(response.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_UNAVAILABLE",
    );

    const jwks = await context.app.inject({
      method: "GET",
      url: "/.well-known/jwks.json",
    });
    expect(jwks.statusCode).toBe(503);

    context.db.close();
    await context.app.close();
  });

  it("fails issuance closed for malformed signing material while retaining login", async () => {
    const context = createContext(
      createTestServiceCredentialKeyMaterial({ activePrivateKey: "not-a-private-key" }),
    );
    await context.service.provisionAccount("alice", password);
    const login = await context.service.login("alice", password, "127.0.0.1");
    await registerDevice(context, login.sessionToken);

    expect(context.keyRing).toBeNull();
    expect(context.service.getSession(login.sessionToken).account.username).toBe("alice");
    expect(
      (await issue(context, login.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE }))
        .statusCode,
    ).toBe(503);
    expect(
      (
        await context.app.inject({
          method: "GET",
          url: "/.well-known/jwks.json",
        })
      ).statusCode,
    ).toBe(503);

    context.db.close();
    await context.app.close();
  });

  it("publishes verifier discovery and verifies active/retiring key overlap", async () => {
    const oldKeyPair = generateKeyPairSync("ed25519");
    const keyMaterial = createTestServiceCredentialKeyMaterial({
      retiringPublicKeys: [
        {
          keyId: "test-retiring-key",
          publicKey: oldKeyPair.publicKey.export({ type: "spki", format: "pem" }).toString(),
        },
      ],
    });
    const context = createContext(keyMaterial);
    await context.service.provisionAccount("alice", password);
    const login = await context.service.login("alice", password, "127.0.0.1");
    const device = await registerDevice(context, login.sessionToken);

    const jwksResponse = await context.app.inject({
      method: "GET",
      url: "/.well-known/jwks.json",
    });
    expect(jwksResponse.statusCode).toBe(200);
    expect(jwksResponse.headers["cache-control"]).toBe("public, max-age=300");
    const jwks = serviceCredentialJwksSchema.parse(jwksResponse.json());
    expect(jwks.keys.map((key) => key.kid)).toEqual([
      keyMaterial.activeKeyId,
      "test-retiring-key",
    ]);

    const issuedResponse = await issue(context, login.sessionToken, {
      audience: CLOUD_SHIYAN_AUDIENCE,
    });
    const issued = issuedServiceCredentialSchema.parse(issuedResponse.json());
    const issuedHeader = JSON.parse(
      Buffer.from(issued.token.split(".")[0]!, "base64url").toString("utf8"),
    ) as { kid: string };
    expect(issuedHeader.kid).toBe(keyMaterial.activeKeyId);

    const oldToken = issueServiceCredential(
      {
        privateKey: oldKeyPair.privateKey,
        keyId: "test-retiring-key",
        ttlSeconds: 300,
      },
      {
        accountId: login.account.id,
        deviceId: device.id,
        audience: CLOUD_SHIYAN_AUDIENCE,
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      },
    );
    expect(
      verifyServiceCredential(oldToken, shiyanVerifier(context)).claims.sub,
    ).toBe(login.account.id);

    context.db.close();
    await context.app.close();
  });

  it("issues Who You read, draft-write and draft-bound send credentials", async () => {
    const context = createContext();
    await context.service.provisionAccount("alice", password);
    const login = await context.service.login("alice", password, "127.0.0.1");
    const device = await registerDevice(context, login.sessionToken);
    const confirmation = {
      actor: "user",
      draft_id: "dr_0123456789abcdef",
      draft_version: 7,
      content_hash: "a".repeat(64),
      nonce: "nonce-0123456789abcdef",
    };

    const readResponse = await issue(context, login.sessionToken, {
      audience: CLOUD_WHO_YOU_AUDIENCE,
    });
    expect(readResponse.statusCode).toBe(200);
    expect(readResponse.body).not.toContain(login.sessionToken);
    const readVerified = verifyServiceCredential(
      issuedServiceCredentialSchema.parse(readResponse.json()).token,
      whoYouVerifier(context),
    );
    expect(readVerified.claims).toMatchObject({
      sub: login.account.id,
      device_id: device.id,
      aud: CLOUD_WHO_YOU_AUDIENCE,
      consumer_id: login.account.id,
      scope: [WHOYOU_READ_SCOPE],
    });
    expect("confirmation" in readVerified.claims).toBe(false);

    const writeResponse = await issue(context, login.sessionToken, {
      audience: CLOUD_WHO_YOU_AUDIENCE,
      scopes: [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE],
    });
    expect(writeResponse.statusCode).toBe(200);
    expect(
      verifyServiceCredential(
        issuedServiceCredentialSchema.parse(writeResponse.json()).token,
        whoYouVerifier(context),
      ).claims,
    ).toMatchObject({ scope: [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE] });

    const sendResponse = await issue(context, login.sessionToken, {
      audience: CLOUD_WHO_YOU_AUDIENCE,
      confirmation,
    });
    expect(sendResponse.statusCode).toBe(200);
    const sendVerified = verifyServiceCredential(
      issuedServiceCredentialSchema.parse(sendResponse.json()).token,
      whoYouVerifier(context),
    );
    expect(sendVerified.claims).toMatchObject({
      consumer_id: login.account.id,
      scope: [WHOYOU_MAIL_SEND_SCOPE],
      confirmation,
    });

    const rejected = await issue(context, login.sessionToken, {
      audience: CLOUD_WHO_YOU_AUDIENCE,
      scopes: [WHOYOU_READ_SCOPE],
      confirmation,
    });
    expect(rejected.statusCode).toBe(400);
    expect(serviceCredentialErrorEnvelopeSchema.parse(rejected.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_INVALID_REQUEST",
    );

    context.db.close();
    await context.app.close();
  });
});
