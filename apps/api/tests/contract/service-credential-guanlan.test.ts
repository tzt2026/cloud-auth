import { createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CLOUD_GUANLAN_AUDIENCE,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  GUANLAN_READ_SCOPE,
  GUANLAN_WRITE_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  issuedServiceCredentialSchema,
  serviceCredentialErrorEnvelopeSchema,
} from "@uichat-mira/cloud-auth-contracts";
import { parseSessionToken } from "../../src/security/session-token.js";
import {
  verifyServiceCredential,
  type ServiceCredentialVerifierConfig,
} from "../../src/service-credentials/index.js";
import { createFirstPartySession } from "../helpers/oauth.js";
import {
  createTestServiceCredentialContext,
  setGuanlanRegistrationStatus,
  type TestServiceCredentialContext,
} from "../helpers/service-credential.js";

const password = "correct horse battery staple";
const cleanup: string[] = [];

afterEach(() => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

function createContext(): TestServiceCredentialContext {
  const dir = mkdtempSync(join(tmpdir(), "mira-guanlan-credential-"));
  cleanup.push(dir);
  return createTestServiceCredentialContext(join(dir, "auth.sqlite"));
}

async function issue(context: TestServiceCredentialContext, token: string, body: unknown) {
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

function guanlanVerifier(
  context: TestServiceCredentialContext,
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_GUANLAN_AUDIENCE,
    publicKeys: trustedKeys(context),
  };
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
): ServiceCredentialVerifierConfig {
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
    publicKeys: trustedKeys(context),
    expectedRelay: { room: "room-7f3a", role: "client" },
  };
}

async function provisionedSession(context: TestServiceCredentialContext) {
  await context.service.provisionAccount("alice", password);
  return createFirstPartySession(context, { username: "alice", password });
}

describe("Guanlan credential HTTP contract", () => {
  it("fails closed while the GLN-012 registration projection is absent", async () => {
    const context = createContext();
    const session = await provisionedSession(context);

    const response = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });

    expect(response.statusCode).toBe(409);
    const envelope = serviceCredentialErrorEnvelopeSchema.parse(response.json());
    expect(envelope.error.code).toBe("SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY");
    expect(envelope.error.message).not.toContain(session.sessionToken);
    expect(response.body).not.toContain("token");

    context.db.close();
    await context.app.close();
  });

  it("rejects unauthenticated and malformed issuance attempts", async () => {
    const context = createContext();
    const session = await provisionedSession(context);

    const anonymous = await context.app.inject({
      method: "POST",
      url: "/v1/service-credentials",
      payload: { audience: CLOUD_GUANLAN_AUDIENCE },
    });
    expect(anonymous.statusCode).toBe(401);
    expect(serviceCredentialErrorEnvelopeSchema.parse(anonymous.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
    );

    const forged = await context.app.inject({
      method: "POST",
      url: "/v1/service-credentials",
      headers: { authorization: "Bearer mcs_v1.00000000-0000-0000-0000-000000000000.nope" },
      payload: { audience: CLOUD_GUANLAN_AUDIENCE },
    });
    expect(forged.statusCode).toBe(401);
    expect(forged.body).not.toContain("nope");

    // A client may not name the account, the device or the consumer.
    for (const body of [
      { audience: CLOUD_GUANLAN_AUDIENCE, consumer_id: session.account.id },
      { audience: CLOUD_GUANLAN_AUDIENCE, accountId: session.account.id },
      { audience: CLOUD_GUANLAN_AUDIENCE, deviceId: "device-1" },
      { audience: CLOUD_GUANLAN_AUDIENCE, scopes: [GUANLAN_WRITE_SCOPE] },
    ]) {
      const response = await issue(context, session.sessionToken, body);
      expect(response.statusCode).toBe(400);
      expect(serviceCredentialErrorEnvelopeSchema.parse(response.json()).error.code).toBe(
        "SERVICE_CREDENTIAL_INVALID_REQUEST",
      );
    }

    context.db.close();
    await context.app.close();
  });
});

describe("Guanlan credential issuance", () => {
  it("issues a read-only credential bound to the verified account and device", async () => {
    const context = createContext();
    const session = await provisionedSession(context);
    setGuanlanRegistrationStatus(context.db, session.account.id, "delivered");

    const response = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });

    expect(response.statusCode).toBe(200);
    const issued = issuedServiceCredentialSchema.parse(response.json());
    expect(issued).toMatchObject({
      tokenType: "Bearer",
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(response.body).not.toContain(session.sessionToken);

    const verified = verifyServiceCredential(issued.token, guanlanVerifier(context));
    const sessionId = parseSessionToken(session.sessionToken)!.id;
    const binding = context.db
      .prepare("SELECT device_id FROM sessions WHERE id = ?")
      .get(sessionId) as { device_id: string } | undefined;
    expect(binding?.device_id).toBeTruthy();
    expect(verified.claims).toMatchObject({
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: session.account.id,
      device_id: binding?.device_id,
      aud: CLOUD_GUANLAN_AUDIENCE,
      consumer_id: session.account.id,
      scope: [GUANLAN_READ_SCOPE],
    });
    expect(verified.claims.exp - verified.claims.iat).toBe(300);
    expect(verified.expiresAt.toISOString()).toBe(issued.expiresAt);
    expect(verified.keyId).toBe(context.keyRing?.activeKeyId);

    context.db.close();
    await context.app.close();
  });

  it("adds guanlan.write only when the caller asks for it explicitly", async () => {
    const context = createContext();
    const session = await provisionedSession(context);
    setGuanlanRegistrationStatus(context.db, session.account.id, "delivered");

    const explicit = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
      scopes: [GUANLAN_WRITE_SCOPE, GUANLAN_READ_SCOPE],
    });
    expect(explicit.statusCode).toBe(200);
    const explicitVerified = verifyServiceCredential(
      issuedServiceCredentialSchema.parse(explicit.json()).token,
      guanlanVerifier(context),
    );
    expect(explicitVerified.claims.scope).toEqual([GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE]);

    const readonly = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
      scopes: [GUANLAN_READ_SCOPE],
    });
    const readonlyVerified = verifyServiceCredential(
      issuedServiceCredentialSchema.parse(readonly.json()).token,
      guanlanVerifier(context),
    );
    expect(readonlyVerified.claims.scope).toEqual([GUANLAN_READ_SCOPE]);

    context.db.close();
    await context.app.close();
  });

  it("rejects credentials minted for another service audience", async () => {
    const context = createContext();
    const session = await provisionedSession(context);
    setGuanlanRegistrationStatus(context.db, session.account.id, "delivered");

    const guanlan = issuedServiceCredentialSchema.parse(
      (
        await issue(context, session.sessionToken, { audience: CLOUD_GUANLAN_AUDIENCE })
      ).json(),
    );
    expect(() => verifyServiceCredential(guanlan.token, shiyanVerifier(context))).toThrow(
      /audience/,
    );
    expect(() => verifyServiceCredential(guanlan.token, relayVerifier(context))).toThrow(
      /audience/,
    );

    const shiyan = issuedServiceCredentialSchema.parse(
      (
        await issue(context, session.sessionToken, { audience: CLOUD_SHIYAN_AUDIENCE })
      ).json(),
    );
    expect(shiyan.token).not.toBe(guanlan.token);
    expect(() => verifyServiceCredential(shiyan.token, guanlanVerifier(context))).toThrow(
      /audience/,
    );

    context.db.close();
    await context.app.close();
  });
});
