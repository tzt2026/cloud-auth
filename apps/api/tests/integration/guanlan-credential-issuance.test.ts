import { createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CLOUD_GUANLAN_AUDIENCE,
  GUANLAN_READ_SCOPE,
  GUANLAN_WRITE_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  issuedServiceCredentialSchema,
  serviceCredentialErrorEnvelopeSchema,
} from "@uichat-mira/cloud-auth-contracts";
import { parseSessionToken } from "../../src/security/session-token.js";
import { deliverGuanlanRegistrations } from "../../src/guanlan-registration.js";
import {
  verifyServiceCredential,
  type ServiceCredentialVerifierConfig,
} from "../../src/service-credentials/index.js";
import { createFirstPartySession } from "../helpers/oauth.js";
import {
  createTestServiceCredentialContext,
  setGuanlanRegistrationStatus,
  type GuanlanRegistrationStatus,
  type TestServiceCredentialContext,
} from "../helpers/service-credential.js";

const password = "correct horse battery staple";
const cleanup: string[] = [];

afterEach(() => {
  for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

function createContext(): TestServiceCredentialContext {
  const dir = mkdtempSync(join(tmpdir(), "mira-guanlan-issuance-"));
  cleanup.push(dir);
  return createTestServiceCredentialContext(join(dir, "auth.sqlite"));
}

async function provisionedSession(
  context: TestServiceCredentialContext,
  username = "alice",
) {
  await context.service.provisionAccount(username, password);
  return createFirstPartySession(context, { username, password });
}

async function issue(context: TestServiceCredentialContext, token: string, body: unknown) {
  return context.app.inject({
    method: "POST",
    url: "/v1/service-credentials",
    headers: { authorization: `Bearer ${token}` },
    payload: body as Record<string, unknown>,
  });
}

function guanlanVerifier(
  context: TestServiceCredentialContext,
): ServiceCredentialVerifierConfig {
  const ring = context.keyRing;
  if (!ring) throw new Error("Expected a configured key ring");
  const publicKeys = new Map<string, KeyObject>(
    ring.jwks.keys.map((jwk) => [
      jwk.kid,
      createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }),
    ]),
  );
  return {
    issuer: SERVICE_CREDENTIAL_ISSUER,
    audience: CLOUD_GUANLAN_AUDIENCE,
    publicKeys,
  };
}

async function close(context: TestServiceCredentialContext): Promise<void> {
  context.db.close();
  await context.app.close();
}

/**
 * Verifies with the Guanlan audience and narrows to the Guanlan claim variant,
 * so a missing `consumer_id` fails here instead of leaking into assertions.
 */
function guanlanClaimsOf(context: TestServiceCredentialContext, token: string) {
  const verified = verifyServiceCredential(token, guanlanVerifier(context));
  if (verified.claims.aud !== CLOUD_GUANLAN_AUDIENCE) {
    throw new Error("Expected a Guanlan-audience credential");
  }
  return verified.claims;
}

describe("Guanlan credential issuance on SQLite", () => {
  it("unblocks issuance only when the GLN-012 delivery state machine confirms", async () => {
    const context = createContext();
    const session = await provisionedSession(context);
    const accountId = session.account.id;

    // GLN-012 enqueues `pending` in the same transaction as account creation.
    const enqueued = context.db
      .prepare("SELECT status FROM guanlan_registration_outbox WHERE account_id = ?")
      .get(accountId) as { status: string } | undefined;
    expect(enqueued?.status).toBe("pending");
    expect(
      (await issue(context, session.sessionToken, { audience: CLOUD_GUANLAN_AUDIENCE }))
        .statusCode,
    ).toBe(409);

    // An unconfirmed delivery must not move the projection to `delivered`.
    const unconfirmed = await deliverGuanlanRegistrations(context.db, {
      send: async () => false,
    });
    expect(unconfirmed.delivered).toBe(0);
    expect(
      (await issue(context, session.sessionToken, { audience: CLOUD_GUANLAN_AUDIENCE }))
        .statusCode,
    ).toBe(409);

    // A confirmed delivery marks the account ready on the real state machine.
    const confirmed = await deliverGuanlanRegistrations(
      context.db,
      { send: async () => true },
      { now: () => new Date(Date.now() + 120_000) },
    );
    expect(confirmed.delivered).toBe(1);

    const issued = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(issued.statusCode).toBe(200);
    const claims = guanlanClaimsOf(
      context,
      issuedServiceCredentialSchema.parse(issued.json()).token,
    );
    expect(claims.consumer_id).toBe(accountId);

    await close(context);
  });

  it("issues only while the GLN-012 registration projection reports delivered", async () => {
    const context = createContext();
    const session = await provisionedSession(context);
    const accountId = session.account.id;

    setGuanlanRegistrationStatus(context.db, accountId, "delivered");
    const delivered = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(delivered.statusCode).toBe(200);
    const issued = issuedServiceCredentialSchema.parse(delivered.json());
    const verified = verifyServiceCredential(issued.token, guanlanVerifier(context));
    expect(verified.claims).toMatchObject({
      sub: accountId,
      aud: CLOUD_GUANLAN_AUDIENCE,
      consumer_id: accountId,
      scope: [GUANLAN_READ_SCOPE],
    });

    const notReady: GuanlanRegistrationStatus[] = [
      "pending",
      "delivering",
      "withheld",
      "failed",
    ];
    for (const status of notReady) {
      setGuanlanRegistrationStatus(context.db, accountId, status);
      const refused = await issue(context, session.sessionToken, {
        audience: CLOUD_GUANLAN_AUDIENCE,
      });
      expect(refused.statusCode).toBe(409);
      expect(serviceCredentialErrorEnvelopeSchema.parse(refused.json()).error.code).toBe(
        "SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY",
      );
      expect(refused.json()).not.toHaveProperty("token");
      // Fail closed without echoing the account back.
      expect(refused.body).not.toContain(accountId);
    }

    context.db
      .prepare("DELETE FROM guanlan_registration_outbox WHERE account_id = ?")
      .run(accountId);
    const missing = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(missing.statusCode).toBe(409);

    await close(context);
  });

  it("derives one stable consumer per account and never crosses accounts", async () => {
    const context = createContext();
    const alice = await provisionedSession(context, "alice");
    const bob = await provisionedSession(context, "bob");
    setGuanlanRegistrationStatus(context.db, alice.account.id, "delivered");
    setGuanlanRegistrationStatus(context.db, bob.account.id, "delivered");

    const aliceIssued = issuedServiceCredentialSchema.parse(
      (
        await issue(context, alice.sessionToken, { audience: CLOUD_GUANLAN_AUDIENCE })
      ).json(),
    );
    const bobIssued = issuedServiceCredentialSchema.parse(
      (await issue(context, bob.sessionToken, { audience: CLOUD_GUANLAN_AUDIENCE })).json(),
    );

    const aliceClaims = guanlanClaimsOf(context, aliceIssued.token);
    const bobClaims = guanlanClaimsOf(context, bobIssued.token);

    expect(aliceClaims.consumer_id).toBe(alice.account.id);
    expect(bobClaims.consumer_id).toBe(bob.account.id);
    expect(aliceClaims.sub).toBe(alice.account.id);
    expect(bobClaims.sub).toBe(bob.account.id);
    expect(aliceClaims.consumer_id).not.toBe(bobClaims.consumer_id);

    // Alice's session can never mint a credential for Bob's consumer.
    const attempted = await issue(context, alice.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
      consumer_id: bob.account.id,
    });
    expect(attempted.statusCode).toBe(400);
    expect(attempted.body).not.toContain("token");

    await close(context);
  });

  it("refuses to issue once the account, device or session loses authority", async () => {
    // Disabled account.
    const disabledContext = createContext();
    const disabledSession = await provisionedSession(disabledContext);
    setGuanlanRegistrationStatus(disabledContext.db, disabledSession.account.id, "delivered");
    disabledContext.repository.setDisabledAndRevoke(
      disabledSession.account.id,
      true,
      new Date().toISOString(),
    );
    const disabled = await issue(disabledContext, disabledSession.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(disabled.statusCode).toBe(401);
    expect(serviceCredentialErrorEnvelopeSchema.parse(disabled.json()).error.code).toBe(
      "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
    );
    await close(disabledContext);

    // Account admission revoked.
    const deniedContext = createContext();
    const deniedSession = await provisionedSession(deniedContext);
    setGuanlanRegistrationStatus(deniedContext.db, deniedSession.account.id, "delivered");
    deniedContext.repository.setAllowedAndRevokeIfDenied(
      deniedSession.account.id,
      false,
      new Date().toISOString(),
    );
    const denied = await issue(deniedContext, deniedSession.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(denied.statusCode).toBe(401);
    await close(deniedContext);

    // Revoked device binding.
    const deviceContext = createContext();
    const deviceSession = await provisionedSession(deviceContext);
    setGuanlanRegistrationStatus(deviceContext.db, deviceSession.account.id, "delivered");
    const deviceId = parseSessionToken(deviceSession.sessionToken)!.id;
    const binding = deviceContext.db
      .prepare("SELECT device_id FROM sessions WHERE id = ?")
      .get(deviceId) as { device_id: string } | undefined;
    expect(binding?.device_id).toBeTruthy();
    await deviceContext.deviceService.revoke(deviceSession.sessionToken, binding!.device_id);
    const revoked = await issue(deviceContext, deviceSession.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(revoked.statusCode).toBe(401);
    await close(deviceContext);

    // Logged-out session.
    const logoutContext = createContext();
    const logoutSession = await provisionedSession(logoutContext);
    setGuanlanRegistrationStatus(logoutContext.db, logoutSession.account.id, "delivered");
    await logoutContext.service.logout(logoutSession.sessionToken);
    const loggedOut = await issue(logoutContext, logoutSession.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(loggedOut.statusCode).toBe(401);
    await close(logoutContext);

    // Session that expired while its device and account stay healthy.
    const expiredContext = createContext();
    const expiredSession = await provisionedSession(expiredContext);
    setGuanlanRegistrationStatus(expiredContext.db, expiredSession.account.id, "delivered");
    const expiredId = parseSessionToken(expiredSession.sessionToken)!.id;
    expiredContext.db
      .prepare("UPDATE sessions SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 1000).toISOString(), expiredId);
    const expired = await issue(expiredContext, expiredSession.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });
    expect(expired.statusCode).toBe(401);
    await close(expiredContext);
  });

  it("keeps read-only credentials free of write authority even on the same session", async () => {
    const context = createContext();
    const session = await provisionedSession(context);
    setGuanlanRegistrationStatus(context.db, session.account.id, "delivered");

    const readOnly = issuedServiceCredentialSchema.parse(
      (
        await issue(context, session.sessionToken, {
          audience: CLOUD_GUANLAN_AUDIENCE,
          scopes: [GUANLAN_READ_SCOPE],
        })
      ).json(),
    );
    const readOnlyClaims = verifyServiceCredential(
      readOnly.token,
      guanlanVerifier(context),
    ).claims;
    expect(readOnlyClaims.scope).toEqual([GUANLAN_READ_SCOPE]);
    expect(readOnlyClaims.scope).not.toContain(GUANLAN_WRITE_SCOPE);

    const writable = issuedServiceCredentialSchema.parse(
      (
        await issue(context, session.sessionToken, {
          audience: CLOUD_GUANLAN_AUDIENCE,
          scopes: [GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE],
        })
      ).json(),
    );
    const writableClaims = verifyServiceCredential(
      writable.token,
      guanlanVerifier(context),
    ).claims;
    expect(writableClaims.scope).toEqual([GUANLAN_READ_SCOPE, GUANLAN_WRITE_SCOPE]);
    // The two credentials are distinct artefacts, not an upgraded copy.
    expect(writable.token).not.toBe(readOnly.token);

    await close(context);
  });
});
