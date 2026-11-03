import { createPrivateKey, sign } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  CLOUD_GUANLAN_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  GUANLAN_READ_SCOPE,
  GUANLAN_WRITE_SCOPE,
  SERVICE_CREDENTIAL_ISSUER,
  issuedServiceCredentialSchema,
  serviceCredentialErrorEnvelopeSchema,
} from "@uichat-mira/cloud-auth-contracts";
import { parseSessionToken } from "../../src/security/session-token.js";
import { verifyServiceCredential } from "../../src/service-credentials/index.js";
import {
  createIsolatedServiceCredentialContext as createContext,
  createTestServiceCredentialKeyMaterial,
  disposeIsolatedServiceCredentialContexts,
  guanlanVerifier,
  issueServiceCredential as issue,
  provisionedSession,
  relayVerifier,
  setGuanlanRegistrationStatus,
  shiyanVerifier,
} from "../helpers/service-credential.js";

afterEach(disposeIsolatedServiceCredentialContexts);

describe("Guanlan credential HTTP contract", () => {
  it("fails closed while the account registration is not delivered", async () => {
    const context = createContext();
    const session = await provisionedSession(context);

    // GLN-012 enqueues `pending` with the account; nothing else moves it.
    const registration = context.db
      .prepare("SELECT status FROM guanlan_registration_outbox WHERE account_id = ?")
      .get(session.account.id) as { status: string } | undefined;
    expect(registration?.status).toBe("pending");

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

  it("fails closed when the GLN-012 projection is missing entirely", async () => {
    const context = createContext();
    const session = await provisionedSession(context);
    context.db.exec("DROP TABLE guanlan_registration_outbox");

    const response = await issue(context, session.sessionToken, {
      audience: CLOUD_GUANLAN_AUDIENCE,
    });

    expect(response.statusCode).toBe(409);
    const envelope = serviceCredentialErrorEnvelopeSchema.parse(response.json());
    expect(envelope.error.code).toBe("SERVICE_CREDENTIAL_PRINCIPAL_NOT_READY");
    expect(response.body).not.toContain("token");

    context.db.close();
    await context.app.close();
  });

  it("rejects a credential whose consumer identity is not its subject", async () => {
    const keyMaterial = createTestServiceCredentialKeyMaterial();
    const context = createContext(keyMaterial);
    const session = await provisionedSession(context);
    const sessionId = parseSessionToken(session.sessionToken)!.id;
    const binding = context.db
      .prepare("SELECT device_id FROM sessions WHERE id = ?")
      .get(sessionId) as { device_id: string } | undefined;
    expect(binding?.device_id).toBeTruthy();

    const nowSeconds = Math.floor(Date.now() / 1000);
    const header = { alg: "EdDSA", typ: "JWT", kid: keyMaterial.activeKeyId };
    const claims = {
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: session.account.id,
      device_id: binding!.device_id,
      aud: CLOUD_GUANLAN_AUDIENCE,
      scope: [GUANLAN_READ_SCOPE],
      consumer_id: "account-someone-else",
      iat: nowSeconds,
      nbf: nowSeconds,
      exp: nowSeconds + 300,
    };
    const signingInput = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}`;
    const signature = sign(
      null,
      Buffer.from(signingInput, "ascii"),
      createPrivateKey(keyMaterial.activePrivateKey),
    );
    const forged = `${signingInput}.${signature.toString("base64url")}`;

    expect(() => verifyServiceCredential(forged, guanlanVerifier(context))).toThrow();

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
