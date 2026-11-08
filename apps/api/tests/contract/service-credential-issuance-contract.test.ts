import { describe, expect, it } from "vitest";
import {
  CLOUD_WHO_YOU_AUDIENCE,
  CLOUD_RELAY_TRANSPORT_AUDIENCE,
  CLOUD_SHIYAN_AUDIENCE,
  WHOYOU_MAIL_WRITE_SCOPE,
  WHOYOU_READ_SCOPE,
  issuedServiceCredentialSchema,
  serviceCredentialErrorEnvelopeSchema,
  serviceCredentialJwksSchema,
  serviceCredentialRequestSchema,
} from "@uichat-mira/cloud-auth-contracts";

describe("service credential HTTP contract", () => {
  it("accepts only an explicit audience and the Relay transport context", () => {
    expect(
      serviceCredentialRequestSchema.parse({ audience: CLOUD_SHIYAN_AUDIENCE }),
    ).toEqual({ audience: CLOUD_SHIYAN_AUDIENCE });

    expect(
      serviceCredentialRequestSchema.parse({
        audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
        relay: { room: "room-7f3a", role: "client" },
      }),
    ).toEqual({
      audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      relay: { room: "room-7f3a", role: "client" },
    });

    for (const body of [
      {},
      { audience: "mira:unknown" },
      { audience: CLOUD_RELAY_TRANSPORT_AUDIENCE },
      { audience: CLOUD_SHIYAN_AUDIENCE, relay: { room: "room-1", role: "client" } },
      { audience: CLOUD_SHIYAN_AUDIENCE, accountId: "account-1" },
      { audience: CLOUD_SHIYAN_AUDIENCE, deviceId: "device-1" },
      { audience: CLOUD_SHIYAN_AUDIENCE, scope: ["shiyan:authenticate"] },
      { audience: CLOUD_SHIYAN_AUDIENCE, kid: "key-1" },
      { audience: CLOUD_RELAY_TRANSPORT_AUDIENCE, relay: { room: "room-1", role: "owner" } },
    ]) {
      expect(serviceCredentialRequestSchema.safeParse(body).success).toBe(false);
    }
  });

  it("keeps the issuance response free of Cloud Session material", () => {
    const response = {
      token: "header.payload.signature",
      tokenType: "Bearer",
      audience: CLOUD_SHIYAN_AUDIENCE,
      expiresAt: "2026-10-24T10:05:00.000Z",
    };
    expect(issuedServiceCredentialSchema.parse(response)).toEqual(response);

    for (const invalid of [
      { ...response, sessionToken: "mcs_v1.id.secret" },
      { ...response, tokenType: "Session" },
      { ...response, audience: "mira:unknown" },
      { ...response, expiresAt: "tomorrow" },
      { ...response, accountId: "account-1" },
    ]) {
      expect(issuedServiceCredentialSchema.safeParse(invalid).success).toBe(false);
    }
  });

  it("publishes only Ed25519 signature verification public keys", () => {
    const jwks = {
      keys: [
        {
          kty: "OKP",
          crv: "Ed25519",
          use: "sig",
          alg: "EdDSA",
          kid: "cloud-auth-2026-10",
          x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        },
      ],
    };
    expect(serviceCredentialJwksSchema.parse(jwks)).toEqual(jwks);

    for (const invalid of [
      { keys: [{ ...jwks.keys[0], d: "private" }] },
      { keys: [{ ...jwks.keys[0], kty: "RSA" }] },
      { keys: [{ ...jwks.keys[0], crv: "P-256" }] },
      { keys: [{ ...jwks.keys[0], use: "enc" }] },
      { keys: [{ ...jwks.keys[0], alg: "RS256" }] },
      { keys: [{ ...jwks.keys[0], kid: "key with spaces" }] },
      { keys: [{ ...jwks.keys[0], x: "" }] },
      { keys: [], extra: true },
    ]) {
      expect(serviceCredentialJwksSchema.safeParse(invalid).success).toBe(false);
    }
  });

  it("uses a bounded public error envelope", () => {
    for (const code of [
      "SERVICE_CREDENTIAL_INVALID_REQUEST",
      "SERVICE_CREDENTIAL_REAUTH_REQUIRED",
      "SERVICE_CREDENTIAL_DEVICE_REQUIRED",
      "SERVICE_CREDENTIAL_RELAY_NOT_AUTHORIZED",
      "SERVICE_CREDENTIAL_UNAVAILABLE",
      "SERVICE_CREDENTIAL_INTERNAL_ERROR",
    ]) {
      expect(
        serviceCredentialErrorEnvelopeSchema.parse({
          error: { code, message: "message" },
        }).error.code,
      ).toBe(code);
    }
    for (const invalid of [
      { error: { code: "AUTH_INVALID_CREDENTIALS", message: "message" } },
      { error: { code: "SERVICE_CREDENTIAL_INVALID_REQUEST" } },
      { error: { code: "SERVICE_CREDENTIAL_INVALID_REQUEST", message: "" } },
      { error: { code: "SERVICE_CREDENTIAL_INVALID_REQUEST", message: "message", extra: 1 } },
    ]) {
      expect(serviceCredentialErrorEnvelopeSchema.safeParse(invalid).success).toBe(false);
    }
  });

  it("accepts only the canonical Who You request shapes", () => {
    for (const body of [
      { audience: CLOUD_WHO_YOU_AUDIENCE },
      { audience: CLOUD_WHO_YOU_AUDIENCE, scopes: [WHOYOU_READ_SCOPE] },
      {
        audience: CLOUD_WHO_YOU_AUDIENCE,
        scopes: [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE],
      },
      {
        audience: CLOUD_WHO_YOU_AUDIENCE,
        confirmation: {
          actor: "user",
          draft_id: "dr_0123456789abcdef",
          draft_version: 7,
          content_hash: "a".repeat(64),
          nonce: "nonce-0123456789abcdef",
        },
      },
    ]) {
      expect(serviceCredentialRequestSchema.parse(body)).toEqual(body);
    }

    for (const body of [
      { audience: CLOUD_WHO_YOU_AUDIENCE, scopes: [] },
      { audience: CLOUD_WHO_YOU_AUDIENCE, scopes: [WHOYOU_MAIL_WRITE_SCOPE] },
      { audience: CLOUD_WHO_YOU_AUDIENCE, scopes: [WHOYOU_READ_SCOPE, WHOYOU_READ_SCOPE] },
      { audience: CLOUD_WHO_YOU_AUDIENCE, scopes: ["whoyou.mail.send"] },
      {
        audience: CLOUD_WHO_YOU_AUDIENCE,
        scopes: [WHOYOU_READ_SCOPE],
        confirmation: {
          actor: "user",
          draft_id: "dr_0123456789abcdef",
          draft_version: 7,
          content_hash: "a".repeat(64),
          nonce: "nonce-0123456789abcdef",
        },
      },
      {
        audience: CLOUD_WHO_YOU_AUDIENCE,
        confirmation: {
          actor: "device",
          draft_id: "dr_0123456789abcdef",
          draft_version: 7,
          content_hash: "a".repeat(64),
          nonce: "nonce-0123456789abcdef",
        },
      },
      { audience: CLOUD_WHO_YOU_AUDIENCE, consumer_id: "account-0001" },
      { audience: CLOUD_WHO_YOU_AUDIENCE, accountId: "account-0001" },
    ]) {
      expect(serviceCredentialRequestSchema.safeParse(body).success).toBe(false);
    }
  });
});
