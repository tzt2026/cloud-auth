import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
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
  type ServiceCredentialAudience,
} from "@uichat-mira/cloud-auth-contracts";
import {
  DEFAULT_SERVICE_CREDENTIAL_TTL_SECONDS,
  MAX_SERVICE_CREDENTIAL_TTL_SECONDS,
  ServiceCredentialIssuanceError,
  issueServiceCredential,
  type IssueServiceCredentialInput,
} from "../../src/service-credentials/index.js";

const FIXED_NOW = new Date("2026-10-24T10:00:00.000Z");
const FIXED_NOW_SECONDS = Math.floor(FIXED_NOW.getTime() / 1000);
const ACCOUNT_ID = "account-0001";
const DEVICE_ID = "device-0001";

function decodeSegment(segment: string): unknown {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

function expectIssuanceError(
  action: () => unknown,
  code: ServiceCredentialIssuanceError["code"],
): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(ServiceCredentialIssuanceError);
    expect((error as ServiceCredentialIssuanceError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ServiceCredentialIssuanceError ${code}`);
}

describe("service credential issuance", () => {
  const { privateKey } = generateKeyPairSync("ed25519");

  it("constructs canonical Shiyan claims with a strict EdDSA header", () => {
    const token = issueServiceCredential(
      { privateKey, keyId: "cloud-auth-2026-10", now: () => FIXED_NOW },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_SHIYAN_AUDIENCE,
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      },
    );

    const [headerSegment, payloadSegment, signatureSegment] = token.split(".");
    expect(signatureSegment).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeSegment(headerSegment!)).toEqual({
      alg: "EdDSA",
      typ: "JWT",
      kid: "cloud-auth-2026-10",
    });
    expect(decodeSegment(payloadSegment!)).toEqual({
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: ACCOUNT_ID,
      device_id: DEVICE_ID,
      aud: CLOUD_SHIYAN_AUDIENCE,
      scope: [SHIYAN_AUTHENTICATE_SCOPE],
      iat: FIXED_NOW_SECONDS,
      nbf: FIXED_NOW_SECONDS,
      exp: FIXED_NOW_SECONDS + DEFAULT_SERVICE_CREDENTIAL_TTL_SECONDS,
    });
  });

  it("binds hosted Relay tickets to one room and transport role", () => {
    const token = issueServiceCredential(
      { privateKey, keyId: "cloud-auth-2026-10", now: () => FIXED_NOW, ttlSeconds: 120 },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
        scope: [RELAY_TRANSPORT_SCOPE],
        relay: { room: "room-7f3a", role: "client" },
      },
    );

    const payload = decodeSegment(token.split(".")[1]!);
    expect(payload).toMatchObject({
      aud: CLOUD_RELAY_TRANSPORT_AUDIENCE,
      scope: [RELAY_TRANSPORT_SCOPE],
      relay: { room: "room-7f3a", role: "client" },
      iat: FIXED_NOW_SECONDS,
      nbf: FIXED_NOW_SECONDS,
      exp: FIXED_NOW_SECONDS + 120,
    });
  });

  it("accepts an explicitly injected PEM private key", () => {
    const pem = privateKey.export({ type: "pkcs8", format: "pem" });
    const token = issueServiceCredential(
      { privateKey: pem, keyId: "pem-key", now: () => FIXED_NOW },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_SHIYAN_AUDIENCE,
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      },
    );
    expect(token.split(".")).toHaveLength(3);
  });

  it("rejects unsafe TTL values and key identifiers", () => {
    const input = {
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      audience: CLOUD_SHIYAN_AUDIENCE,
      scope: [SHIYAN_AUTHENTICATE_SCOPE],
    } as const;

    for (const ttlSeconds of [0, -1, 1.5, MAX_SERVICE_CREDENTIAL_TTL_SECONDS + 1]) {
      expectIssuanceError(
        () => issueServiceCredential({ privateKey, keyId: "key-1", ttlSeconds }, input),
        "INVALID_TTL",
      );
    }

    for (const keyId of ["", "key with spaces", "k".repeat(65)]) {
      expectIssuanceError(
        () => issueServiceCredential({ privateKey, keyId }, input),
        "INVALID_KID",
      );
    }
  });

  it("rejects missing, unexpected and cross-audience scope/context", () => {
    expectIssuanceError(
      () =>
        issueServiceCredential(
          { privateKey, keyId: "key-1" },
          {
            accountId: ACCOUNT_ID,
            deviceId: DEVICE_ID,
            audience: CLOUD_SHIYAN_AUDIENCE,
            scope: [SHIYAN_AUTHENTICATE_SCOPE],
            relay: { room: "room-1", role: "client" },
          },
        ),
      "INVALID_INPUT",
    );

    expectIssuanceError(
      () =>
        issueServiceCredential(
          { privateKey, keyId: "key-1" },
          {
            accountId: ACCOUNT_ID,
            deviceId: DEVICE_ID,
            audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
            scope: [RELAY_TRANSPORT_SCOPE],
          },
        ),
      "INVALID_INPUT",
    );

    expectIssuanceError(
      () =>
        issueServiceCredential(
          { privateKey, keyId: "key-1" },
          {
            accountId: ACCOUNT_ID,
            deviceId: DEVICE_ID,
            audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
            scope: [SHIYAN_AUTHENTICATE_SCOPE],
            relay: { room: "room-1", role: "client" },
          },
        ),
      "INVALID_INPUT",
    );

    expectIssuanceError(
      () =>
        issueServiceCredential(
          { privateKey, keyId: "key-1" },
          {
            accountId: ACCOUNT_ID,
            deviceId: DEVICE_ID,
            audience: "mira:unknown" as ServiceCredentialAudience,
            scope: [SHIYAN_AUTHENTICATE_SCOPE],
          },
        ),
      "INVALID_INPUT",
    );
  });

  it("rejects invalid subject, device and relay context", () => {
    const invalidInputs: IssueServiceCredentialInput[] = [
      {
        accountId: "",
        deviceId: DEVICE_ID,
        audience: CLOUD_SHIYAN_AUDIENCE,
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      },
      {
        accountId: ACCOUNT_ID,
        deviceId: "",
        audience: CLOUD_SHIYAN_AUDIENCE,
        scope: [SHIYAN_AUTHENTICATE_SCOPE],
      },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_RELAY_TRANSPORT_AUDIENCE,
        scope: [RELAY_TRANSPORT_SCOPE],
        relay: { room: "room with spaces", role: "client" },
      },
    ];
    for (const input of invalidInputs) {
      expectIssuanceError(
        () => issueServiceCredential({ privateKey, keyId: "key-1" }, input),
        "INVALID_INPUT",
      );
    }
  });

  it("rejects non-Ed25519 signing keys", () => {
    const { privateKey: rsaPrivateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expectIssuanceError(
      () =>
        issueServiceCredential(
          { privateKey: rsaPrivateKey, keyId: "key-1" },
          {
            accountId: ACCOUNT_ID,
            deviceId: DEVICE_ID,
            audience: CLOUD_SHIYAN_AUDIENCE,
            scope: [SHIYAN_AUTHENTICATE_SCOPE],
          },
        ),
      "INVALID_SIGNING_KEY",
    );
  });
});

describe("Who You service credential issuance", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const config = { privateKey, keyId: "cloud-auth-2026-10", now: () => FIXED_NOW };
  const confirmation = {
    actor: "user" as const,
    draft_id: "dr_0123456789abcdef",
    draft_version: 7,
    content_hash: "a".repeat(64),
    nonce: "nonce-0123456789abcdef",
  };

  it("derives the Who You consumer from the account and signs read scope", () => {
    const token = issueServiceCredential(config, {
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      audience: CLOUD_WHO_YOU_AUDIENCE,
      scope: [WHOYOU_READ_SCOPE],
      consumerId: ACCOUNT_ID,
    });

    expect(decodeSegment(token.split(".")[1]!)).toEqual({
      iss: SERVICE_CREDENTIAL_ISSUER,
      sub: ACCOUNT_ID,
      device_id: DEVICE_ID,
      aud: CLOUD_WHO_YOU_AUDIENCE,
      scope: [WHOYOU_READ_SCOPE],
      consumer_id: ACCOUNT_ID,
      iat: FIXED_NOW_SECONDS,
      nbf: FIXED_NOW_SECONDS,
      exp: FIXED_NOW_SECONDS + DEFAULT_SERVICE_CREDENTIAL_TTL_SECONDS,
    });
  });

  it("signs the read+write scope set in canonical order", () => {
    const token = issueServiceCredential(config, {
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      audience: CLOUD_WHO_YOU_AUDIENCE,
      scope: [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE],
      consumerId: ACCOUNT_ID,
    });

    expect(decodeSegment(token.split(".")[1]!)).toMatchObject({
      scope: [WHOYOU_READ_SCOPE, WHOYOU_MAIL_WRITE_SCOPE],
      consumer_id: ACCOUNT_ID,
    });
  });

  it("signs a standalone send credential bound to one draft revision", () => {
    const token = issueServiceCredential(config, {
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      audience: CLOUD_WHO_YOU_AUDIENCE,
      scope: [WHOYOU_MAIL_SEND_SCOPE],
      consumerId: ACCOUNT_ID,
      confirmation,
    });

    const payload = decodeSegment(token.split(".")[1]!);
    expect(payload).toMatchObject({
      aud: CLOUD_WHO_YOU_AUDIENCE,
      scope: [WHOYOU_MAIL_SEND_SCOPE],
      consumer_id: ACCOUNT_ID,
      confirmation,
    });
  });

  it("rejects send without confirmation and confirmation without send", () => {
    const invalidInputs: IssueServiceCredentialInput[] = [
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_WHO_YOU_AUDIENCE,
        scope: [WHOYOU_MAIL_SEND_SCOPE],
        consumerId: ACCOUNT_ID,
      },
      {
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        audience: CLOUD_WHO_YOU_AUDIENCE,
        scope: [WHOYOU_READ_SCOPE],
        consumerId: ACCOUNT_ID,
        confirmation,
      },
    ];
    for (const input of invalidInputs) {
      expectIssuanceError(
        () => issueServiceCredential(config, input),
        "INVALID_INPUT",
      );
    }
  });

  it("rejects malformed confirmations and non-Who You audiences", () => {
    for (const bad of [
      { ...confirmation, draft_version: 0 },
      { ...confirmation, content_hash: "A".repeat(64) },
      { ...confirmation, nonce: "short" },
    ]) {
      expectIssuanceError(
        () =>
          issueServiceCredential(config, {
            accountId: ACCOUNT_ID,
            deviceId: DEVICE_ID,
            audience: CLOUD_WHO_YOU_AUDIENCE,
            scope: [WHOYOU_MAIL_SEND_SCOPE],
            consumerId: ACCOUNT_ID,
            confirmation: bad,
          }),
        "INVALID_INPUT",
      );
    }

    expectIssuanceError(
      () =>
        issueServiceCredential(config, {
          accountId: ACCOUNT_ID,
          deviceId: DEVICE_ID,
          audience: CLOUD_SHIYAN_AUDIENCE,
          scope: [SHIYAN_AUTHENTICATE_SCOPE],
          confirmation,
        }),
      "INVALID_INPUT",
    );
  });
});
